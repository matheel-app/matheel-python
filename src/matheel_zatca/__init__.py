"""Official Python client for the Matheel ZATCA Phase 2 e-invoicing API (https://matheel.app). Standard library only."""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Protocol, Tuple

__all__ = [
    "Matheel",
    "MatheelError",
    "QrData",
    "TokenStore",
    "decode_qr",
    "verify_activation_callback",
    "verify_telr",
]
__version__ = "0.2.0"

DEFAULT_BASE_URL = "https://matheel.app"


# What the caller should do with an error, per the API contract (https://matheel.app/llms.txt).
_RETRY_CODES = frozenset({
    "network_error", "invalid_response", "device_token_reused", "filing_in_progress", "filing_outcome_unknown",
    "zatca_unavailable", "filing_failed", "billing_unavailable", "sandbox_rate_limited",
})
_PERMANENT_CODES = frozenset({"zatca_rejected", "invalid", "missing_fields", "invalid_amount", "validation_failed"})


class MatheelError(Exception):
    """A failed call: an API answer other than 200 (status, parsed body, code), or status 0 for a network failure."""

    def __init__(self, status: int, body: Any, retry_after: Optional[float] = None):
        self.status = status
        self.body = body
        self.code = _error_code(status, body)
        self.retry_after = retry_after
        super().__init__(f"Matheel {status}: {self.code}")

    @property
    def retryable(self) -> str:
        """``"retry"`` (resend the same request later), ``"permanent"`` (fix the document) or ``"attention"`` (a person must act)."""
        if self.code in _RETRY_CODES:
            return "retry"
        if self.code in _PERMANENT_CODES:
            return "permanent"
        if self.status in (0, 429) or self.status >= 500:
            return "retry"
        return "attention"  # 401 key/certificate, 402 plan, 409 previous_filing_unknown, anything unknown


def _invalid_response(raw: Any) -> MatheelError:
    """The MatheelError for an answer that is not the API's JSON (an HTML page, a 200 with no device_token)."""
    return MatheelError(502, {"error": "invalid_response", "raw": raw})


def _error_code(status: int, body: Any) -> str:
    # body.error is a string or {"code": ...}; a ZATCA rejection carries a non-empty "errors" list instead.
    error = body.get("error") if isinstance(body, dict) else None
    if isinstance(error, str):
        return error
    if isinstance(error, dict) and isinstance(error.get("code"), str):
        return error["code"]
    if isinstance(body, dict) and body.get("errors"):
        return "zatca_rejected"
    return f"http_{status}"


class TokenStore(Protocol):
    """Where the caller keeps one device's token, read and written under the caller's own DB lock."""

    def read(self) -> str:
        """Returns the current device token (e.g. SELECT token ... FOR UPDATE)."""
        ...

    def write(self, token: str) -> None:
        """Saves the token returned by an accepted invoice."""
        ...


def _tls_context() -> ssl.SSLContext:
    """Verified TLS with a classic X25519 key share.

    Some networks between a cloud host and Matheel's edge drop the large post-quantum ClientHello that OpenSSL 3.5
    sends by default (measured 2026-11-17: Python on OpenSSL 3.5 failed with UNEXPECTED_EOF, X25519 succeeded).
    """
    ctx = ssl.create_default_context()
    try:
        ctx.set_ecdh_curve("X25519")
    except (ValueError, ssl.SSLError):  # an OpenSSL build without X25519 keeps its defaults
        pass
    return ctx


class Matheel:
    """A client for the Matheel API; ``key`` is optional on the sandbox."""

    def __init__(self, key: Optional[str] = None, base_url: str = DEFAULT_BASE_URL, timeout: float = 60):
        self.key = key or None
        self.base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self.timeout = timeout

    def _send(self, path: str, body: Mapping[str, Any]) -> Tuple[int, Any, Optional[str]]:
        """POSTs JSON and returns (status, parsed body, Retry-After header); tests override this to mock HTTP."""
        headers = {"Content-Type": "application/json", "Accept": "application/json", "User-Agent": f"matheel-python/{__version__}"}
        if self.key:
            headers["Authorization"] = f"Bearer {self.key}"
        req = urllib.request.Request(self.base_url + path, data=json.dumps(body).encode(), headers=headers, method="POST")
        try:
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=_tls_context()) as res:
                    status, raw, retry_after = res.status, res.read(), res.headers.get("Retry-After")
            except urllib.error.HTTPError as e:
                status, raw, retry_after = e.code, e.read(), e.headers.get("Retry-After") if e.headers else None
        except (OSError, ssl.SSLError, http.client.HTTPException) as e:
            # URLError, DNS, timeouts, resets and TLS failures: the request may have reached Matheel, so resend it.
            raise MatheelError(0, {"error": "network_error", "message": str(e)}) from e
        try:
            return status, json.loads(raw) if raw else {}, retry_after
        except ValueError:
            return status, {"error": "invalid_json", "raw": raw.decode("utf-8", "replace")}, retry_after

    def post(self, path: str, body: Mapping[str, Any]) -> Any:
        """POSTs JSON to an API path and returns the parsed body; raises MatheelError on any status but 200 (0 = network)."""
        status, parsed, retry_after = self._send(path, body)
        if status != 200:
            raise MatheelError(status, parsed, _seconds(retry_after))
        if not isinstance(parsed, dict) or parsed.get("error") == "invalid_json":
            raise _invalid_response(parsed.get("raw") if isinstance(parsed, dict) else parsed)
        return parsed

    def file_invoice(self, invoice: Mapping[str, Any], device_token: Optional[str] = None, pdf: Optional[bool] = None, **fields: Any) -> dict:
        """Files one invoice (POST /api/v1/invoices); extra fields (environment, seller, csid, mode) pass through."""
        body = {**fields, "invoice": invoice}
        if device_token:
            body["device_token"] = device_token
        if pdf is not None:
            body["pdf"] = pdf
        res = self.post("/api/v1/invoices", body)
        # A device filing always answers with the next token; without one the answer did not come from the API.
        if device_token and not isinstance(res.get("device_token"), str):
            raise _invalid_response(res)
        return res

    def file_with_store(
        self,
        store: TokenStore,
        invoice: Mapping[str, Any],
        pdf: Optional[bool] = None,
        retries: int = 3,
        uuid: Optional[str] = None,
        **fields: Any,
    ) -> dict:
        """Files with the token in ``store``, writes the next token on 200, and resends on 409 (stale token, filing in progress).

        Up to ``retries`` times: 409 device_token_reused stores ``latest_device_token`` and resends; filing_in_progress
        waits Retry-After (max 10 s) and resends. ``uuid`` is put into an invoice that has none: pass one per document.
        """
        if uuid and not invoice.get("uuid"):
            invoice = {**invoice, "uuid": uuid}
        token = store.read()
        attempt = 0
        while True:
            try:
                res = self.file_invoice(invoice, device_token=token, pdf=pdf, **fields)
            except MatheelError as e:
                if e.status != 409 or attempt >= retries:
                    raise  # the stored token is left as it was
                attempt += 1
                error = e.body.get("error") if isinstance(e.body, dict) else None
                latest = error.get("latest_device_token") if isinstance(error, dict) else None
                if e.code == "device_token_reused" and latest:
                    store.write(latest)
                    token = latest
                elif e.code == "device_token_reused":
                    token = store.read()  # no latest token in the answer: another writer may have stored it
                elif e.code == "filing_in_progress":
                    time.sleep(min(e.retry_after if e.retry_after is not None else 5, 10))
                else:
                    raise
                continue
            if res.get("device_token"):
                store.write(res["device_token"])
            return res

    def onboard(self, environment: str, seller: Mapping[str, Any], device: Optional[Mapping[str, Any]] = None, otp: Optional[str] = None, **fields: Any) -> dict:
        """Registers a device with ZATCA (POST /api/v1/onboarding) and returns its ``device_token``."""
        body = {**fields, "environment": environment, "seller": seller}
        if device:
            body["device"] = device
        if otp:
            body["otp"] = otp
        return self.post("/api/v1/onboarding", body)

    def activation_link(
        self,
        environment: str,
        reference: str,
        callback_url: Optional[str] = None,
        expires_in_days: Optional[int] = None,
        max_devices: Optional[int] = None,
        **fields: Any,
    ) -> dict:
        """Makes a merchant activation link (POST /api/v1/onboarding/links): ``{url, callback_secret, expires_at}``."""
        body = {**fields, "environment": environment, "reference": reference}
        for name, value in (("callback_url", callback_url), ("expires_in_days", expires_in_days), ("max_devices", max_devices)):
            if value:
                body[name] = value
        return self.post("/api/v1/onboarding/links", body)


def _seconds(header: Optional[str]) -> Optional[float]:
    """Retry-After as non-negative seconds, or None when absent or not a number."""
    try:
        value = float(header) if header else None
    except ValueError:
        return None
    return value if value is not None and value >= 0 else None


@dataclass(frozen=True)
class QrData:
    """The fields of a ZATCA Phase 2 TLV QR; tags 8 and 9 are base64."""

    seller_name: str
    vat_number: str
    timestamp: str
    total: str
    vat_amount: str
    invoice_hash: Optional[str] = None
    signature: Optional[str] = None
    public_key: Optional[str] = None
    certificate_signature: Optional[str] = None


def decode_qr(base64_tlv: str) -> QrData:
    """Decodes the base64 TLV ZATCA QR (``qr`` in Matheel's answer)."""
    data = base64.b64decode(base64_tlv.strip())
    tags = {}
    i = 0
    while i + 2 <= len(data):
        tag, length = data[i], data[i + 1]
        i += 2
        if length & 0x80:
            # BER long form: the low bits count the length bytes that follow (keys and signatures exceed 127 bytes).
            count = length & 0x7F
            length = int.from_bytes(data[i : i + count], "big")
            i += count
        if i + length > len(data):
            raise ValueError("Truncated ZATCA QR")
        tags[tag] = data[i : i + length]
        i += length

    def text(tag: int) -> str:
        return tags[tag].decode("utf-8") if tag in tags else ""

    if not text(1) or not text(2):
        raise ValueError("Not a ZATCA QR: tags 1 and 2 are required")
    b64 = lambda tag: base64.b64encode(tags[tag]).decode() if tag in tags else None  # noqa: E731
    return QrData(
        seller_name=text(1),
        vat_number=text(2),
        timestamp=text(3),
        total=text(4),
        vat_amount=text(5),
        invoice_hash=text(6) if 6 in tags else None,
        signature=text(7) if 7 in tags else None,
        public_key=b64(8),
        certificate_signature=b64(9),
    )


def verify_activation_callback(raw_body: "bytes | str", signature_header: Optional[str], callback_secret: str) -> bool:
    """True when ``x-matheel-signature`` ("sha256=<hex>") is the HMAC-SHA256 of the raw body with ``callback_secret``."""
    if not callback_secret or not signature_header:
        return False
    body = raw_body.encode() if isinstance(raw_body, str) else raw_body
    expected = "sha256=" + hmac.new(callback_secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected.encode(), signature_header.strip().lower().encode())


_TELR_FIELDS = (
    "tran_store", "tran_type", "tran_class", "tran_test", "tran_ref", "tran_prevref", "tran_firstref", "tran_order",
    "tran_currency", "tran_amount", "tran_cartid", "tran_desc", "tran_status", "tran_authcode", "tran_authmessage",
)


def verify_telr(post_fields: Mapping[str, Any], secret: str) -> bool:
    """True when Telr's ``tran_check`` matches the SHA1 of the secret and the transaction fields (tran_order only when sent)."""
    check = post_fields.get("tran_check")
    if not secret or not check:
        return False
    parts = [secret]
    for name in _TELR_FIELDS:
        if name == "tran_order" and name not in post_fields:
            continue
        value = post_fields.get(name)
        parts.append("" if value is None else str(value))
    expected = hashlib.sha1(":".join(parts).encode()).hexdigest()
    return hmac.compare_digest(expected.encode(), str(check).strip().lower().encode())
