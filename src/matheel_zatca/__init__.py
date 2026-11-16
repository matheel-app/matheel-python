"""Official Python client for the Matheel ZATCA Phase 2 e-invoicing API (https://matheel.app). Standard library only."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
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
__version__ = "0.1.1"

DEFAULT_BASE_URL = "https://matheel.app"


class MatheelError(Exception):
    """An API answer other than 200: carries the HTTP status, the parsed body and the error code."""

    def __init__(self, status: int, body: Any):
        self.status = status
        self.body = body
        self.code = _error_code(status, body)
        super().__init__(f"Matheel {status}: {self.code}")


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


class Matheel:
    """A client for the Matheel API; ``key`` is optional on the sandbox."""

    def __init__(self, key: Optional[str] = None, base_url: str = DEFAULT_BASE_URL, timeout: float = 60):
        self.key = key or None
        self.base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self.timeout = timeout

    def _send(self, path: str, body: Mapping[str, Any]) -> Tuple[int, Any]:
        """POSTs JSON and returns (status, parsed body); tests override this to mock HTTP."""
        headers = {"Content-Type": "application/json", "Accept": "application/json", "User-Agent": f"matheel-python/{__version__}"}
        if self.key:
            headers["Authorization"] = f"Bearer {self.key}"
        req = urllib.request.Request(self.base_url + path, data=json.dumps(body).encode(), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as res:
                status, raw = res.status, res.read()
        except urllib.error.HTTPError as e:
            status, raw = e.code, e.read()
        try:
            return status, json.loads(raw) if raw else {}
        except ValueError:
            return status, {"error": "invalid_json", "raw": raw.decode("utf-8", "replace")}

    def post(self, path: str, body: Mapping[str, Any]) -> Any:
        """POSTs JSON to an API path and returns the parsed body; raises MatheelError on any status but 200."""
        status, parsed = self._send(path, body)
        if status != 200:
            raise MatheelError(status, parsed)
        return parsed

    def file_invoice(self, invoice: Mapping[str, Any], device_token: Optional[str] = None, pdf: Optional[bool] = None, **fields: Any) -> dict:
        """Files one invoice (POST /api/v1/invoices); extra fields (environment, seller, csid, mode) pass through."""
        body = {**fields, "invoice": invoice}
        if device_token:
            body["device_token"] = device_token
        if pdf is not None:
            body["pdf"] = pdf
        return self.post("/api/v1/invoices", body)

    def file_with_store(self, store: TokenStore, invoice: Mapping[str, Any], pdf: Optional[bool] = None, retries: int = 3, **fields: Any) -> dict:
        """Files with the token in ``store``: writes the new token on 200, re-reads and retries on 409 device_token_reused."""
        attempt = 0
        while True:
            try:
                res = self.file_invoice(invoice, device_token=store.read(), pdf=pdf, **fields)
            except MatheelError as e:
                if e.status == 409 and e.code == "device_token_reused" and attempt < retries:
                    attempt += 1
                    continue
                raise  # any other error: the stored token is left as it was
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
