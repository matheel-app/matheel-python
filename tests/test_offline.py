"""Offline tests: QR decoding, callback and Telr signatures, and file_with_store on a mocked transport."""

import base64
import hashlib
import hmac
import json
import socket
import ssl
import unittest
import urllib.error
from unittest import mock

from matheel_zatca import Matheel, MatheelError, decode_qr, verify_activation_callback, verify_telr


def tlv(tag, value):
    """One TLV field, with a BER long-form length when the value exceeds 127 bytes."""
    v = value.encode() if isinstance(value, str) else value
    length = bytes([len(v)]) if len(v) < 128 else bytes([0x81, len(v)])
    return bytes([tag]) + length + v


class MockMatheel(Matheel):
    """A client whose transport answers from a queue of (status, body[, retry_after]) and records each request."""

    def __init__(self, answers, **kwargs):
        super().__init__(**kwargs)
        self.answers = list(answers)
        self.calls = []

    def _send(self, path, body):
        self.calls.append((path, json.loads(json.dumps(body))))
        answer = self.answers.pop(0)
        return answer if len(answer) == 3 else (*answer, None)


class MemoryStore:
    """An in-memory TokenStore that counts reads and writes."""

    def __init__(self, token):
        self.token, self.reads, self.writes = token, 0, []

    def read(self):
        self.reads += 1
        return self.token

    def write(self, token):
        self.writes.append(token)
        self.token = token


class DecodeQrTest(unittest.TestCase):
    def test_reads_all_tags_arabic_and_long_lengths(self):
        key = bytes([7]) * 136
        qr = base64.b64encode(
            tlv(1, "شركة ماثل") + tlv(2, "399999999900003") + tlv(3, "2026-11-16T10:00:00") + tlv(4, "115.00")
            + tlv(5, "15.00") + tlv(6, "aGFzaA==") + tlv(7, "c2ln") + tlv(8, key) + tlv(9, b"\x01\x02\x03")
        ).decode()
        d = decode_qr(qr)
        self.assertEqual(d.seller_name, "شركة ماثل")
        self.assertEqual(d.vat_number, "399999999900003")
        self.assertEqual((d.timestamp, d.total, d.vat_amount), ("2026-11-16T10:00:00", "115.00", "15.00"))
        self.assertEqual((d.invoice_hash, d.signature), ("aGFzaA==", "c2ln"))
        self.assertEqual(base64.b64decode(d.public_key), key)
        self.assertEqual(d.certificate_signature, "AQID")

    def test_rejects_truncated_and_foreign_input(self):
        full = tlv(1, "Seller") + tlv(2, "399999999900003")
        with self.assertRaisesRegex(ValueError, "Truncated"):
            decode_qr(base64.b64encode(full[:-3]).decode())
        with self.assertRaisesRegex(ValueError, "tags 1 and 2"):
            decode_qr(base64.b64encode(tlv(3, "x")).decode())


class SignatureTest(unittest.TestCase):
    def test_activation_callback(self):
        body = json.dumps({"reference": "m-1", "devices": [{"device_token": "mdt1.x"}]})
        sig = "sha256=" + hmac.new(b"s3cret", body.encode(), hashlib.sha256).hexdigest()
        self.assertTrue(verify_activation_callback(body, sig, "s3cret"))
        self.assertTrue(verify_activation_callback(body.encode(), "sha256=" + sig[7:].upper(), "s3cret"))
        self.assertFalse(verify_activation_callback(body + " ", sig, "s3cret"))
        self.assertFalse(verify_activation_callback(body, sig, "other"))
        self.assertFalse(verify_activation_callback(body, None, "s3cret"))
        self.assertFalse(verify_activation_callback(body, "sha256=é", "s3cret"))

    def test_telr(self):
        f = {
            "tran_store": "12345", "tran_type": "sale", "tran_class": "ecom", "tran_test": "1", "tran_ref": "040029158825",
            "tran_prevref": "", "tran_firstref": "040029158825", "tran_currency": "SAR", "tran_amount": "115.00",
            "tran_cartid": "order-9", "tran_desc": "Iqama renewal", "tran_status": "A", "tran_authcode": "123456",
            "tran_authmessage": "Authorised",
        }
        head = ["tran_store", "tran_type", "tran_class", "tran_test", "tran_ref", "tran_prevref", "tran_firstref"]
        tail = ["tran_currency", "tran_amount", "tran_cartid", "tran_desc", "tran_status", "tran_authcode", "tran_authmessage"]
        sha1 = lambda s: hashlib.sha1(s.encode()).hexdigest()  # noqa: E731
        without = {**f, "tran_check": sha1(":".join(["secret"] + [f[k] for k in head + tail])).upper()}
        self.assertTrue(verify_telr(without, "secret"))
        self.assertFalse(verify_telr({**without, "tran_amount": "1.00"}, "secret"))
        self.assertFalse(verify_telr(without, "wrong"))
        with_order = {**f, "tran_order": "ORD1"}
        with_order["tran_check"] = sha1(":".join(["secret"] + [f[k] for k in head] + ["ORD1"] + [f[k] for k in tail]))
        self.assertTrue(verify_telr(with_order, "secret"))
        self.assertFalse(verify_telr(f, "secret"))


class FileWithStoreTest(unittest.TestCase):
    def test_409_then_200_writes_the_new_token_once(self):
        m = MockMatheel([(409, {"error": {"code": "device_token_reused"}}), (200, {"status": "reported", "device_token": "mdt1.new"})])
        store = MemoryStore("mdt1.old")
        res = m.file_with_store(store, {"type": "simplified"}, pdf=True)
        self.assertEqual(res["status"], "reported")
        self.assertEqual(store.writes, ["mdt1.new"])
        self.assertEqual(store.reads, 2)
        self.assertEqual(m.calls[1], ("/api/v1/invoices", {"invoice": {"type": "simplified"}, "device_token": "mdt1.old", "pdf": True}))

    def test_rejection_leaves_the_token_and_raises(self):
        rejected = {"status": "rejected", "errors": [{"code": "BR-KSA-33"}]}
        m = MockMatheel([(422, rejected)])
        store = MemoryStore("mdt1.old")
        with self.assertRaises(MatheelError) as cm:
            m.file_with_store(store, {})
        self.assertEqual((cm.exception.status, cm.exception.code, cm.exception.body), (422, "zatca_rejected", rejected))
        self.assertEqual(store.writes, [])

    def test_gives_up_after_three_retries(self):
        m = MockMatheel([(409, {"error": {"code": "device_token_reused"}})] * 5)
        store = MemoryStore("mdt1.old")
        with self.assertRaises(MatheelError) as cm:
            m.file_with_store(store, {})
        self.assertEqual(cm.exception.code, "device_token_reused")
        self.assertEqual(len(m.calls), 4)
        self.assertEqual(store.writes, [])


class ContractTest(unittest.TestCase):
    """The 0.2.0 server contract: latest token, filing in progress, network errors, invalid answers, classification."""

    def test_409_latest_token_is_stored_and_used_and_uuid_fills_the_invoice(self):
        stale = {"error": {"code": "device_token_reused", "latest_device_token": "mdt1.latest", "latest_counter": 7}}
        m = MockMatheel([(409, stale), (200, {"status": "reported", "device_token": "mdt1.next", "counter": 8})])
        store = MemoryStore("mdt1.old")
        res = m.file_with_store(store, {"type": "simplified"}, uuid="u-1")
        self.assertEqual(res["counter"], 8)
        self.assertEqual(store.writes, ["mdt1.latest", "mdt1.next"])
        self.assertEqual([c[1]["device_token"] for c in m.calls], ["mdt1.old", "mdt1.latest"])
        self.assertEqual([c[1]["invoice"]["uuid"] for c in m.calls], ["u-1", "u-1"])
        own = MockMatheel([(200, {"device_token": "t"})])
        own.file_with_store(MemoryStore("x"), {"uuid": "own"}, uuid="u-1")
        self.assertEqual(own.calls[0][1]["invoice"]["uuid"], "own")

    def test_filing_in_progress_waits_retry_after_capped_and_resends_the_same_request(self):
        busy = {"error": {"code": "filing_in_progress"}}
        m = MockMatheel([(409, busy, "5"), (409, busy, "60"), (200, {"device_token": "mdt1.next"})])
        store = MemoryStore("mdt1.old")
        with mock.patch("matheel_zatca.time.sleep") as sleep:
            m.file_with_store(store, {"uuid": "u-1"})
        self.assertEqual([c.args[0] for c in sleep.call_args_list], [5.0, 10])
        self.assertEqual([c[1] for c in m.calls], [{"invoice": {"uuid": "u-1"}, "device_token": "mdt1.old"}] * 3)
        self.assertEqual(store.writes, ["mdt1.next"])

    def test_in_progress_is_bounded_and_previous_unknown_is_not_retried(self):
        m = MockMatheel([(409, {"error": {"code": "filing_in_progress"}}, "1")] * 5)
        with mock.patch("matheel_zatca.time.sleep"), self.assertRaises(MatheelError) as cm:
            m.file_with_store(MemoryStore("t"), {}, retries=2)
        self.assertEqual((cm.exception.code, cm.exception.retry_after, len(m.calls)), ("filing_in_progress", 1.0, 3))
        prev = MockMatheel([(409, {"error": {"code": "previous_filing_unknown", "uuid": "earlier"}})])
        with self.assertRaises(MatheelError) as cm:
            prev.file_with_store(MemoryStore("t"), {})
        self.assertEqual((cm.exception.retryable, cm.exception.body["error"]["uuid"], len(prev.calls)), ("attention", "earlier", 1))

    def test_network_failures_become_status_0_network_error(self):
        failures = [
            urllib.error.URLError(socket.gaierror(-2, "Name or service not known")),
            TimeoutError("timed out"),
            socket.timeout("timed out"),
            ConnectionResetError(104, "Connection reset by peer"),
            ssl.SSLError("UNEXPECTED_EOF_WHILE_READING"),
        ]
        for failure in failures:
            store = MemoryStore("mdt1.old")
            with mock.patch("urllib.request.urlopen", side_effect=failure), self.assertRaises(MatheelError) as cm:
                Matheel().file_with_store(store, {})
            self.assertEqual((cm.exception.status, cm.exception.code, cm.exception.retryable), (0, "network_error", "retry"))
            self.assertIs(cm.exception.__cause__, failure)
            self.assertEqual(store.writes, [])
        # Nothing listens on port 1: the real transport fails the same way.
        with self.assertRaises(MatheelError) as cm:
            Matheel(base_url="https://127.0.0.1:1", timeout=5).file_invoice({})
        self.assertEqual((cm.exception.status, cm.exception.code), (0, "network_error"))

    def test_a_200_that_is_not_the_api_answer_is_invalid_response(self):
        html = {"error": "invalid_json", "raw": "<!DOCTYPE html><html>Login to Wi-Fi</html>"}
        for body in (html, {"status": "reported"}, None, [1]):
            store = MemoryStore("mdt1.old")
            with self.assertRaises(MatheelError) as cm:
                MockMatheel([(200, body)]).file_with_store(store, {})
            self.assertEqual((cm.exception.status, cm.exception.code, cm.exception.retryable), (502, "invalid_response", "retry"))
            self.assertEqual(store.writes, [])
        # Without a device_token (keyless sandbox, own credentials) a JSON 200 with no token is fine.
        self.assertEqual(MockMatheel([(200, {"status": "reported"})]).file_invoice({})["status"], "reported")

    def test_retryable_follows_the_contract(self):
        cases = [
            (0, "network_error", "retry"), (502, "invalid_response", "retry"), (504, {"code": "filing_outcome_unknown"}, "retry"),
            (503, {"code": "zatca_unavailable"}, "retry"), (429, "sandbox_rate_limited", "retry"), (500, "boom", "retry"),
            (409, {"code": "device_token_reused"}, "retry"), (409, {"code": "filing_in_progress"}, "retry"),
            (422, {"code": "filing_failed"}, "retry"), (422, {"code": "zatca_rejected"}, "permanent"),
            (422, {"code": "invalid"}, "permanent"), (422, {"code": "missing_fields"}, "permanent"),
            (422, {"code": "invalid_amount"}, "permanent"), (422, {"code": "validation_failed"}, "permanent"),
            (401, "invalid_api_key", "attention"), (401, {"code": "invalid_csid"}, "attention"),
            (402, "production_plan_required", "attention"), (409, {"code": "previous_filing_unknown"}, "attention"),
        ]
        for status, error, expected in cases:
            self.assertEqual(MatheelError(status, {"error": error}).retryable, expected, (status, error))
        self.assertEqual(MatheelError(422, {"status": "rejected", "errors": [{"code": "BR-KSA-33"}]}).retryable, "permanent")


class RequestBodyTest(unittest.TestCase):
    def test_onboard_and_activation_link(self):
        m = MockMatheel([(200, {"device_token": "mdt1.a"}), (200, {"url": "https://matheel.app/activate#x"})])
        m.onboard("sandbox", {"vat_number": "1"}, device={"name": "Till 1"})
        m.activation_link("production", "m-42", callback_url="https://a.test/cb", max_devices=3)
        self.assertEqual(m.calls[0], ("/api/v1/onboarding", {"environment": "sandbox", "seller": {"vat_number": "1"}, "device": {"name": "Till 1"}}))
        self.assertEqual(
            m.calls[1],
            ("/api/v1/onboarding/links", {"environment": "production", "reference": "m-42", "callback_url": "https://a.test/cb", "max_devices": 3}),
        )

    def test_string_error_code(self):
        with self.assertRaises(MatheelError) as cm:
            MockMatheel([(429, {"error": "sandbox_rate_limited"})]).file_invoice({})
        self.assertEqual((cm.exception.status, cm.exception.code), (429, "sandbox_rate_limited"))


if __name__ == "__main__":
    unittest.main()
