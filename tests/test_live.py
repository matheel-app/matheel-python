"""Live test against the keyless sandbox (one filing; set MATHEEL_OFFLINE=1 to skip)."""

import base64
import os
import re
import unittest
import uuid

from matheel_zatca import Matheel, decode_qr


@unittest.skipIf(os.environ.get("MATHEEL_OFFLINE") == "1", "MATHEEL_OFFLINE=1")
class LiveSandboxTest(unittest.TestCase):
    def test_files_a_simplified_invoice_with_pdf_and_qr(self):
        res = Matheel().file_invoice(
            {
                "type": "simplified", "counter": 1, "uuid": str(uuid.uuid4()), "number": "T-1",
                "line_items": [{"name": "Iqama renewal service", "quantity": 1, "price": "100.00"}],
            },
            environment="sandbox",
            pdf=True,
        )
        self.assertEqual(res["status"], "reported")
        self.assertEqual(base64.b64decode(res["pdf"])[:4], b"%PDF")
        self.assertRegex(decode_qr(res["qr"]).vat_number, re.compile(r"^\d{15}$"))


if __name__ == "__main__":
    unittest.main()
