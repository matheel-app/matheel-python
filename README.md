# matheel-zatca

Official Python client for [Matheel](https://matheel.app), the **ZATCA (Fatoora) Phase 2** e-invoicing API for Saudi
Arabia. One call signs the invoice, files it with ZATCA (reporting or clearance) and returns ZATCA's answer, the legal
XML, the QR and a bilingual PDF. Python 3.9+, standard library only.

```sh
pip install matheel-zatca
```

```python
import base64, os
from matheel_zatca import Matheel

matheel = Matheel(os.environ.get("MATHEEL_KEY"))  # no key needed on the sandbox

# Try it now: the keyless sandbox files as Matheel's shared test taxpayer.
res = matheel.file_invoice(
    {"type": "simplified", "line_items": [{"name": "Iqama renewal service", "quantity": 1, "price": "100.00"}]},
    environment="sandbox",
    pdf=True,
)
res["status"]                   # "reported"
base64.b64decode(res["pdf"])    # the PDF/A-3 invoice
```

## After a payment: `file_with_store`

Register the device once (`onboard`, or an `activation_link` for a merchant), keep its `device_token` in one database
row, and file every paid order through `file_with_store`. The token carries the invoice chain (counter and hash), so
invoices of one device must be filed one after another: read and write the token under a row lock.

```python
# psycopg; CREATE TABLE matheel_device (id INT PRIMARY KEY, token TEXT NOT NULL);
class DeviceRow:
    def __init__(self, cur):
        self.cur = cur

    def read(self):
        self.cur.execute("SELECT token FROM matheel_device WHERE id = 1 FOR UPDATE")
        return self.cur.fetchone()[0]

    def write(self, token):
        self.cur.execute("UPDATE matheel_device SET token = %s WHERE id = 1", (token,))


def invoice_order(conn, items):
    with conn, conn.cursor() as cur:  # commits on success, rolls back on any exception
        return matheel.file_with_store(DeviceRow(cur), {"type": "simplified", "line_items": items}, pdf=True)
```

On 200 it writes the new token. On `409 device_token_reused` it re-reads the token and retries (3 times). On any other
error it leaves the token alone and raises `MatheelError` (`status`, `body`, `code`): fix the invoice and resend.

## API

| | |
|---|---|
| `Matheel(key=None, base_url="https://matheel.app", timeout=60)` | The client. |
| `file_invoice(invoice, device_token=None, pdf=None, **fields)` | `POST /api/v1/invoices`. Extra fields (`environment`, `seller`, `csid`, `mode`) pass through. |
| `file_with_store(store, invoice, pdf=None, retries=3)` | The safe chain helper above. `store` has `read()` and `write(token)`. |
| `onboard(environment, seller, device=None, otp=None)` | `POST /api/v1/onboarding`, returns `device_token`. |
| `activation_link(environment, reference, callback_url=None, expires_in_days=None, max_devices=None)` | `POST /api/v1/onboarding/links`. |
| `decode_qr(qr)` | `QrData(seller_name, vat_number, timestamp, total, vat_amount, invoice_hash, signature, public_key, certificate_signature)` (tags 8 and 9 as base64). |
| `verify_activation_callback(raw_body, request.headers["x-matheel-signature"], callback_secret)` | Checks an activation callback (HMAC-SHA256, constant time). Pass the raw body bytes. |
| `verify_telr(post_fields, telr_secret)` | Checks Telr's `tran_check` on a transaction advice. |

Every non-200 answer raises `MatheelError`; `code` is the API's error code (`device_token_reused`,
`sandbox_rate_limited`, `invalid_device_token`, …) or `zatca_rejected` when ZATCA's `errors` are in the body.
Keep the key and the device token on your server, never in an app.

Docs: https://matheel.app/en/docs · Python guide: https://matheel.app/en/zatca-integration/python ·
API reference for agents: https://matheel.app/llms.txt

## عربي

مكتبة ماثل الرسمية لبايثون: أرسل فاتورة زاتكا (المرحلة الثانية) بطلب واحد، ويرجع لك رد الهيئة والـ XML والـ QR والـ PDF.
بعد الدفع استخدم `file_with_store` مع قفل صف الجهاز في قاعدة بياناتك (`SELECT … FOR UPDATE`)، وهي تحفظ `device_token`
الجديد بعد كل فاتورة مقبولة. بيئة التجربة ما تحتاج مفتاح. الدليل: [matheel.app/rabt](https://matheel.app/rabt)
