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


# order.invoice_uuid: str(uuid.uuid4()), made once when the order is created and stored with it.
def invoice_order(conn, order, items):
    with conn, conn.cursor() as cur:  # commits on success, rolls back on any exception
        invoice = {"type": "simplified", "line_items": items}
        return matheel.file_with_store(DeviceRow(cur), invoice, pdf=True, uuid=order.invoice_uuid)
```

What `file_with_store` does with each answer (up to `retries` resends, default 3):

* **200**: writes the next `device_token` and returns. `replayed: True` means this document was already accepted and
  its stored answer came back: it was not filed twice.
* **409 `device_token_reused`**: another invoice moved the chain on. It writes `error.latest_device_token` and sends this
  invoice again with it.
* **409 `filing_in_progress`**: waits `Retry-After` (at most 10 s) and sends the same request again.
* Anything else: leaves the token alone and raises `MatheelError` (`status`, `body`, `code`, `retry_after`).

**Pass a stable `uuid`.** Make one UUID v4 per business document, store it with the order, and send it on every
attempt (`uuid=` or `invoice["uuid"]`). The library never invents one: a resend after a timeout is only safe when it
carries the same uuid, which is how Matheel knows not to file it twice.

### What to do with an error: `MatheelError.retryable`

```python
try:
    invoice_order(conn, order, items)
except MatheelError as e:
    if e.retryable == "retry":
        queue_retry(order)  # same request later: same token, same uuid
    elif e.retryable == "permanent":
        mark_invalid(order, e.body)  # fix the document (ZATCA rejection, bad fields)
    else:  # "attention"
        alert_ops(e)  # key, plan, certificate, or resend e.body["error"]["uuid"] first
```

| `retryable` | Codes |
|---|---|
| `"retry"` | `network_error` (status 0: timeout, DNS, reset, TLS), `invalid_response` (a 200 that is not the API's JSON), `filing_outcome_unknown` (504), `zatca_unavailable` (503), `filing_failed`, 429, any 5xx |
| `"permanent"` | `zatca_rejected`, `invalid`, `missing_fields`, `invalid_amount`, `validation_failed` (422) |
| `"attention"` | `invalid_api_key`, `invalid_csid` (401), `production_plan_required` (402), `previous_filing_unknown` (409: resend the document `error.uuid` first), anything unknown |

## API

| | |
|---|---|
| `Matheel(key=None, base_url="https://matheel.app", timeout=60)` | The client. |
| `file_invoice(invoice, device_token=None, pdf=None, **fields)` | `POST /api/v1/invoices`. Extra fields (`environment`, `seller`, `csid`, `mode`) pass through. |
| `file_with_store(store, invoice, pdf=None, retries=3, uuid=None)` | The safe chain helper above. `store` has `read()` and `write(token)`. |
| `MatheelError.retryable` | `"retry"`, `"permanent"` or `"attention"`, per the API contract. |
| `onboard(environment, seller, device=None, otp=None)` | `POST /api/v1/onboarding`, returns `device_token`. |
| `activation_link(environment, reference, callback_url=None, expires_in_days=None, max_devices=None)` | `POST /api/v1/onboarding/links`. |
| `decode_qr(qr)` | `QrData(seller_name, vat_number, timestamp, total, vat_amount, invoice_hash, signature, public_key, certificate_signature)` (tags 8 and 9 as base64). |
| `verify_activation_callback(raw_body, request.headers["x-matheel-signature"], callback_secret)` | Checks an activation callback (HMAC-SHA256, constant time). Pass the raw body bytes. |
| `verify_telr(post_fields, telr_secret)` | Checks Telr's `tran_check` on a transaction advice. |

Every non-200 answer raises `MatheelError`; `code` is the API's error code (`device_token_reused`,
`sandbox_rate_limited`, `invalid_device_token`, …) or `zatca_rejected` when ZATCA's `errors` are in the body. A network
failure (URLError, timeout, reset, TLS) raises `MatheelError` with status 0 and code `network_error`.
Keep the key and the device token on your server, never in an app.

Docs: https://matheel.app/en/docs · Python guide: https://matheel.app/en/zatca-integration/python ·
API reference for agents: https://matheel.app/llms.txt

## عربي

مكتبة ماثل الرسمية لبايثون: أرسل فاتورة زاتكا (المرحلة الثانية) بطلب واحد، ويرجع لك رد الهيئة والـ XML والـ QR والـ PDF.
بعد الدفع استخدم `file_with_store` مع قفل صف الجهاز في قاعدة بياناتك (`SELECT … FOR UPDATE`)، وهي تحفظ `device_token`
الجديد بعد كل فاتورة مقبولة. بيئة التجربة ما تحتاج مفتاح. الدليل: [matheel.app/rabt](https://matheel.app/rabt)
