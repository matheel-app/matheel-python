## 0.2.0

* Network failures (timeouts, DNS, resets, TLS) raise `MatheelError` with status 0 and code `network_error` instead of a raw URLError, TimeoutError, socket or ssl error.
* A 200 that is not the API's JSON (an HTML page), or a device filing answered without `device_token`, raises `MatheelError` 502 `invalid_response`: never treated as success.
* `file_with_store` follows the new contract: on 409 `device_token_reused` it stores `error.latest_device_token` and resends; on 409 `filing_in_progress` it waits `Retry-After` (at most 10 s) and resends; both bounded by `retries` (default 3).
* `file_with_store(store, invoice, uuid=...)` puts a stable document uuid into an invoice that has none. No uuid is ever generated silently.
* New `MatheelError.retryable`: `"retry"`, `"permanent"` or `"attention"`. `MatheelError.retry_after` carries the Retry-After seconds.

## 0.1.2

* Connects with a classic X25519 TLS key share: some networks between cloud hosts and Matheel's edge drop the large post-quantum ClientHello that OpenSSL 3.5 sends by default (Node 24, PHP and Python failed from GitHub's network; X25519 succeeded).

## 0.1.1

- Links to the public source repository (github.com/matheel-app).

## 0.1.0

* First release: `file_invoice`, `file_with_store`, `onboard`, `activation_link`, `decode_qr`, `verify_activation_callback`, `verify_telr`.
