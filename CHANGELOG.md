## 0.1.2

* Connects with a classic X25519 TLS key share: some networks between cloud hosts and Matheel's edge drop the large post-quantum ClientHello that OpenSSL 3.5 sends by default (Node 24, PHP and Python failed from GitHub's network; X25519 succeeded).

## 0.1.1

- Links to the public source repository (github.com/matheel-app).

## 0.1.0

* First release: `file_invoice`, `file_with_store`, `onboard`, `activation_link`, `decode_qr`, `verify_activation_callback`, `verify_telr`.
