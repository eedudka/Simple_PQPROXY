# Simple PQ Proxy

A simple and lightweight MITM forward proxy with Post-Quantum TLS support (OpenSSL-OQS, ML-KEM-768) and dynamic leaf certificate generation.

- 🇷🇺 [Русский](README.ru.md) 
---

## 🚀 Features

* **PQ-TLS rewrapping**: client→proxy over standard HTTPS, proxy→origin over hybrid TLS 1.3 (X25519 + ML-KEM-768)
* **Dynamic leaf certificates**: the proxy automatically issues a certificate with `CN=target_host` / `SAN=…` on the fly, using your passwordless PFX as the root CA
* **Fallback support**: if the server does not support the hybrid PQ group, you can specify a fallback group in `pqp.json`

---

## ⚙️ Requirements

* [.NET 9.0 SDK or later](https://dotnet.microsoft.com/download)
* [OpenSSL 3.2 or later](https://github.com/openssl/openssl) (this project was built with OpenSSL 3.5.1)
* [OQS Provider 0.9.0](https://github.com/open-quantum-safe/oqs-provider/)
* [liboqs 0.14.0](https://github.com/open-quantum-safe/liboqs)
* A generated passwordless PFX file containing your root CA (configured in `configs/pqp.json`)

---

## Generating Your Certificate

1. **Generate the CA private key**

   ```bash
   openssl genrsa -out rootCA.key 4096
   ```

2. **Create a self-signed CA certificate (valid for 10 years)**

   ```bash
   openssl req -x509 -new -nodes \
     -key rootCA.key \
     -sha256 \
     -days 3650 \
     -out rootCA.crt \
     -subj "/C=RU/ST=Moscow/L=Moscow/O=MyCompany/CN=MyProxy Root CA"
   ```

3. **Generate a CSR and leaf key**

   ```bash
   openssl req -new -nodes \
     -newkey rsa:2048 \
     -keyout proxy.key \
     -out proxy.csr \
     -subj "/CN=my-proxy.local"
   ```

4. **Sign the leaf certificate with the CA, adding SAN**

   ```bash
   openssl x509 -req \
     -in proxy.csr \
     -CA rootCA.crt \
     -CAkey rootCA.key \
     -CAcreateserial \
     -out proxy.crt \
     -days 365 \
     -sha256 \
     -extfile <(printf "subjectAltName=DNS:my-proxy.local")
   ```

5. **Create the PFX bundle**

   ```bash
   openssl pkcs12 -export \
     -out proxy.pfx \
     -inkey proxy.key \
     -in proxy.crt \
     -certfile rootCA.crt \
     -passout pass:
   ```

6. **Finalize setup**

   * Install `rootCA.crt` into your trusted root certificates.
   * Copy the certificates into `.../pqproxy.server/configs/crts/`.
   * Update `pqp.json` to reference your PFX filename.

---

## 🛠 Configuration

1. **PQ methods** in `pqp.json`:

   ```json
   "pq.methods": {
     "kem": "x25519mlkem768:x25519",
     "cipher_suite": "TLS_AES_256_GCM_SHA384",
     "signature": "falcon512"
   }
   ```

   * `x25519mlkem768:x25519` — supports both PQ and classic encryption
   * `x25519` — classic only
   * `x25519mlkem768` — PQ only

2. **SSL paths** in `configs/pqp.json`:

   ```json
   "ssl": {
     "pq_key": "crts/falcon-key.pem",
     "pq_cert": "crts/falcon-crt.pem",
     "key": "configs/crts/my-proxy.key",
     "cert": "configs/crts/my-proxy.crt",
     "pbx": "configs/crts/my-proxy.pfx",
     "pq_pbx": ""
   },
   ```

3. **OpenSSL and OQS library locations** in `configs/pqp.json`:

   ```json
   "lib_paths": {
     "openssl": "/usr/local/openssl-3.5.1/",
     "oqs_lib": "/lib64",
     "ossl-modules": "/lib64/ossl-modules"
   }
   ```

---

## 🔍 Usage Examples

1. **PQ-TLS via Cloudflare**

   ```bash
   curl --proxy http://localhost:3443 -v https://pq.cloudflareresearch.com/
   ```

2. **System proxy on Windows**

   * Proxy server → Manual proxy setup:

     * Address: `http://<your-proxy-host>`
     * Port: `3443` (or as defined in `pqp.json`)
     * Save

---

## Verifying PQ Encryption

* **Windows**: use Wireshark.
* **Linux**: use tshark:

  ```bash
  sudo tshark -i any -f "tcp port 443 and host pq.cloudflareresearch.com" -Y "tls.handshake" -V
  ```

---

## 🔭 Stage 1 Roadmap

1. **Performance**

   * Cache leaf certificates
   * Pool PQ-TLS connections & session tickets
   * I/O optimizations (Pipelines, ArrayPool)

2. **Refactoring & Documentation**

   * Add test coverage
   * Simplify and improve configuration

3. **Reliability & Monitoring**

   * Graceful shutdown with retry/backoff
   * Health endpoint
   * Docker Compose / Kubernetes readiness

---

## 📜 License

This project is licensed under the [Apache 2.0 License](LICENSE).
