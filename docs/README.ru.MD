# Simple PQ Proxy 

Простой и легкий MITM-forward-proxy с поддержкой Post-Quantum TLS (OpenSSL-OQS, mlkem768) и динамической генерацией листовых сертификатов.

---

## 🚀 Возможности

- **PQ-TLS-перепаковка**: клиент→прокси via стандартный HTTPS, прокси→origin via гибрид TLS 1.3 (X25519 + ML-KEM-768)  
- **Динамические leaf-серты**: прокси автоматически выпускает сертификат `CN=целевой_хост`/`SAN=…` на лету, используя ваш PFX(без пароля) как корневой CA  
- **fallback**: если сервер не поддерживает гибрид PQ-группу можно поставить вспомогательную группу в `pqp.json`  

---

## ⚙️ Требования

- [.NET 9.0 SDK+](https://dotnet.microsoft.com/download)  
- [OpenSSL 3.2 (или выше)](https://github.com/openssl/openssl) - данный проект собран на Openssl 3.5.1 
- [OQS Provider 0.9.0](https://github.com/open-quantum-safe/oqs-provider/)
- [Liboqs 0.14.0](https://github.com/open-quantum-safe/liboqs)
- Сгенерированный PFX-файл с корневым CA без пароля (`configs/pqp.json`) 

---

## Генерация вашего сертификата

- Генерация ключа CA
``` openssl genrsa -out rootCA.key 4096  ```
- ca.cnf
```yaml
[ req ]
default_bits       = 4096
prompt             = no
default_md         = sha256
distinguished_name = dn
x509_extensions    = v3_ca

[ dn ]
C  = RU
ST = Moscow
L  = Moscow
O  = MyCompany
CN = my-proxy.local

[ v3_ca ]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage         = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
subjectAltName   = @alt_names

[ v3_req ]
basicConstraints   = CA:FALSE
keyUsage           = critical,digitalSignature,keyEncipherment
subjectAltName     = @alt_names

[ alt_names ]
DNS.1 = *your domain*
IP.1  = *your server ip*
```
- Самоподписной сертификат CA (10 лет)
``` openssl req -x509 -new -nodes -key rootCA.key -out rootCA.crt -days 3650 -config ca.cnf ```

- CSR и ключ leaf
``` openssl pkcs12 -export   -inkey rootCA.key   -in rootCA.crt   -out proxy.pfx   -passout pass: ```

- Создание PFX
```
openssl pkcs12 -export -out proxy.pfx -inkey proxy.key -in proxy.crt -certfile rootCA.crt -passout pass:
```
- После этого:
```
Установите rootCA.crt в доверенные сертификаты.
Перенесите сертефикат в ...\pqproxy.server\configs\crts\
Укажите в pqp.json название pfx сертификат
```

---


## 🛠 Конфигурация

- В pqp.json укажите необходимые группы
    Например: 
    - `x25519mlkem768:x25519` для работы как с PQ так 
    -  `x25519` для работы только с классическим шифрованием
    - `x25519mlkem768` для работы только с PQ
 ``` json
    "pq.methods": {
      "kem": "x25519mlkem768:x25519",
      "cipher_suite": "TLS_AES_256_GCM_SHA384",
      "signature": "falscon512"
    },
```

- В configs/pqp.json укажите путь до своего pfx сертификата 

```json
"ssl": {
      "pq_key": "crts/falcon-key.pem",
      "pq_cert": "crts/falcon-crt.pem",
      "key": "configs/crts/my-proxy.key",
      "cert": "configs/crts/my-proxy.crt",
      "pbx":"configs/crts/my-proxy.pfx",
      "pq_pbx":""
    },
```

- В configs/pqp.json укажите путь до установленного Openssl c провайдером и библиотеками OQS

```json
 "lib_paths": {
      "openssl": "/usr/local/openssl-3.5.1/",
      "oqs_lib": "/lib64",
      "ossl-modules": "/lib64/ossl-modules"
    }
```

---

## 🔍 Примеры использования

1. **PQ-TLS через Cloudflare**  
   `curl --proxy http://localhost:3443 -v https://pq.cloudflareresearch.com/`  

2. **Системный прокси для Windows**
  Прокси сервер -> Настроить прокси сервер в ручную:  
   - Адресс: http://адрес вашего сервера   
   - Прокси сервер -> Порт -> 3443 (или тот что вы указали в pqp.json)  
   - Сохранить

---
## Чтобы убедится в использовании PQ шифрования:
 - на Windows используйте - Wireshark
 - на Linux tshark - sudo `tshark -i any -f "tcp port 443 and host pq.cloudflareresearch.com" -Y "tls.handshake" -V `

---

## Анализ Wireshark/tshark:

### Найдите в Tls Handshake
 - **Прииспользовании mlkem + x25519** 
    1. Supported Group: Unknown (0x11ec)
    2. Supported Group: x25519 (0x001d) 
    3. Key Share Entry: Group: Unknown (4588), Key Exchange length: 1120
- **Прииспользовании mlkem** все будет тоже самое, но должна отсутвовать вспомогательная группа x25519 (0x001d)
- **Прииспользовании x25519** ожидаем отсутвие Unknown (0x11ec) и (4588)
---

## 📖 Дальнейшие планы 1 этапа

1. **Производительность**  
   - Кэш leaf-сертификатов  
   - Пул PQ-TLS-соединений & session tickets  
   - I/O-оптимизация (Pipelines, ArrayPool)  
2. **Рефакторинг & документация**   
   - Покрытие тестами
   - Улучшение и упращение конфигурации
3. **Надёжность & мониторинг**  
   - Graceful shutdown и retry/backoff  
   - health-endpoint  
   - Docker-Compose/Kubernetes readiness

---

## 📜 Лицензия

Этот проект распространяется под [Apache 2.0 License](LICENSE).
