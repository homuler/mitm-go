# http-proxy

This is a sample implementation of HTTP(S) proxy.

## Setup
You need to generate a CA key and trust it.

```sh
openssl genrsa -out rootCAKey.pem 2048
openssl req -x509 -sha256 -new -nodes -key rootCAKey.pem -days 3650 -out rootCACert.pem -subj "/CN=localhost"
openssl x509 -outform der -in rootCACert.pem -out rootCA.crt
```

Install the certificate according to your environment.

```sh
trust anchor --store rootCA.crt
```

## Run
```sh
go run . -rootCACert rootCACert.pem -rootCAKey rootCAKey.pem
```

```sh
curl -x http://localhost:8080 -v http://github.com/homuler/mitm-go
curl -x http://localhost:8080 -v https://github.com/homuler/mitm-go
curl -x https://localhost:8443 -v http://github.com/homuler/mitm-go
curl -x https://localhost:8443 -v https://github.com/homuler/mitm-go
curl --proxy-http2 https://localhost:8443 -v http://github.com/homuler/mitm-go
curl --proxy-http2 https://localhost:8443 -v https://github.com/homuler/mitm-go
```
