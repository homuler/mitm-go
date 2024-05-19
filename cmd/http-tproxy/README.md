# http-tproxy

This is a sample implementation of transparent HTTP(S) proxy.

Note that this program assumes that the host machine is the default route of the client.
If you are testing on a single machine, consider using `netns`.

## Setup
### Certificate
You need to generate a CA key and trust it.

```sh
openssl genrsa -out rootCAKey.pem 2048
openssl req -x509 -sha256 -new -nodes -key rootCAKey.pem -days 3650 -out rootCACert.pem -subj "/CN=mitm-go"
openssl x509 -outform der -in rootCACert.pem -out rootCA.crt
```

Install the certificate according to your environment.

```sh
trust anchor --store rootCA.crt
```

### TPROXY
You also need to configure TPROXY.

```sh
iptables -t mangle -N DIVERT
iptables -t mangle -A DIVERT -j MARK --set-mark 1
iptables -t mangle -A DIVERT -j ACCEPT
iptables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT
iptables -t mangle -A PREROUTING -p udp -m socket -j DIVERT
iptables -t mangle -A PREROUTING -p tcp --dport 80 -j TPROXY --tproxy-mark 0x1/0x1 --on-ip 127.0.0.1 --on-port 8080
iptables -t mangle -A PREROUTING -p tcp --dport 443 -j TPROXY --tproxy-mark 0x1/0x1 --on-ip 127.0.0.1 --on-port 8443
iptables -t mangle -A PREROUTING -p udp --dport 443 -j TPROXY --tproxy-mark 0x1/0x1 --on-ip 127.0.0.1 --on-port 443
iptables -t mangle -A PREROUTING -p udp --dport 8443 -j TPROXY --tproxy-mark 0x1/0x1 --on-ip 127.0.0.1 --on-port 8443

ip rule add fwmark 1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
```

## Run
```sh
go run . -rootCACert rootCACert.pem -rootCAKey rootCAKey.pem
```

```sh
curl -v http://github.com/homuler/mitm-go
curl -v https://github.com/homuler/mitm-go
```
