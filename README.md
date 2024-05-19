# mitm-go
mitm-go is a library to implement an MITM (Man-in-the-Middle) server.\
When you can intercept TLS communications, it provides abstractions for decrypting them, and performing man-in-the-middle attacks.

## Overview
The main APIs are `NewTLSServer` and `NewTLSListener`.

When you call `NewTLSServer` on a `net.Conn` corresponding to the intercepted communication from a client, it returns a `tls.Conn`.
Normally, the communication using such a `tls.Conn` would fail because it lacks a valid certificate.
However, by generating a self-signed certificate corresponding to the actual server and performing a handshake, the communication succeeds (provided that the client trusts the CA certificate used for signing).

```go
l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 443})
if err != nil {
  panic(err)
}
defer l.Close()

for {
	conn, err := l.Accept()
  if err != nil {
    break
  }

  go func() {
    defer conn.Close()

    tlsConn, err := mitm.NewTLSServer(conn, &mitm.TLSConfig{
      RootCertificate: mitmCACert, // self-signed certificate
      GetDestination: func(conn net.Conn, serverName string) net.Addr {
        return conn.LocalAddr() // e.g. [TPROXY](https://docs.kernel.org/networking/tproxy.html)
      },
    })
    if err != nil {
      return
    }
    defer tlsConn.Close()

    // ...
  }()
}
```

`NewTLSListener` is the API used for `net.Listener`.
The above code can be rewritten as follows:

```go
l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 443})
if err != nil {
  panic(err)
}

l, err = mitm.NewTLSListener(l, &mitm.TLSConfig{
  RootCertificate: mitmCACert, // self-signed certificate
  GetDestination: func(conn net.Conn, serverName string) net.Addr {
    return conn.LocalAddr() // e.g. [TPROXY](https://docs.kernel.org/networking/tproxy.html)
  },
})
if err != nil {
  panic(err)
}
defer l.Close()

for {
	conn, err := l.Accept()
  if err != nil {
    break
  }

  go func() {
    defer conn.Close()

    // ...
  }()
}
```

Technically, this library implements the same methods described in [the mitmproxy documentation](https://docs.mitmproxy.org/stable/concepts-howmitmproxyworks/), so please refer to it as well.

The abstractions provided by `tls.Conn` and `net.Listener` are powerful enough to allow you to write various types of proxies using these APIs. Currently, the following HTTP proxies are implemented:

- HTTP(S) proxy using HTTP/1.1 CONNECT
- HTTP(S) proxy using HTTP/2 CONNECT
- Transparent HTTP(S) proxy

## TODO
- QUIC support
- HTTP/3 proxy
- transparent HTTP proxy sample on Windows/macOS
- SOCKS5 proxy

## LICENSE
MIT
