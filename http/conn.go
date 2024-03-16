package http

import (
	"net"
	"net/url"
)

type ProxyConn interface {
	LocalAddr() net.Addr
}

type urlAddr struct {
	*url.URL
}

var _ net.Addr = (*urlAddr)(nil)

func (a *urlAddr) Network() string {
	return a.Network()
}

func (a *urlAddr) String() string {
	return a.Host
}
