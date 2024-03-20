package http

import (
	"net"
	"net/url"

	"github.com/homuler/mitm-proxy-go"
)

type ProxyConn interface {
	LocalAddr() net.Addr
}

func NewURLAddr(network string, u *url.URL) net.Addr {
	return mitm.NewAddr(network, u.Host)
}
