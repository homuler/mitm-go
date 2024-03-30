package http

import (
	"net"
	"net/url"

	"github.com/homuler/mitm-go"
)

func NewURLAddr(network string, u *url.URL) net.Addr {
	return mitm.NewAddr(network, u.Host)
}
