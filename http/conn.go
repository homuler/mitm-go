package http

import "net"

type ProxyConn interface {
	LocalAddr() net.Addr
}
