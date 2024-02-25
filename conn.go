package mitm

import (
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// closedchan is a reusable closed channel.
var closedchan = make(chan struct{})

func init() {
	close(closedchan)
}

type TamperedConn struct {
	read             func(b []byte) (int, error)
	write            func(b []byte) (int, error)
	close            func() error
	localAddr        func() net.Addr
	remoteAddr       func() net.Addr
	setDeadline      func(t time.Time) error
	setReadDeadline  func(t time.Time) error
	setWriteDeadline func(t time.Time) error

	closeOnce sync.Once
}

var _ net.Conn = (*TamperedConn)(nil)

type TamperedConnOption func(*TamperedConn) error

func TamperConnRead(f func(b []byte) (int, error)) TamperedConnOption {
	return func(c *TamperedConn) error {
		c.read = f
		return nil
	}
}

func TamperConnWrite(f func(b []byte) (int, error)) TamperedConnOption {
	return func(c *TamperedConn) error {
		c.write = f
		return nil
	}
}

func TamperConnClose(f func() error) TamperedConnOption {
	return func(c *TamperedConn) error {
		c.close = f
		return nil
	}
}

func TamperConnLocalAddr(f func() net.Addr) TamperedConnOption {
	return func(c *TamperedConn) error {
		c.localAddr = f
		return nil
	}
}

func TamperConnRemoteAddr(f func() net.Addr) TamperedConnOption {
	return func(c *TamperedConn) error {
		c.remoteAddr = f
		return nil
	}
}

func TamperConnSetDeadline(f func(t time.Time) error) TamperedConnOption {
	return func(c *TamperedConn) error {
		c.setDeadline = f
		return nil
	}
}

func TamperConnSetReadDeadline(f func(t time.Time) error) TamperedConnOption {
	return func(c *TamperedConn) error {
		c.setReadDeadline = f
		return nil
	}
}

func TamperConnSetWriteDeadline(f func(t time.Time) error) TamperedConnOption {
	return func(c *TamperedConn) error {
		c.setWriteDeadline = f
		return nil
	}
}

func NewTamperedConn(conn net.Conn, opts ...TamperedConnOption) *TamperedConn {
	c := &TamperedConn{
		read:             conn.Read,
		write:            conn.Write,
		close:            conn.Close,
		localAddr:        conn.LocalAddr,
		remoteAddr:       conn.RemoteAddr,
		setDeadline:      conn.SetDeadline,
		setReadDeadline:  conn.SetReadDeadline,
		setWriteDeadline: conn.SetWriteDeadline,
	}
	for _, opt := range opts {
		_ = opt(c)
	}
	return c
}

func (c *TamperedConn) Read(b []byte) (int, error)  { return c.read(b) }
func (c *TamperedConn) Write(b []byte) (int, error) { return c.write(b) }
func (c *TamperedConn) Close() (err error) {
	c.closeOnce.Do(func() {
		err = c.close()
	})
	return
}
func (c *TamperedConn) LocalAddr() net.Addr                { return c.localAddr() }
func (c *TamperedConn) RemoteAddr() net.Addr               { return c.remoteAddr() }
func (c *TamperedConn) SetDeadline(t time.Time) error      { return c.setDeadline(t) }
func (c *TamperedConn) SetReadDeadline(t time.Time) error  { return c.setReadDeadline(t) }
func (c *TamperedConn) SetWriteDeadline(t time.Time) error { return c.setWriteDeadline(t) }

type ProxyConn struct {
	*TamperedConn
	dstAddr string
}

var _ net.Conn = (*ProxyConn)(nil)

func NewProxyConn(conn net.Conn, dstAddr string, opts ...TamperedConnOption) *ProxyConn {
	return &ProxyConn{
		TamperedConn: NewTamperedConn(conn, opts...),
		dstAddr:      dstAddr,
	}
}

func (c *ProxyConn) Destination() string {
	return c.dstAddr
}

type OneTimeListener struct {
	conn     net.Conn
	accepted atomic.Bool

	mu     sync.Mutex    // protect following fields
	done   chan struct{} // closed when Close is called
	closed bool          // set to true if Close is called
}

var _ net.Listener = (*OneTimeListener)(nil)

func NewOneTimeListener(conn net.Conn) *OneTimeListener {
	return &OneTimeListener{
		conn: conn,
		done: make(chan struct{}),
	}
}

func (l *OneTimeListener) Accept() (net.Conn, error) {
	if l.accepted.Load() {
		<-l.done
		return nil, syscall.EINVAL
	}
	if l.accepted.CompareAndSwap(false, true) {
		return l.conn, nil
	}
	return l.Accept()
}

func (l *OneTimeListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.closed {
		close(l.done)
		l.closed = true
	}
	return nil
}

func (l *OneTimeListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}
