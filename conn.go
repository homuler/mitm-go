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

// TamperedConn is a [net.Conn] that can be tampered.
// Every [net.Conn] method can be replaced with a custom implementation.
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

// TamperConnRead replaces the [net.Conn.Read] method with f.
func TamperConnRead(f func(b []byte) (int, error)) TamperedConnOption {
	return func(c *TamperedConn) error {
		c.read = f
		return nil
	}
}

// TamperConnWrite replaces the [net.Conn.Write] method with f.
func TamperConnWrite(f func(b []byte) (int, error)) TamperedConnOption {
	return func(c *TamperedConn) error {
		c.write = f
		return nil
	}
}

// TamperConnClose replaces the [net.Conn.Close] method with f.
func TamperConnClose(f func() error) TamperedConnOption {
	return func(c *TamperedConn) error {
		c.close = f
		return nil
	}
}

// TamperConnLocalAddr replaces the [net.Conn.LocalAddr] method with f.
func TamperConnLocalAddr(f func() net.Addr) TamperedConnOption {
	return func(c *TamperedConn) error {
		c.localAddr = f
		return nil
	}
}

// TamperConnRemoteAddr replaces the [net.Conn.RemoteAddr] method with f.
func TamperConnRemoteAddr(f func() net.Addr) TamperedConnOption {
	return func(c *TamperedConn) error {
		c.remoteAddr = f
		return nil
	}
}

// TamperConnSetDeadline replaces the [net.Conn.SetDeadline] method with f.
func TamperConnSetDeadline(f func(t time.Time) error) TamperedConnOption {
	return func(c *TamperedConn) error {
		c.setDeadline = f
		return nil
	}
}

// TamperConnSetReadDeadline replaces the [net.Conn.SetReadDeadline] method with f.
func TamperConnSetReadDeadline(f func(t time.Time) error) TamperedConnOption {
	return func(c *TamperedConn) error {
		c.setReadDeadline = f
		return nil
	}
}

// TamperConnSetWriteDeadline replaces the [net.Conn.SetWriteDeadline] method with f.
func TamperConnSetWriteDeadline(f func(t time.Time) error) TamperedConnOption {
	return func(c *TamperedConn) error {
		c.setWriteDeadline = f
		return nil
	}
}

var (
	fallbackConnRead             = func(b []byte) (int, error) { return 0, net.ErrClosed }
	fallbackConnWrite            = func(b []byte) (int, error) { return 0, net.ErrClosed }
	fallbackConnClose            = func() error { return nil }
	fallbackConnLocalAddr        = func() net.Addr { return &net.IPAddr{} }
	fallbackConnRemoteAddr       = func() net.Addr { return &net.IPAddr{} }
	fallbackConnSetDeadline      = func(t time.Time) error { return net.ErrClosed }
	fallbackConnSetReadDeadline  = func(t time.Time) error { return net.ErrClosed }
	fallbackConnSetWriteDeadline = func(t time.Time) error { return net.ErrClosed }
)

// NewTamperedConn returns a new [TamperedConn].
// opts is used to change the behaviour of the underlying [net.Conn].
func NewTamperedConn(conn net.Conn, opts ...TamperedConnOption) *TamperedConn {
	c := newTamperedConn(conn)
	for _, opt := range opts {
		_ = opt(c)
	}
	return c
}

func newTamperedConn(conn net.Conn) *TamperedConn {
	if conn == nil {
		return &TamperedConn{
			read:             fallbackConnRead,
			write:            fallbackConnWrite,
			close:            fallbackConnClose,
			localAddr:        fallbackConnLocalAddr,
			remoteAddr:       fallbackConnRemoteAddr,
			setDeadline:      fallbackConnSetDeadline,
			setReadDeadline:  fallbackConnSetReadDeadline,
			setWriteDeadline: fallbackConnSetWriteDeadline,
		}
	}
	return &TamperedConn{
		read:             conn.Read,
		write:            conn.Write,
		close:            conn.Close,
		localAddr:        conn.LocalAddr,
		remoteAddr:       conn.RemoteAddr,
		setDeadline:      conn.SetDeadline,
		setReadDeadline:  conn.SetReadDeadline,
		setWriteDeadline: conn.SetWriteDeadline,
	}
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

// ProxyConn is a [TamperedConn] that has a destination address.
type ProxyConn struct {
	*TamperedConn
	dstAddr string
}

var _ net.Conn = (*ProxyConn)(nil)

// NewProxyConn returns a new [ProxyConn].
// dstAddr is the destination address of the connection.
// opts is used to change the behaviour of the underlying [TamperedConn].
func NewProxyConn(conn net.Conn, dstAddr string, opts ...TamperedConnOption) *ProxyConn {
	return &ProxyConn{
		TamperedConn: NewTamperedConn(conn, opts...),
		dstAddr:      dstAddr,
	}
}

// Destination returns the destination address of the connection.
func (c *ProxyConn) Destination() string {
	return c.dstAddr
}

// OneTimeListener is a [net.Listener] that accepts only one connection.
// It is useful when an existing API demands a [net.Listener] instead of a [net.Conn], but you want to serve only one connection.
// After the first call to [Accept], all subsequent calls will be blocked until [Close] is called.
type OneTimeListener struct {
	conn     net.Conn
	accepted atomic.Bool

	mu     sync.Mutex    // protect following fields
	done   chan struct{} // closed when Close is called
	closed bool          // set to true if Close is called
}

var _ net.Listener = (*OneTimeListener)(nil)

// NewOneTimeListener returns a new [OneTimeListener].
func NewOneTimeListener(conn net.Conn) *OneTimeListener {
	return &OneTimeListener{
		conn: conn,
		done: make(chan struct{}),
	}
}

// Accept returns the underlying connection if it has not been accepted yet.
// Otherwise, it blocks until [Close] is called.
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

// Close closes the listener.
// Any blocked [Accept] calls will be unblocked and return an error.
func (l *OneTimeListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.closed {
		close(l.done)
		l.closed = true
	}
	return nil
}

// Addr returns the local network address of the underlying connection.
func (l *OneTimeListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}
