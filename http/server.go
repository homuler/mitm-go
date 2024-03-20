package http

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/homuler/mitm-proxy-go"
)

type connKey struct{}

func WithConn(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, connKey{}, c)
}

func GetConn(r *http.Request) (conn net.Conn, ok bool) {
	conn, ok = r.Context().Value(connKey{}).(net.Conn)
	return
}

type destinationKey struct{}

func WithDestination(ctx context.Context, dstAddr net.Addr) context.Context {
	return context.WithValue(ctx, destinationKey{}, dstAddr)
}

func GetDestination(r *http.Request) (dstAddr net.Addr, ok bool) {
	dstAddr, ok = r.Context().Value(destinationKey{}).(net.Addr)
	return
}

type proxyServer struct {
	server     *http.Server
	rootCert   tls.Certificate
	nextProtos []string
}

type ProxyServerOption func(*proxyServer) error

// Addr optionally specifies the TCP address for the server to listen on,
// in the form "host:port". If empty, ":http" (port 80) is used.
// The service names are defined in RFC 6335 and assigned by IANA.
// See net.Dial for details of the address format.
func Addr(addr string) ProxyServerOption {
	return func(psrv *proxyServer) error {
		psrv.server.Addr = addr
		return nil
	}
}

// Handler specifies the handler to invoke, RoundTripHandler if nil
func Handler(h http.Handler) ProxyServerOption {
	return func(psrv *proxyServer) error {
		psrv.server.Handler = h
		return nil
	}
}

// DisableGeneralOptionsHandler, if true, passes "OPTIONS *" requests to the Handler,
// otherwise responds with 200 OK and Content-Length: 0.
func DisableGeneralOptionsHandler(v bool) ProxyServerOption {
	return func(psrv *proxyServer) error {
		psrv.server.DisableGeneralOptionsHandler = v
		return nil
	}
}

// ReadTimeout is the maximum duration for reading the entire
// request, including the body. A zero or negative value means
// there will be no timeout.
//
// Because ReadTimeout does not let Handlers make per-request
// decisions on each request body's acceptable deadline or
// upload rate, most users will prefer to use
// ReadHeaderTimeout. It is valid to use them both.
func ReadTimeout(d time.Duration) ProxyServerOption {
	return func(psrv *proxyServer) error {
		psrv.server.ReadTimeout = d
		return nil
	}
}

// ReadHeaderTimeout is the amount of time allowed to read
// request headers. The connection's read deadline is reset
// after reading the headers and the Handler can decide what
// is considered too slow for the body. If ReadHeaderTimeout
// is zero, the value of ReadTimeout is used. If both are
// zero, there is no timeout.
func ReadHeaderTimeout(d time.Duration) ProxyServerOption {
	return func(psrv *proxyServer) error {
		psrv.server.ReadHeaderTimeout = d
		return nil
	}
}

// WriteTimeout is the maximum duration before timing out
// writes of the response. It is reset whenever a new
// request's header is read. Like ReadTimeout, it does not
// let Handlers make decisions on a per-request basis.
// A zero or negative value means there will be no timeout.
func WriteTimeout(d time.Duration) ProxyServerOption {
	return func(psrv *proxyServer) error {
		psrv.server.WriteTimeout = d
		return nil
	}
}

// IdleTimeout is the maximum amount of time to wait for the
// next request when keep-alives are enabled. If IdleTimeout
// is zero, the value of ReadTimeout is used. If both are
// zero, there is no timeout.
func IdleTimeout(d time.Duration) ProxyServerOption {
	return func(psrv *proxyServer) error {
		psrv.server.IdleTimeout = d
		return nil
	}
}

// MaxHeaderBytes controls the maximum number of bytes the
// server will read parsing the request header's keys and
// values, including the request line. It does not limit the
// size of the request body.
// If zero, http.DefaultMaxHeaderBytes is used.
func MaxHeaderBytes(v int) ProxyServerOption {
	return func(psrv *proxyServer) error {
		psrv.server.MaxHeaderBytes = v
		return nil
	}
}

// TLSNextProto optionally specifies a function to take over
// ownership of the provided TLS connection when an ALPN
// protocol upgrade has occurred. The map key is the protocol
// name negotiated. The Handler argument should be used to
// handle HTTP requests and will initialize the Request's TLS
// and RemoteAddr if not already set. The connection is
// automatically closed when the function returns.
// If TLSNextProto is not nil, HTTP/2 support is not enabled
// automatically.
func TLSNextProto(m map[string]func(*http.Server, *tls.Conn, http.Handler)) ProxyServerOption {
	return func(psrv *proxyServer) error {
		psrv.server.TLSNextProto = m
		return nil
	}
}

func TLSNextProtos(protos []string) ProxyServerOption {
	return func(psrv *proxyServer) error {
		psrv.nextProtos = protos
		return nil
	}
}

// ConnState specifies an optional callback function that is
// called when a client connection changes state. See the
// ConnState type and associated constants for details.
func ConnState(f func(net.Conn, http.ConnState)) ProxyServerOption {
	return func(psrv *proxyServer) error {
		psrv.server.ConnState = f
		return nil
	}
}

// ErrorLog specifies an optional logger for errors accepting
// connections, unexpected behavior from handlers, and
// underlying FileSystem errors.
// If nil, logging is done via the log package's standard logger.
func ErrorLog(l *log.Logger) ProxyServerOption {
	return func(psrv *proxyServer) error {
		psrv.server.ErrorLog = l
		return nil
	}
}

// BaseContext optionally specifies a function that returns
// the base context for incoming requests on this server.
// The provided Listener is the specific Listener that's
// about to start accepting requests.
// If BaseContext is nil, the default is context.Background().
// If non-nil, it must return a non-nil context.
func BaseContext(f func(net.Listener) context.Context) ProxyServerOption {
	return func(psrv *proxyServer) error {
		psrv.server.BaseContext = f
		return nil
	}
}

// ConnContext optionally specifies a function that modifies
// the context used for a new connection c. The provided ctx
// is derived from the base context and has a ServerContextKey
// value.
func ConnContext(f func(ctx context.Context, c net.Conn) context.Context) ProxyServerOption {
	return func(psrv *proxyServer) error {
		psrv.server.ConnContext = f
		return nil
	}
}

func (psrv *proxyServer) Close() error {
	return psrv.server.Close()
}

func (psrv *proxyServer) Shutdown(ctx context.Context) error {
	return psrv.server.Shutdown(ctx)
}

func (psrv *proxyServer) RegisterOnShutdown(f func()) {
	psrv.server.RegisterOnShutdown(f)
}

func (psrv *proxyServer) Serve(l net.Listener) error {
	return psrv.server.Serve(l)
}

type ProxyServer struct {
	*proxyServer
}

func NewProxyServer(rootCert tls.Certificate, options ...ProxyServerOption) ProxyServer {
	psrv := &proxyServer{
		server: &http.Server{
			Handler: RoundTripHandlerFunc,
		},
		nextProtos: []string{"h2", "http/1.1"},
		rootCert:   rootCert,
	}
	for _, opt := range options {
		opt(psrv)
	}

	if psrv.server.ConnContext == nil {
		psrv.server.ConnContext = WithConn
	} else {
		connContext := psrv.server.ConnContext
		psrv.server.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
			return connContext(WithConn(ctx, c), c)
		}
	}

	psrv.server.Handler = Proxify(psrv.server.Handler, &mitm.TLSConfig{
		RootCertificate: &psrv.rootCert,
		NextProtos:      psrv.nextProtos,
	})
	return ProxyServer{psrv}
}

func (psrv ProxyServer) ServeTLS(l net.Listener, certFile, keyFile string) error {
	return psrv.server.ServeTLS(l, certFile, keyFile)
}

type TProxyServer struct {
	*proxyServer
}

func tproxyConnContext(ctx context.Context, c net.Conn) context.Context {
	return WithDestination(ctx, c.LocalAddr())
}

func NewTProxyServer(rootCert tls.Certificate, options ...ProxyServerOption) TProxyServer {
	psrv := &proxyServer{
		server: &http.Server{
			Handler: RoundTripHandlerFunc,
		},
		nextProtos: []string{"h2", "http/1.1"},
		rootCert:   rootCert,
	}
	for _, opt := range options {
		opt(psrv)
	}

	if psrv.server.ConnContext == nil {
		psrv.server.ConnContext = tproxyConnContext
	} else {
		connContext := psrv.server.ConnContext
		psrv.server.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
			return connContext(tproxyConnContext(ctx, c), c)
		}
	}
	psrv.server.Handler = &tproxyHandler{handler: psrv.server.Handler}

	return TProxyServer{psrv}
}

func (psrv TProxyServer) ServeTLS(l net.Listener) error {
	tl, err := mitm.NewTLSListener(l, &mitm.TLSConfig{
		RootCertificate: &psrv.rootCert,
		NextProtos:      psrv.nextProtos,
		GetDestination: func(conn net.Conn, serverName string) net.Addr {
			return conn.LocalAddr()
		},
	})
	if err != nil {
		return err
	}
	return psrv.server.Serve(tl)
}

var (
	httpScheme  = "http"
	httpsScheme = "https"
)

func CopyAsProxyRequest(req *http.Request, dest string) *http.Request {
	proxyReq := req.Clone(req.Context())
	scheme := httpsScheme
	if req.TLS == nil {
		scheme = httpScheme
	}
	proxyReq.URL = &url.URL{Scheme: scheme, Host: dest}
	return proxyReq
}
