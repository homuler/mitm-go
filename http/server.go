package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/homuler/mitm-proxy-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

type connKey struct{}

func getProxyConn(r *http.Request) ProxyConn {
	return r.Context().Value(connKey{}).(ProxyConn)
}

func withConn(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, connKey{}, c)
}

type tproxyHandler struct {
	handler http.Handler
}

var _ http.Handler = (*tproxyHandler)(nil)

func (h *tproxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn := getProxyConn(r)
	proxyReq := CopyAsProxyRequest(r, conn)
	h.handler.ServeHTTP(w, proxyReq)
}

type roundTripHandler struct{}

var RoundTripHandler http.Handler = &roundTripHandler{}

func (h *roundTripHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("%+v\n", r)
	rt, err := NewRoundTripper(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to build an HTTP client: %v", err), http.StatusInternalServerError)
		return
	}

	res, err := rt.RoundTrip(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to request to %v: %v", r.URL, err), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	fmt.Printf("%+v\n", res)
	header := w.Header()
	for k, v := range res.Header {
		for _, vv := range v {
			header.Add(k, vv)
		}
	}
	w.WriteHeader(res.StatusCode)
	_, err = io.Copy(w, res.Body)
	if err != nil {
		panic(err)
	}
}

func NewRoundTripper(r *http.Request) (http.RoundTripper, error) {
	if r.TLS == nil {
		return &http.Transport{}, nil
	}

	serverName := r.TLS.ServerName
	switch r.ProtoMajor {
	case 2:
		return &http2.Transport{
			TLSClientConfig: &tls.Config{
				ServerName: serverName,
				NextProtos: []string{"h2"},
			},
		}, nil
	case 3:
		return &http3.RoundTripper{
			TLSClientConfig: &tls.Config{
				ServerName: serverName,
				NextProtos: []string{"h3"},
			},
		}, nil
	default:
		return &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName: serverName,
				NextProtos: []string{"http/1.1"},
			},
		}, nil
	}
}

type ProxyServer struct {
	server     *http.Server
	nextProtos []string

	inShutdown atomic.Bool // true when server is in shutdown
}

type ProxyServerOption func(*ProxyServer) error

// Addr optionally specifies the TCP address for the server to listen on,
// in the form "host:port". If empty, ":http" (port 80) is used.
// The service names are defined in RFC 6335 and assigned by IANA.
// See net.Dial for details of the address format.
func Addr(addr string) ProxyServerOption {
	return func(psrv *ProxyServer) error {
		psrv.server.Addr = addr
		return nil
	}
}

// Handler specifies the handler to invoke, RoundTripHandler if nil
func Handler(h http.Handler) ProxyServerOption {
	return func(psrv *ProxyServer) error {
		psrv.server.Handler = h
		return nil
	}
}

// DisableGeneralOptionsHandler, if true, passes "OPTIONS *" requests to the Handler,
// otherwise responds with 200 OK and Content-Length: 0.
func DisableGeneralOptionsHandler(v bool) ProxyServerOption {
	return func(psrv *ProxyServer) error {
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
	return func(psrv *ProxyServer) error {
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
	return func(psrv *ProxyServer) error {
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
	return func(psrv *ProxyServer) error {
		psrv.server.WriteTimeout = d
		return nil
	}
}

// IdleTimeout is the maximum amount of time to wait for the
// next request when keep-alives are enabled. If IdleTimeout
// is zero, the value of ReadTimeout is used. If both are
// zero, there is no timeout.
func IdleTimeout(d time.Duration) ProxyServerOption {
	return func(psrv *ProxyServer) error {
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
	return func(psrv *ProxyServer) error {
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
	return func(psrv *ProxyServer) error {
		psrv.server.TLSNextProto = m
		return nil
	}
}

func TLSNextProtos(protos []string) ProxyServerOption {
	return func(psrv *ProxyServer) error {
		psrv.nextProtos = protos
		return nil
	}
}

// ConnState specifies an optional callback function that is
// called when a client connection changes state. See the
// ConnState type and associated constants for details.
func ConnState(f func(net.Conn, http.ConnState)) ProxyServerOption {
	return func(psrv *ProxyServer) error {
		psrv.server.ConnState = f
		return nil
	}
}

// ErrorLog specifies an optional logger for errors accepting
// connections, unexpected behavior from handlers, and
// underlying FileSystem errors.
// If nil, logging is done via the log package's standard logger.
func ErrorLog(l *log.Logger) ProxyServerOption {
	return func(psrv *ProxyServer) error {
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
	return func(psrv *ProxyServer) error {
		psrv.server.BaseContext = f
		return nil
	}
}

// ConnContext optionally specifies a function that modifies
// the context used for a new connection c. The provided ctx
// is derived from the base context and has a ServerContextKey
// value.
func ConnContext(f func(ctx context.Context, c net.Conn) context.Context) ProxyServerOption {
	return func(psrv *ProxyServer) error {
		psrv.server.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
			return f(withConn(ctx, c), c)
		}
		return nil
	}
}

func (psrv *ProxyServer) Close() error {
	psrv.inShutdown.Store(true)
	return psrv.server.Close()
}

func (psrv *ProxyServer) Shutdown(ctx context.Context) error {
	psrv.inShutdown.Store(true)
	return psrv.server.Shutdown(ctx)
}

func (psrv *ProxyServer) RegisterOnShutdown(f func()) {
	psrv.server.RegisterOnShutdown(f)
}

func (psrv *ProxyServer) Serve(l net.Listener) error {
	return psrv.server.Serve(l)
}

func (psrv *ProxyServer) ServeTLS(l net.Listener, certFile, keyFile string) error {
	nextProtos := psrv.nextProtos
	if len(nextProtos) == 0 {
		nextProtos = []string{"h2", "http/1.1"}
	}
	tl := mitm.NewTLSListener(l, &mitm.TLSListenerConfig{
		NextProtos: nextProtos,
	})
	return psrv.server.Serve(tl)
}

func NewTProxyServer(options ...ProxyServerOption) *ProxyServer {
	psrv := &ProxyServer{
		server: &http.Server{
			Handler:     RoundTripHandler,
			ConnContext: withConn,
		},
	}
	for _, opt := range options {
		opt(psrv)
	}
	psrv.server.Handler = &tproxyHandler{handler: psrv.server.Handler}
	return psrv
}

var (
	httpScheme  = "http"
	httpsScheme = "https"
)

func CopyAsProxyRequest(req *http.Request, conn ProxyConn) *http.Request {
	proxyReq := req.Clone(req.Context())
	scheme := httpsScheme
	if req.TLS == nil {
		scheme = httpScheme
	}
	proxyReq.URL = &url.URL{Scheme: scheme, Host: conn.LocalAddr().String()}
	return proxyReq
}
