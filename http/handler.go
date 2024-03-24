package http

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"

	"github.com/homuler/mitm-proxy-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

var (
	ErrProxyInternal = errors.New("proxy internal error")
)

type proxyHandler struct {
	handler   http.Handler
	tlsConfig *mitm.TLSConfig
	innerSrv  *http.Server
}

var _ http.Handler = (*proxyHandler)(nil)

func (h *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		switch r.ProtoMajor {
		case 1:
			h.handleHTTP1Connect(w, r)
		case 2:
			h.handleHTTP2Connect(w, r)
		default:
			panic(fmt.Errorf("http version not supported: %s", r.Proto))
		}
		return
	}
	h.handler.ServeHTTP(w, r)
}

func (h *proxyHandler) handleHTTP1Connect(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		panic(fmt.Errorf("%w: server doesn't support hijacking", ErrProxyInternal))
	}

	conn, bufrw, err := hj.Hijack()
	if err != nil {
		panic(fmt.Errorf("%w: failed to hijack the connection", ErrProxyInternal))
	}

	_, err = bufrw.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	err = errors.Join(err, bufrw.Flush())
	if err != nil {
		// TODO: log the error
		panic(err)
	}

	err = h.serveInnerConn(conn, r.URL)
	if err != nil {
		// TODO: log the error
		panic(err)
	}
}

type h2ResponseWriter interface {
	http.ResponseWriter
	http.Flusher
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

func (h *proxyHandler) handleHTTP2Connect(w http.ResponseWriter, r *http.Request) {
	conn := r.Context().Value(connKey{}).(net.Conn)

	h2rw := w.(h2ResponseWriter)
	h2rw.WriteHeader(http.StatusOK)
	h2rw.Flush()

	innerConn := mitm.NewTamperedConn(conn,
		mitm.TamperConnRead(r.Body.Read),
		mitm.TamperConnWrite(func(b []byte) (n int, err error) {
			n, err = h2rw.Write(b)
			h2rw.Flush()
			return
		}),
		mitm.TamperConnSetReadDeadline(h2rw.SetReadDeadline),
		mitm.TamperConnSetWriteDeadline(h2rw.SetWriteDeadline))

	if err := h.serveInnerConn(innerConn, r.URL); err != nil {
		// TODO: log the error
		panic(err)
	}
}

func (h *proxyHandler) serveInnerConn(conn net.Conn, destination *url.URL) error {
	close := make(chan struct{})
	tc := mitm.NewTamperedConn(conn,
		mitm.TamperConnClose(func() error {
			// NOTE:
			//   Even if Close is called by the inner server, we should not close the outer connection, especially when HTTP/2 is used.
			//	 Instead, we receive the notification and close the connection at that time.
			close <- struct{}{}
			return nil
		}))

	config := h.tlsConfig.Clone()
	config.GetDestination = func(net.Conn, string) net.Addr { return NewURLAddr(conn.LocalAddr().Network(), destination) }

	tlsConn, err := mitm.NewTLSServer(tc, config)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrProxyInternal, err)
	}
	ln := mitm.NewOneTimeListener(tlsConn)

	go func() {
		inerr := h.innerSrv.Serve(ln)
		if !errors.Is(inerr, syscall.EINVAL) {
			err = inerr
		}
		fmt.Println("serve done")
	}()

	<-close
	return errors.Join(err, ln.Close())
}

func Proxify(handler http.Handler, tlsConfig *mitm.TLSConfig) *proxyHandler {
	config := tlsConfig.Clone()
	if config.ServerInfoCache == nil {
		config.ServerInfoCache = make(mitm.ServerInfoCache)
	}

	return &proxyHandler{
		handler:   handler,
		tlsConfig: config,
		innerSrv: &http.Server{
			Handler: TProxify(handler),
			ConnContext: func(ctx context.Context, c net.Conn) context.Context {
				var pc *mitm.ProxyConn
				tlsConn, ok := c.(*tls.Conn)
				if ok {
					pc = tlsConn.NetConn().(*mitm.ProxyConn)
				} else {
					pc = c.(*mitm.ProxyConn)
				}

				return WithDestination(ctx, pc.Destination())
			},
		},
	}
}

type tproxyHandler struct {
	handler http.Handler
}

var _ http.Handler = (*tproxyHandler)(nil)

func (h *tproxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	dest, ok := GetDestination(r)
	if !ok {
		panic(errors.New("destination is not stored in the context"))
	}

	proxyReq := CopyAsProxyRequest(r, dest.String())
	h.handler.ServeHTTP(w, proxyReq)
}

func TProxify(handler http.Handler) *tproxyHandler {
	return &tproxyHandler{handler: handler}
}

var RoundTripHandlerFunc http.HandlerFunc = handleRoundTrip

func handleRoundTrip(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("%+v\n", r)
	rt := NewRoundTripper(r)
	res, err := rt.RoundTrip(r)
	if err != nil {
		panic(fmt.Errorf("failed to request to %v: %w", r.URL, err))
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

func NewRoundTripper(r *http.Request) http.RoundTripper {
	if r.TLS == nil {
		return &http.Transport{
			DisableKeepAlives: true,
		}
	}

	serverName := r.TLS.ServerName
	switch r.ProtoMajor {
	case 2:
		return &http2.Transport{
			TLSClientConfig: &tls.Config{
				ServerName: serverName,
				NextProtos: []string{"h2"},
			},
		}
	case 3:
		return &http3.RoundTripper{
			TLSClientConfig: &tls.Config{
				ServerName: serverName,
				NextProtos: []string{"h3"},
			},
		}
	default:
		return &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName: serverName,
				NextProtos: []string{"http/1.1"},
			},
			DisableKeepAlives: true,
		}
	}
}
