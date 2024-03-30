package http3

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/homuler/mitm-go"
	mitmhttp "github.com/homuler/mitm-go/http"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type destinationKey struct{}

func withDestination(ctx context.Context, dstAddr net.Addr) context.Context {
	return context.WithValue(ctx, destinationKey{}, dstAddr)
}

func getDestination(r *http.Request) net.Addr {
	return r.Context().Value(destinationKey{}).(net.Addr)
}

type tproxyHandler struct {
	handler http.Handler
}

var _ http.Handler = (*tproxyHandler)(nil)

func (h *tproxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	dest := getDestination(r)
	proxyReq := mitmhttp.CopyAsProxyRequest(r, dest.String())
	h.handler.ServeHTTP(w, proxyReq)
}

type proxyServer struct {
	http3.Server
}

type ProxyServerOption func(*proxyServer) error

// Addr optionally specifies the UDP address for the server to listen on,
// in the form "host:port".
//
// When used by ListenAndServe and ListenAndServeTLS methods, if empty,
// ":https" (port 443) is used. See net.Dial for details of the address
// format.
func Addr(addr string) ProxyServerOption {
	return func(psrv *proxyServer) error {
		psrv.Addr = addr
		return nil
	}
}

// TLSConfig optionally provides a TLS configuration for use by server.
func TLSConfig(config *tls.Config) ProxyServerOption {
	return func(psrv *proxyServer) error {
		psrv.TLSConfig = config.Clone()
		return nil
	}
}

// QuicConfig provides the parameters for QUIC connection created with
// Serve. If nil, it uses reasonable default values.
func QUICServerConfig(config *quic.Config) ProxyServerOption {
	return func(psrv *proxyServer) error {
		psrv.QuicConfig = config
		return nil
	}
}

// Handler is the HTTP request handler to use. If not set, defaults to
// mitmhttp.RoundTripHandler.
func Handler(h http.Handler) ProxyServerOption {
	return func(psrv *proxyServer) error {
		psrv.Handler = h
		return nil
	}
}

// EnableDatagrams enables support for HTTP/3 datagrams.
// If set to true, QuicConfig.EnableDatagram will be set.
// See https://datatracker.ietf.org/doc/html/rfc9297.
func EnableDatagrams(v bool) ProxyServerOption {
	return func(psrv *proxyServer) error {
		psrv.EnableDatagrams = v
		return nil
	}
}

// MaxHeaderBytes controls the maximum number of bytes the server will
// read parsing the request HEADERS frame. It does not limit the size of
// the request body. If zero or negative, http.DefaultMaxHeaderBytes is
// used.
func MaxHeaderBytes(v int) ProxyServerOption {
	return func(psrv *proxyServer) error {
		psrv.MaxHeaderBytes = v
		return nil
	}
}

// AdditionalSettings specifies additional HTTP/3 settings.
// It is invalid to specify any settings defined by the HTTP/3 draft and the datagram draft.
func AdditionalSettings(v map[uint64]uint64) ProxyServerOption {
	return func(psrv *proxyServer) error {
		psrv.AdditionalSettings = v
		return nil
	}
}

// ConnContext optionally specifies a function that modifies
// the context used for a new connection c. The provided ctx
// has a ServerContextKey value.
func ConnContext(f func(ctx context.Context, c quic.Connection) context.Context) ProxyServerOption {
	return func(psrv *proxyServer) error {
		psrv.ConnContext = f
		return nil
	}
}

type TProxyServer struct {
	*proxyServer
	config *mitm.QUICConfig
}

func nopConnContext(ctx context.Context, c quic.Connection) context.Context {
	return ctx
}

func NewTProxyServer(config *mitm.QUICConfig, opts ...ProxyServerOption) TProxyServer {
	psrv := &proxyServer{
		http3.Server{
			Handler: mitmhttp.RoundTripHandlerFunc,
		},
	}
	for _, opt := range opts {
		opt(psrv)
	}

	config = config.Clone()
	if config.NextProtos == nil {
		config.NextProtos = []string{"h3"}
	}
	if config.TLSServerConfig == nil {
		config.TLSServerConfig = &tls.Config{}
	}
	if config.TLSServerConfig.NextProtos == nil {
		config.TLSServerConfig.NextProtos = config.NextProtos
	}

	if psrv.Server.ConnContext == nil {
		psrv.Server.ConnContext = nopConnContext
	}

	connCtx := psrv.Server.ConnContext

	psrv.Server.ConnContext = func(ctx context.Context, c quic.Connection) context.Context {
		ctx = withDestination(ctx, c.LocalAddr())

		return connCtx(ctx, c)
	}

	psrv.Handler = &tproxyHandler{handler: psrv.Handler}
	return TProxyServer{proxyServer: psrv, config: config}
}

func (psrv *TProxyServer) Serve(conn net.PacketConn) (err error) {
	ql, err := mitm.NewQUICListener(conn, psrv.config)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, ql.Close())
	}()

	return psrv.ServeListener(ql)
}

func (psrv *TProxyServer) ServeListener(listener mitm.QUICListener) error {
	for {
		conn, err := listener.Accept(context.Background())
		if err == quic.ErrServerClosed {
			return http.ErrServerClosed
		}
		if err != nil {
			return err
		}

		go func() {
			if err := psrv.ServeQUICConn(conn); err != nil {
				// TODO: use logger
				fmt.Printf("serve error: %v\n", err)
			}
		}()
	}
}
