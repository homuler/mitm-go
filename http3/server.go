package http3

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/homuler/mitm-proxy-go"
	mitmhttp "github.com/homuler/mitm-proxy-go/http"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type destinationKey struct{}

func getDestination(r *http.Request) string {
	return r.Context().Value(destinationKey{}).(string)
}

func tproxyConnContext(ctx context.Context, c quic.Connection) context.Context {
	return context.WithValue(ctx, destinationKey{}, c.LocalAddr().String())
}

type tproxyHandler struct {
	handler http.Handler
}

var _ http.Handler = (*tproxyHandler)(nil)

func (h *tproxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	dest := getDestination(r)
	proxyReq := mitmhttp.CopyAsProxyRequest(r, dest)
	h.handler.ServeHTTP(w, proxyReq)
}

type ProxyServerOption func(*ProxyServer) error

type ProxyServer struct {
	server *http3.Server

	rootCert        tls.Certificate
	nextProtos      []string
	getServerConfig func(certificate *tls.Certificate, negotiatedProtocol string) *tls.Config
	getClientConfig func(serverName string, alpnProtocols []string) *tls.Config
}

// Addr optionally specifies the UDP address for the server to listen on,
// in the form "host:port".
//
// When used by ListenAndServe and ListenAndServeTLS methods, if empty,
// ":https" (port 443) is used. See net.Dial for details of the address
// format.
func Addr(addr string) ProxyServerOption {
	return func(psrv *ProxyServer) error {
		psrv.server.Addr = addr
		return nil
	}
}

// TLSConfig optionally provides a TLS configuration for use by server.
func TLSConfig(config *tls.Config) ProxyServerOption {
	return func(psrv *ProxyServer) error {
		psrv.server.TLSConfig = config.Clone()
		return nil
	}
}

// QuicConfig provides the parameters for QUIC connection created with
// Serve. If nil, it uses reasonable default values.
func QUICServerConfig(config *quic.Config) ProxyServerOption {
	return func(psrv *ProxyServer) error {
		psrv.server.QuicConfig = config
		return nil
	}
}

// Handler is the HTTP request handler to use. If not set, defaults to
// mitmhttp.RoundTripHandler.
func Handler(h http.Handler) ProxyServerOption {
	return func(psrv *ProxyServer) error {
		psrv.server.Handler = h
		return nil
	}
}

// EnableDatagrams enables support for HTTP/3 datagrams.
// If set to true, QuicConfig.EnableDatagram will be set.
// See https://datatracker.ietf.org/doc/html/rfc9297.
func EnableDatagrams(v bool) ProxyServerOption {
	return func(psrv *ProxyServer) error {
		psrv.server.EnableDatagrams = v
		return nil
	}
}

// MaxHeaderBytes controls the maximum number of bytes the server will
// read parsing the request HEADERS frame. It does not limit the size of
// the request body. If zero or negative, http.DefaultMaxHeaderBytes is
// used.
func MaxHeaderBytes(v int) ProxyServerOption {
	return func(psrv *ProxyServer) error {
		psrv.server.MaxHeaderBytes = v
		return nil
	}
}

// AdditionalSettings specifies additional HTTP/3 settings.
// It is invalid to specify any settings defined by the HTTP/3 draft and the datagram draft.
func AdditionalSettings(v map[uint64]uint64) ProxyServerOption {
	return func(psrv *ProxyServer) error {
		psrv.server.AdditionalSettings = v
		return nil
	}
}

// ConnContext optionally specifies a function that modifies
// the context used for a new connection c. The provided ctx
// has a ServerContextKey value.
func ConnContext(f func(ctx context.Context, c quic.Connection) context.Context) ProxyServerOption {
	return func(psrv *ProxyServer) error {
		psrv.server.ConnContext = func(ctx context.Context, c quic.Connection) context.Context {
			return f(tproxyConnContext(ctx, c), c)
		}
		return nil
	}
}

// NextProtos is a list of supported ALPN protocols.
// If it is empty, the client specified list is used to negotiate the protocol with the actual server.
func NextProtos(protos []string) ProxyServerOption {
	return func(psrv *ProxyServer) error {
		psrv.nextProtos = protos
		return nil
	}
}

// GetServerConfig optionally specifies a function that returns a tls.Config that is used to handle incoming connections.
func GetServerConfig(f func(certificate *tls.Certificate, negotiatedProtocol string) *tls.Config) ProxyServerOption {
	return func(psrv *ProxyServer) error {
		psrv.getServerConfig = f
		return nil
	}
}

// GetClientConfig optionally specifies a function that returns a tls.Config that is used to dial the actual server.
func GetClientConfig(f func(serverName string, alpnProtocols []string) *tls.Config) ProxyServerOption {
	return func(psrv *ProxyServer) error {
		psrv.getClientConfig = f
		return nil
	}
}

func NewTProxyServer(rootCert tls.Certificate, opts ...ProxyServerOption) *ProxyServer {
	psrv := &ProxyServer{
		server: &http3.Server{
			Handler:     mitmhttp.RoundTripHandlerFunc,
			ConnContext: tproxyConnContext,
		},
		rootCert: rootCert,
	}
	for _, opt := range opts {
		opt(psrv)
	}
	psrv.server.Handler = &tproxyHandler{handler: psrv.server.Handler}
	return psrv
}

func (psrv *ProxyServer) Close() error {
	return psrv.server.Close()
}

func (psrv *ProxyServer) Serve(conn net.PacketConn) (err error) {
	ql, err := mitm.NewQUICListener(conn, psrv.rootCert, nil)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, ql.Close())
	}()

	return psrv.ServeListener(ql)
}

func (psrv *ProxyServer) ServeListener(listener mitm.QUICListener) error {
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
				fmt.Println(err)
			}
		}()
	}
}

func (psrv *ProxyServer) ServeQUICConn(conn quic.Connection) error {
	return psrv.server.ServeQUICConn(conn)
}
