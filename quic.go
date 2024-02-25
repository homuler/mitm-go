package mitm

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/quic-go/quic-go"
)

type QUICListenerConfig struct {
	ServerConfig *quic.Config
	ClientConfig *quic.Config
}

type quicListener struct {
	transport *quic.Transport
	listener  *quic.Listener

	config *QUICListenerConfig
}

type QUICListener interface {
	Accept(context.Context) (quic.Connection, error)
	Close() error
	Addr() net.Addr
}

var _ QUICListener = (*quicListener)(nil)

// NewQUICListener returns a new net.Listener that listens for incoming TLS connections on l.
func NewQUICListener(conn net.PacketConn, rootCert tls.Certificate, config *QUICListenerConfig) (*quicListener, error) {
	certStore := make(map[string]*tls.Certificate)
	transport := &quic.Transport{Conn: conn}
	// TODO: make it configurable
	nextProtos := []string{"h3"}

	var quicServerConf *quic.Config
	if config != nil {
		quicServerConf = config.ServerConfig.Clone()
	}

	var quicClientConf *quic.Config
	if config != nil {
		quicClientConf = config.ClientConfig.Clone()
	}

	listener, err := transport.Listen(&tls.Config{
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			serverName := chi.ServerName

			if cert, ok := certStore[serverName]; ok {
				return cert, nil
			}

			addr := chi.Conn.LocalAddr()
			proxyConn, err := quic.DialAddr(context.Background(), addr.String(), &tls.Config{
				ServerName: serverName,
				NextProtos: nextProtos,
			}, quicClientConf)
			if err != nil {
				return nil, fmt.Errorf("failed to handshake with %v(%v): %w", serverName, addr, err)
			}

			certs := proxyConn.ConnectionState().TLS.PeerCertificates
			if len(certs) == 0 {
				// it should not occur.
				return nil, fmt.Errorf("no certificates of %v(%v) found", serverName, addr)
			}
			cert, err := ForgeCertificate(&rootCert, certs[0])
			if err != nil {
				return nil, fmt.Errorf("failed to forge a certificate of %v(%v): %w", serverName, addr, err)
			}
			certStore[serverName] = &cert
			return &cert, nil
		},
		NextProtos: nextProtos,
	}, quicServerConf)
	if err != nil {
		return nil, err
	}

	return &quicListener{
		transport: transport,
		listener:  listener,

		config: config,
	}, nil
}

func (ql *quicListener) Accept(ctx context.Context) (quic.Connection, error) {
	return ql.listener.Accept(ctx)
}
func (ql *quicListener) Close() error   { return ql.transport.Close() }
func (ql *quicListener) Addr() net.Addr { return ql.listener.Addr() }
