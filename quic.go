// Copyright (c) 2024 homuler
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package mitm

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"github.com/quic-go/quic-go"
)

type QUICConfig struct {
	// RootCertificate is the root certificate to be used to forge certificates.
	RootCertificate *tls.Certificate

	// GetDestination specifies a function that returns the destination address of the connection.
	GetDestination func(conn net.Conn, serverName string) net.Addr

	// NextProtos is a list of supported ALPN protocols.
	// If it is empty, the client specified list is used to negotiate the protocol with the actual server.
	NextProtos []string

	// TLSServerConfig optionally specifies a tls.Config that is used to handle incoming connections.
	// That is, the tls.Config is used when the server is acting as a TLS server.
	TLSServerConfig *tls.Config

	// GetTLSClientConfig optionally specifies a function that returns a tls.Config that is used to dial the actual server.
	// That is, the returned tls.Config is used when the server is acting as a TLS client.
	GetTLSClientConfig func(serverName string, alpnProtocols []string) *tls.Config

	// ServerConfig optionally specifies a quic.Config that is used to handle incoming connections.
	ServerConfig *quic.Config

	// ClientConfig optionally specifies a quic.Config that is used to dial the actual server.
	ClientConfig *quic.Config

	// ServerInfoCache optionally specifies a cache that stores the information of the actual servers.
	// If not set, a new cache is created.
	ServerInfoCache ServerInfoCache
}

var (
	ErrInvalidQUICConfig = errors.New("invalid mitm.QUICConfig")
)

func (c *QUICConfig) Clone() *QUICConfig {
	if c == nil {
		return &QUICConfig{}
	}
	return &QUICConfig{
		RootCertificate:    c.RootCertificate,
		GetDestination:     c.GetDestination,
		NextProtos:         c.NextProtos,
		TLSServerConfig:    c.TLSServerConfig,
		GetTLSClientConfig: c.GetTLSClientConfig,
		ServerConfig:       c.ServerConfig,
		ClientConfig:       c.ClientConfig,
		ServerInfoCache:    c.ServerInfoCache,
	}
}

func (c *QUICConfig) normalize() *QUICConfig {
	c = c.Clone()

	if c.TLSServerConfig == nil {
		c.TLSServerConfig = &tls.Config{}
	}
	if c.GetTLSClientConfig == nil {
		c.GetTLSClientConfig = DefaultGetTLSClientConfig
	}
	if c.ServerInfoCache == nil {
		c.ServerInfoCache = make(ServerInfoCache)
	}
	return c
}

func (c *QUICConfig) validate() error {
	if c.RootCertificate == nil {
		return fmt.Errorf("%w: RootCertificate is required", ErrInvalidQUICConfig)
	}
	if c.GetDestination == nil {
		return fmt.Errorf("%w: GetDestination is required", ErrInvalidQUICConfig)
	}
	if c.TLSServerConfig != nil {
		if len(c.TLSServerConfig.Certificates) > 0 {
			return fmt.Errorf("%w: Certificates must be nil since they will be forged at runtime", ErrInvalidQUICConfig)
		}
		if c.TLSServerConfig.GetCertificate != nil {
			return fmt.Errorf("%w: GetCertificate must be nil since it will be overwritten", ErrInvalidQUICConfig)
		}
	}
	return nil
}

type quicListener struct {
	transport *quic.Transport
	listener  *quic.Listener
}

type QUICListener interface {
	Accept(context.Context) (quic.Connection, error)
	Close() error
	Addr() net.Addr
}

var _ QUICListener = (*quicListener)(nil)

func NewQUICListener(conn net.PacketConn, config *QUICConfig) (*quicListener, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}

	config = config.normalize()

	transport := &quic.Transport{Conn: conn}

	var quicServerConf *quic.Config
	if config.ServerConfig != nil {
		quicServerConf = config.ServerConfig.Clone()
	}

	var quicClientConf *quic.Config
	if config.ClientConfig != nil {
		quicClientConf = config.ClientConfig.Clone()
	}

	serverInfoCache := config.ServerInfoCache

	tlsServerConfig := config.TLSServerConfig
	tlsServerConfig.GetCertificate = func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		serverName := chi.ServerName
		alpnProtocols := chi.SupportedProtos
		if len(config.NextProtos) > 0 {
			alpnProtocols = deleteNotIn(alpnProtocols, config.NextProtos)
		}

		addr := config.GetDestination(chi.Conn, serverName)
		key := serverName
		if key == "" {
			key = addr.String()
		}

		si, ok := serverInfoCache[key]
		if ok {
			_, ok := si.alpnCache.get(alpnProtocols)
			if ok {
				// skip handshake & negotiation if succeeded once
				return si.certificate, nil
			}
			// we still need to negotiate the protocol
		} else {
			si = serverInfo{alpnCache: make(alpnCache)}
		}

		tlsConfig := config.GetTLSClientConfig(serverName, alpnProtocols)

		proxyConn, err := quic.DialAddr(context.Background(), addr.String(), tlsConfig, quicClientConf)
		if err != nil {
			return nil, fmt.Errorf("%w (serverName=%v, addr=%v): %w", ErrHandshakeWithServer, serverName, addr, err)
		}

		state := proxyConn.ConnectionState().TLS

		if si.certificate == nil {
			certs := state.PeerCertificates
			cert, err := ForgeCertificate(config.RootCertificate, certs[0])
			if err != nil {
				return nil, fmt.Errorf("mitm: failed to forge a certificate (serverName=%v, addr=%v): %w", serverName, addr, err)
			}
			si.certificate = &cert
		}
		si.cacheALPNResult(&state, alpnProtocols)

		serverInfoCache[key] = si

		return si.certificate, nil
	}

	listener, err := transport.Listen(tlsServerConfig, quicServerConf)
	if err != nil {
		return nil, err
	}

	return &quicListener{
		transport: transport,
		listener:  listener,
	}, nil
}

func (ql *quicListener) Accept(ctx context.Context) (quic.Connection, error) {
	return ql.listener.Accept(ctx)
}
func (ql *quicListener) Close() error   { return ql.transport.Close() }
func (ql *quicListener) Addr() net.Addr { return ql.listener.Addr() }
