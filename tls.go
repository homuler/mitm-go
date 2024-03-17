package mitm

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
)

type supportedProtocolMap map[string]bool

func (m supportedProtocolMap) getFirst(protos []string) (string, bool) {
	for _, p := range protos {
		supported, ok := m[p]
		if supported {
			return p, true
		}
		if !ok {
			return p, false
		}
	}
	return "", false
}

type serverInfo struct {
	certificate *tls.Certificate

	protocols supportedProtocolMap // TODO: clear it periodically
}

type ServerInfoCache map[string]serverInfo

type TLSConfig struct {
	// RootCertificate is the root certificate to be used to forge certificates.
	RootCertificate *tls.Certificate

	// GetDestination optionally specifies a function that returns the destination address of the connection.
	// If not set, the destination address is determined by the ClientHello message.
	GetDestination func(conn net.Conn, serverName string) net.Addr

	// NextProtos is a list of supported ALPN protocols.
	// If it is empty, the client specified list is used to negotiate the protocol with the actual server.
	NextProtos []string

	// GetServerConfig optionally specifies a function that returns a tls.Config that is used to handle incoming connections.
	GetServerConfig func(certificate *tls.Certificate, negotiatedProtocol string) *tls.Config

	// GetClientConfig optionally specifies a function that returns a tls.Config that is used to dial the actual server.
	GetClientConfig func(serverName string, alpnProtocols []string) *tls.Config
}

var (
	ErrMissingRootCertificate = errors.New("TLSConfig: RootCertificate is required")
)

func (c *TLSConfig) Clone() *TLSConfig {
	return &TLSConfig{
		RootCertificate: c.RootCertificate,
		GetDestination:  c.GetDestination,
		NextProtos:      c.NextProtos,
		GetServerConfig: c.GetServerConfig,
		GetClientConfig: c.GetClientConfig,
	}
}

func (c *TLSConfig) validate() error {
	if c.RootCertificate == nil {
		return ErrMissingRootCertificate
	}
	return nil
}

type tlsListener struct {
	listener net.Listener
	config   *TLSConfig

	serverInfoCache ServerInfoCache
}

var _ net.Listener = (*tlsListener)(nil)

var defaultBufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 0)
		return &buf
	},
}

var defaultGetDestination = func(conn net.Conn, serverName string) net.Addr {
	return &addr{network: conn.LocalAddr().Network(), str: serverName}
}

// NewTLSListener returns a new net.Listener that listens for incoming TLS connections on l.
func NewTLSListener(l net.Listener, config *TLSConfig) (net.Listener, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}

	if config.GetDestination == nil {
		config.GetDestination = defaultGetDestination
	}

	return &tlsListener{
		listener: l,
		config:   config.Clone(),

		serverInfoCache: make(ServerInfoCache),
	}, nil
}

func (tl *tlsListener) Accept() (net.Conn, error) {
	conn, err := tl.listener.Accept()
	if err != nil {
		return nil, err
	}

	tlsConn, err := newTLSServer(conn, tl.config, tl.serverInfoCache)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (tl *tlsListener) Close() error   { return tl.listener.Close() }
func (tl *tlsListener) Addr() net.Addr { return tl.listener.Addr() }

var (
	ErrPeekClientHello     = errors.New("failed to peek client hello")
	ErrHandshakeWithServer = errors.New("failed to handshake with the server")
)

type tlsConn struct {
	conn   net.Conn
	reader *memorizingReader
	config *TLSConfig
}

func NewTLSServer(conn net.Conn, config *TLSConfig, serverInfoCache ServerInfoCache) (*tls.Conn, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	if config.GetDestination == nil {
		config.GetDestination = defaultGetDestination
	}

	return newTLSServer(conn, config, serverInfoCache)
}

func newTLSServer(conn net.Conn, config *TLSConfig, serverInfoCache ServerInfoCache) (*tls.Conn, error) {
	bufPtr := defaultBufferPool.Get().(*[]byte)
	c := newTlsConn(conn, config, (*bufPtr)[0:0])
	clientHello := &clientHelloMsg{}

	err := peekClientHello(c.reader, clientHello)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPeekClientHello, err)
	}

	dstAddr := config.GetDestination(conn, clientHello.serverName)
	cert, protocol, err := c.handshakeWithServer(dstAddr, clientHello, serverInfoCache)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHandshakeWithServer, err)
	}

	var serverConfig *tls.Config
	if c.config.GetServerConfig != nil {
		serverConfig = c.config.GetServerConfig(cert, protocol)
	} else {
		serverConfig = &tls.Config{
			Certificates: []tls.Certificate{*cert},
			NextProtos:   []string{protocol},
		}
	}

	_, err = c.reader.Seek(0, io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf("failed to seek the reader: %w", err)
	}
	proxyConn := NewProxyConn(c.conn, dstAddr,
		TamperConnRead(c.reader.OneTimeReader().Read),
		TamperConnClose(func() error {
			*bufPtr = c.reader.buf
			defaultBufferPool.Put(bufPtr)
			return nil
		}))
	return tls.Server(proxyConn, serverConfig), nil
}

func newTlsConn(conn net.Conn, config *TLSConfig, buffer []byte) *tlsConn {
	return &tlsConn{
		conn:   conn,
		reader: NewMemorizingReader(conn, buffer),
		config: config,
	}
}

// handshakeWithServer returns a certificate of the server and the negotiated protocol.
// serverInfoCache will be updated with the result.
func (c *tlsConn) handshakeWithServer(dstAddr net.Addr, msg *clientHelloMsg, serverInfoCache ServerInfoCache) (*tls.Certificate, string, error) {
	serverName := msg.serverName
	alpnProtocols := msg.alpnProtocols
	if len(c.config.NextProtos) > 0 {
		ps := c.config.NextProtos
		alpnProtocols = slices.DeleteFunc(alpnProtocols, func(s string) bool {
			return !slices.Contains(ps, s)
		})
	}

	si, ok := serverInfoCache[serverName]
	if ok {
		protocol, ok := si.protocols.getFirst(alpnProtocols)
		if ok || protocol == "" {
			// skip handshake & negotiation
			return si.certificate, protocol, nil
		}
		// we still need to negotiate the protocol
	} else {
		si = serverInfo{protocols: make(supportedProtocolMap)}
	}

	var clientConfig *tls.Config
	if c.config.GetClientConfig != nil {
		clientConfig = c.config.GetClientConfig(serverName, alpnProtocols)
	} else {
		clientConfig = &tls.Config{
			ServerName: serverName,
			NextProtos: alpnProtocols,
		}
	}

	tc, err := tls.Dial(dstAddr.Network(), dstAddr.String(), clientConfig)
	if err != nil {
		return nil, "", fmt.Errorf("failed to dial %v(%v): %w", serverName, dstAddr, err)
	}
	state := tc.ConnectionState()

	if si.certificate == nil {
		certs := state.PeerCertificates
		if len(certs) == 0 {
			// it should not occur.
			return nil, "", fmt.Errorf("no certificates of %v(%v) found", serverName, dstAddr)
		}
		cert, err := ForgeCertificate(c.config.RootCertificate, certs[0])
		if err != nil {
			return nil, "", fmt.Errorf("failed to forge a certificate of %v(%v): %w", serverName, dstAddr, err)
		}
		si.certificate = &cert
	}

	negotiatedProtocol := state.NegotiatedProtocol
	for _, p := range clientConfig.NextProtos {
		if p == negotiatedProtocol {
			break
		}
		si.protocols[p] = false
	}
	si.protocols[negotiatedProtocol] = true
	serverInfoCache[serverName] = si

	return si.certificate, state.NegotiatedProtocol, nil
}

var (
	errUnexpectedRecordType = errors.New("unexpected record type")
	errInvalidClientHello   = errors.New("invalid ClientHello")
)

func peekClientHello(r *memorizingReader, msg *clientHelloMsg) error {
	hdr, err := r.Next(recordHeaderLen)
	if err != nil {
		return err
	}

	typ := recordType(hdr[0])
	ver := uint16(hdr[1])<<8 | uint16(hdr[2])

	if typ != recordTypeHandshake || ver > 0x1000 {
		return fmt.Errorf("%w: type=%v, ver=%v", errUnexpectedRecordType, typ, ver)
	}
	n := int(hdr[3])<<8 | int(hdr[4])

	fragment, err := r.Next(n)
	if err != nil {
		return fmt.Errorf("failed to read the fragment: %w", err)
	}

	if !unmarshalClientHello(fragment, msg) {
		return errInvalidClientHello
	}
	return nil
}
