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

	// GetDestination specifies a function that returns the destination address of the connection.
	GetDestination func(conn net.Conn, serverName string) net.Addr

	// NextProtos is a list of supported ALPN protocols.
	// If it is empty, the client specified list is used to negotiate the protocol with the actual server.
	NextProtos []string

	// GetServerConfig optionally specifies a function that returns a tls.Config that is used to handle incoming connections.
	// That is, the returned tls.Config is used when the server is acting as a TLS server.
	GetServerConfig func(certificate *tls.Certificate, negotiatedProtocol string, err error) *tls.Config

	// GetClientConfig optionally specifies a function that returns a tls.Config that is used to dial the actual server.
	// That is, the returned tls.Config is used when the server is acting as a TLS client.
	GetClientConfig func(serverName string, alpnProtocols []string) *tls.Config

	// ServerInfoCache optionally specifies a cache that stores the information of the actual servers.
	// If not set, a new cache is created.
	ServerInfoCache ServerInfoCache
}

var (
	ErrInvalidTLSConfig = errors.New("invalid mitm.TLSConfig")
)

func (c *TLSConfig) Clone() *TLSConfig {
	if c == nil {
		return &TLSConfig{}
	}
	return &TLSConfig{
		RootCertificate: c.RootCertificate,
		GetDestination:  c.GetDestination,
		NextProtos:      c.NextProtos,
		GetServerConfig: c.GetServerConfig,
		GetClientConfig: c.GetClientConfig,
		ServerInfoCache: c.ServerInfoCache,
	}
}

func (c *TLSConfig) normalize() *TLSConfig {
	c = c.Clone()

	if c.GetServerConfig == nil {
		c.GetServerConfig = defaultGetServerConfig
	}
	if c.GetClientConfig == nil {
		c.GetClientConfig = defaultGetClientConfig
	}
	if c.ServerInfoCache == nil {
		c.ServerInfoCache = make(ServerInfoCache)
	}
	return c
}

func (c *TLSConfig) validate() error {
	if c.RootCertificate == nil {
		return fmt.Errorf("%w: RootCertificate is required", ErrInvalidTLSConfig)
	}
	if c.GetDestination == nil {
		return fmt.Errorf("%w: GetDestination is required", ErrInvalidTLSConfig)
	}
	return nil
}

type tlsListener struct {
	listener net.Listener
	config   *TLSConfig
}

var _ net.Listener = (*tlsListener)(nil)

var defaultBufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 0)
		return &buf
	},
}

var defaultGetServerConfig = func(certificate *tls.Certificate, negotiatedProtocol string, err error) *tls.Config {
	config := &tls.Config{}

	if err != nil {
		config.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return nil, err
		}
		return config
	}

	// if negotiatedProtocol is empty(""), the handshake will succeed only if the client does not support ALPN.
	config.NextProtos = []string{negotiatedProtocol}

	if certificate != nil {
		config.Certificates = []tls.Certificate{*certificate}
	}

	return config
}

var defaultGetClientConfig = func(serverName string, alpnProtocols []string) *tls.Config {
	return &tls.Config{
		ServerName: serverName,
		NextProtos: alpnProtocols,
	}
}

// NewTLSListener returns a new net.Listener that listens for incoming TLS connections on l.
func NewTLSListener(l net.Listener, config *TLSConfig) (net.Listener, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}

	return &tlsListener{
		listener: l,
		config:   config.normalize(),
	}, nil
}

func (tl *tlsListener) Accept() (net.Conn, error) {
	conn, err := tl.listener.Accept()
	if err != nil {
		return nil, err
	}

	return tlsServer(conn, tl.config), nil
}

func (tl *tlsListener) Close() error   { return tl.listener.Close() }
func (tl *tlsListener) Addr() net.Addr { return tl.listener.Addr() }

var (
	ErrHandshakeWithServer   = errors.New("mitm: upstream certificate sniffing failed")
	ErrNoApplicationProtocol = errors.New("mitm: no application protocol")
)

type tlsConn struct {
	conn net.Conn

	reader *memorizingReader
	config *TLSConfig
}

func NewTLSServer(conn net.Conn, config *TLSConfig) (*tls.Conn, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}

	return tlsServer(conn, config.normalize()), nil
}

// tlsServer returns a TLS server connection and the error that occurred while forging a certificate if any.
// tls.Conn is always returned even if an error occurred.
func tlsServer(conn net.Conn, config *TLSConfig) *tls.Conn {
	bufPtr := defaultBufferPool.Get().(*[]byte)
	tlsConn := newTlsConn(conn, config, (*bufPtr)[0:0])
	closeTLSConn := func() (err error) {
		err = tlsConn.conn.Close()
		*bufPtr = tlsConn.reader.buf
		defaultBufferPool.Put(bufPtr)
		return
	}

	clientHello := &clientHelloMsg{}
	err := tlsConn.readClientHello(clientHello)
	// NOTE: we have peeked the ClientHello message and won't peek more data from the connection.
	{
		// this must not fail
		_, err := tlsConn.reader.Seek(0, io.SeekStart)
		if err != nil {
			panic(err)
		}
	}
	if err != nil {
		// let tls.Server to handle the error.
		// The same error should occur because the same message will be read.
		c := NewProxyConn(tlsConn.conn, nil,
			TamperConnRead(tlsConn.reader.OneTimeReader().Read),
			TamperConnClose(closeTLSConn))
		return tls.Server(c, nil)
	}

	dstAddr := config.GetDestination(conn, clientHello.serverName)
	proxyConn := NewProxyConn(tlsConn.conn, dstAddr,
		TamperConnRead(tlsConn.reader.OneTimeReader().Read),
		TamperConnClose(closeTLSConn))

	cert, protocol, err := tlsConn.handshakeWithServer(dstAddr, clientHello)

	serverConfig := tlsConn.config.GetServerConfig(cert, protocol, err)
	return tls.Server(proxyConn, serverConfig)
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
// Note that even if the error in the return value is not nil, other return values may not be zero values.
func (c *tlsConn) handshakeWithServer(dstAddr net.Addr, msg *clientHelloMsg) (*tls.Certificate, string, error) {
	serverName := msg.serverName
	alpnProtocols := msg.alpnProtocols
	if len(c.config.NextProtos) > 0 {
		ps := c.config.NextProtos
		alpnProtocols = slices.DeleteFunc(alpnProtocols, func(s string) bool {
			return !slices.Contains(ps, s)
		})
	}

	serverInfoCache := c.config.ServerInfoCache
	dstAddrStr := dstAddr.String()
	key := serverName
	if key == "" {
		key = dstAddrStr
	}

	si, ok := c.config.ServerInfoCache[key]
	if ok {
		protocol, ok := si.protocols.getFirst(alpnProtocols)
		if ok || (protocol == "" && len(alpnProtocols) == 0) {
			// skip handshake & negotiation
			return si.certificate, protocol, nil
		}
		if protocol == "" {
			// the server does not support any of alpnProtocols
			return si.certificate, "", fmt.Errorf("%w (serverName=%s, addr=%s)", ErrNoApplicationProtocol, serverName, dstAddr)
		}
		// we still need to negotiate the protocol
	} else {
		si = serverInfo{protocols: make(supportedProtocolMap)}
	}

	clientConfig := c.config.GetClientConfig(serverName, alpnProtocols)
	tc, err := tls.Dial(dstAddr.Network(), dstAddrStr, clientConfig)
	if err != nil {
		return nil, "", fmt.Errorf("%w (serverName=%v, addr=%v): %w", ErrHandshakeWithServer, serverName, dstAddr, err)
	}
	defer tc.Close()

	state := tc.ConnectionState()
	negotiatedProtocol := state.NegotiatedProtocol

	if si.certificate == nil {
		certs := state.PeerCertificates
		cert, err := ForgeCertificate(c.config.RootCertificate, certs[0])
		if err != nil {
			return nil, negotiatedProtocol, fmt.Errorf("mitm: failed to forge a certificate (serverName=%v, addr=%v): %w", serverName, dstAddr, err)
		}
		si.certificate = &cert
	}

	for _, p := range clientConfig.NextProtos {
		if p == negotiatedProtocol {
			break
		}
		si.protocols[p] = false
	}
	si.protocols[negotiatedProtocol] = true
	serverInfoCache[key] = si

	return si.certificate, negotiatedProtocol, nil
}

func (c *tlsConn) readClientHello(msg *clientHelloMsg) error {
	hdr, err := c.reader.Next(recordHeaderLen)
	if err != nil {
		return err
	}

	typ := recordType(hdr[0])
	ver := uint16(hdr[1])<<8 | uint16(hdr[2])

	if typ != recordTypeHandshake || ver > 0x1000 {
		return fmt.Errorf("unexpected record type: type=%v, ver=%v", typ, ver)
	}
	n := int(hdr[3])<<8 | int(hdr[4])

	fragment, err := c.reader.Next(n)
	if err != nil {
		return fmt.Errorf("failed to read the fragment: %w", err)
	}

	if !unmarshalClientHello(fragment, msg) {
		return errors.New("invalid ClientHello")
	}
	return nil
}
