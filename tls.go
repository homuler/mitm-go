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

func (c *TLSConfig) Normalize() *TLSConfig {
	c = c.Clone()

	if c.GetDestination == nil {
		c.GetDestination = defaultGetDestination
	}
	if c.GetServerConfig == nil {
		c.GetServerConfig = defaultGetServerConfig
	}
	if c.GetClientConfig == nil {
		c.GetClientConfig = defaultGetClientConfig
	}
	return c
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

var defaultGetServerConfig = func(certificate *tls.Certificate, negotiatedProtocol string) *tls.Config {
	config := &tls.Config{
		// if negotiatedProtocol is empty, the handshake will success only if the client does not send ALPN.
		NextProtos: []string{negotiatedProtocol},
	}

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
		config:   config.Normalize(),

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
		// TODO: log the error
		fmt.Printf("MITM %v\n", err)
	}
	return tlsConn, nil
}

func (tl *tlsListener) Close() error   { return tl.listener.Close() }
func (tl *tlsListener) Addr() net.Addr { return tl.listener.Addr() }

var (
	ErrPeekClientHello     = errors.New("failed to peek client hello")
	errHandshakeWithServer = errors.New("failed to handshake with the true server")
	errForgeCertificate    = errors.New("failed to forge a certificate")
)

type tlsConn struct {
	conn net.Conn

	reader *memorizingReader
	config *TLSConfig
}

func NewTLSServer(conn net.Conn, config *TLSConfig, serverInfoCache ServerInfoCache) (*tls.Conn, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}

	return newTLSServer(conn, config.Normalize(), serverInfoCache)
}

// newTLSServer returns a TLS server connection and the error that occurred while forging a certificate if any.
// tls.Conn is always returned even if an error occurred.
func newTLSServer(conn net.Conn, config *TLSConfig, serverInfoCache ServerInfoCache) (*tls.Conn, error) {
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
		// let tls.Server to handle the error
		c := NewTamperedConn(tlsConn.conn,
			TamperConnRead(tlsConn.reader.OneTimeReader().Read),
			TamperConnClose(closeTLSConn))
		return tls.Server(c, nil), err
	}

	dstAddr := config.GetDestination(conn, clientHello.serverName)
	proxyConn := NewProxyConn(tlsConn.conn, dstAddr,
		TamperConnRead(tlsConn.reader.OneTimeReader().Read),
		TamperConnClose(closeTLSConn))

	cert, protocol, err := tlsConn.handshakeWithServer(dstAddr, clientHello, serverInfoCache)
	serverConfig := tlsConn.config.GetServerConfig(cert, protocol)
	// let tls.Server to handle the error
	return tls.Server(proxyConn, serverConfig), err
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
		if ok || (protocol == "" && len(alpnProtocols) == 0) {
			// skip handshake & negotiation
			return si.certificate, protocol, nil
		}
		if protocol == "" {
			// the server does not support any of alpnProtocols
			return si.certificate, "", fmt.Errorf("no application protocol (serverName=%s, addr=%s)", serverName, dstAddr)
		}
		// we still need to negotiate the protocol
	} else {
		si = serverInfo{protocols: make(supportedProtocolMap)}
	}

	clientConfig := c.config.GetClientConfig(serverName, alpnProtocols)
	tc, err := tls.Dial(dstAddr.Network(), dstAddr.String(), clientConfig)
	if err != nil {
		return si.certificate, "", fmt.Errorf("%w (serverName=%v, addr=%v): %w", errHandshakeWithServer, serverName, dstAddr, err)
	}
	state := tc.ConnectionState()
	negotiatedProtocol := state.NegotiatedProtocol

	if si.certificate == nil {
		certs := state.PeerCertificates
		cert, err := ForgeCertificate(c.config.RootCertificate, certs[0])
		if err != nil {
			return nil, negotiatedProtocol, fmt.Errorf("%s (serverName=%v, addr=%v): %w", errForgeCertificate, serverName, dstAddr, err)
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
	serverInfoCache[serverName] = si

	return si.certificate, negotiatedProtocol, nil
}

var (
	errInvalidClientHello = errors.New("invalid ClientHello")
)

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
		return errInvalidClientHello
	}
	return nil
}
