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

	// NextProtos is a list of supported ALPN protocols.
	// If it is empty, the client specified list is used to negotiate the protocol with the actual server.
	NextProtos []string

	// GetServerConfig optionally specifies a function that returns a tls.Config that is used to handle incoming connections.
	GetServerConfig func(certificate *tls.Certificate, negotiatedProtocol string) *tls.Config

	// GetClientConfig optionally specifies a function that returns a tls.Config that is used to dial the actual server.
	GetClientConfig func(serverName string, alpnProtocols []string) *tls.Config
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

// NewTLSListener returns a new net.Listener that listens for incoming TLS connections on l.
func NewTLSListener(l net.Listener, config *TLSConfig) net.Listener {
	return &tlsListener{
		listener: l,
		config:   config,

		serverInfoCache: make(ServerInfoCache),
	}
}

func (tl *tlsListener) Accept() (net.Conn, error) {
	c, err := tl.listener.Accept()
	if err != nil {
		return nil, err
	}

	return NewTLSServerConn(c, c.LocalAddr().String(), tl.config, tl.serverInfoCache)
}

func (tl *tlsListener) Close() error   { return tl.listener.Close() }
func (tl *tlsListener) Addr() net.Addr { return tl.listener.Addr() }

var (
	ErrMissingRootCertificate = errors.New("config.RootCertificate is required")

	ErrPeekClientHello     = errors.New("failed to peek client hello")
	ErrHandshakeWithServer = errors.New("failed to handshake with the server")
)

type tlsConn struct {
	conn    net.Conn
	dstAddr string
	reader  *memorizingReader
	config  *TLSConfig
}

func NewTLSServerConn(conn net.Conn, dstAddr string, config *TLSConfig, serverInfoCache ServerInfoCache) (*tls.Conn, error) {
	if config.RootCertificate == nil {
		return nil, ErrMissingRootCertificate
	}

	bufPtr := defaultBufferPool.Get().(*[]byte)
	c := newTlsConn(conn, dstAddr, config, (*bufPtr)[0:0])
	clientHello := &clientHelloMsg{}

	err := peekClientHello(c.reader, clientHello)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPeekClientHello, err)
	}

	cert, protocol, err := c.handshakeWithServer(clientHello, serverInfoCache)
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

func newTlsConn(conn net.Conn, dstAddr string, config *TLSConfig, buffer []byte) *tlsConn {
	return &tlsConn{
		conn:    conn,
		dstAddr: dstAddr,
		reader:  NewMemorizingReader(conn, buffer),
		config:  config,
	}
}

// handshakeWithServer returns a certificate of the server and the negotiated protocol.
// serverInfoCache will be updated with the result.
func (c *tlsConn) handshakeWithServer(msg *clientHelloMsg, serverInfoCache ServerInfoCache) (*tls.Certificate, string, error) {
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

	addr := c.dstAddr
	tc, err := tls.Dial("tcp", addr, clientConfig)
	if err != nil {
		return nil, "", fmt.Errorf("failed to dial to %v(%v): %w", serverName, addr, err)
	}

	if err := tc.Handshake(); err != nil {
		return nil, "", fmt.Errorf("failed to handshake with %v(%v): %w", serverName, addr, err)
	}

	state := tc.ConnectionState()

	if si.certificate == nil {
		certs := state.PeerCertificates
		if len(certs) == 0 {
			// it should not occur.
			return nil, "", fmt.Errorf("no certificates of %v(%v) found", serverName, addr)
		}
		cert, err := ForgeCertificate(c.config.RootCertificate, certs[0])
		if err != nil {
			return nil, "", fmt.Errorf("failed to forge a certificate of %v(%v): %w", serverName, addr, err)
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

const (
	recordHeaderLen     = 5
	recordTypeHandshake = 22
)

var (
	errUnexpectedRecordType = errors.New("unexpected record type")
	errInvalidClientHello   = errors.New("invalid ClientHello")
)

func peekClientHello(r *memorizingReader, msg *clientHelloMsg) error {
	hdr, err := r.Next(recordHeaderLen)
	if err != nil {
		return err
	}

	typ := uint8(hdr[0])
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
