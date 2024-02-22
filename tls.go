package mitm

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"time"
)

type readTamperedConn struct {
	conn net.Conn

	reader io.Reader
}

var _ net.Conn = (*readTamperedConn)(nil)

func (c *readTamperedConn) Read(b []byte) (int, error)         { return c.reader.Read(b) }
func (c *readTamperedConn) Write(b []byte) (int, error)        { return c.conn.Write(b) }
func (c *readTamperedConn) Close() error                       { return c.conn.Close() }
func (c *readTamperedConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *readTamperedConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *readTamperedConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *readTamperedConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *readTamperedConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

var (
	ErrPeekClientHello     = errors.New("failed to peek client hello")
	ErrHandshakeWithServer = errors.New("failed to handshake with the server")
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

type TLSListenerConfig struct {
	// NextProtos is a list of supported ALPN protocols.
	// If it is empty, the client specified list is used to negotiate the protocol with the actual server.
	NextProtos []string

	// GetServerConfig optionally specifies a function that returns a tls.Config that is used to handle incoming connections.
	GetServerConfig func(certificate *tls.Certificate, negotiatedProtocol string) *tls.Config

	// GetClientConfig optionally specifies a function that returns a tls.Config that is used to dial the actual server.
	GetClientConfig func(serverName string, alpnProtocols []string) *tls.Config
}

type serverInfo struct {
	certificate *tls.Certificate

	protocols supportedProtocolMap // TODO: clear it periodically
}

type tlsListener struct {
	listener net.Listener
	config   *TLSListenerConfig

	serverInfoCache map[string]serverInfo
}

var _ net.Listener = (*tlsListener)(nil)

// NewTLSListener returns a new net.Listener that listens for incoming TLS connections on l.
func NewTLSListener(l net.Listener, config *TLSListenerConfig) net.Listener {
	return &tlsListener{
		listener: l,
		config:   config,

		serverInfoCache: make(map[string]serverInfo),
	}
}

func (tl *tlsListener) Accept() (net.Conn, error) {
	c, err := tl.listener.Accept()
	if err != nil {
		return nil, err
	}

	pr := NewPeekReader(c, make([]byte, 1024))
	clientHello := &clientHelloMsg{}
	err = peekClientHello(pr, clientHello)
	if err != nil {
		err = errors.Join(err, c.Close())
		return nil, fmt.Errorf("%w: %w", ErrPeekClientHello, err)
	}

	cert, protocol, err := tl.handshakeWithServer(c, clientHello)
	if err != nil {
		err = errors.Join(err, c.Close())
		return nil, fmt.Errorf("%w: %w", ErrHandshakeWithServer, err)
	}

	var serverConfig *tls.Config
	if tl.config.GetServerConfig != nil {
		serverConfig = tl.config.GetServerConfig(cert, protocol)
	} else {
		serverConfig = &tls.Config{
			Certificates: []tls.Certificate{*cert},
			NextProtos:   []string{protocol},
		}
	}

	return tls.Server(&readTamperedConn{conn: c, reader: pr}, serverConfig), nil
}

// handshakeWithServer returns a certificate of the server and the negotiated protocol.
func (tl *tlsListener) handshakeWithServer(conn net.Conn, msg *clientHelloMsg) (*tls.Certificate, string, error) {
	serverName := msg.serverName
	alpnProtocols := msg.alpnProtocols
	if len(tl.config.NextProtos) > 0 {
		ps := tl.config.NextProtos
		alpnProtocols = slices.DeleteFunc(alpnProtocols, func(s string) bool {
			return !slices.Contains(ps, s)
		})
	}

	si, ok := tl.serverInfoCache[serverName]
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

	addr := conn.LocalAddr()
	var clientConfig *tls.Config
	if tl.config.GetClientConfig != nil {
		clientConfig = tl.config.GetClientConfig(serverName, alpnProtocols)
	} else {
		clientConfig = &tls.Config{
			ServerName: serverName,
			NextProtos: alpnProtocols,
		}
	}

	tc, err := tls.Dial("tcp", addr.String(), clientConfig)
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
		cert, err := ForgeCertificate(certs[0])
		if err != nil {
			return nil, "", fmt.Errorf("failed to forge a certificate of %v(%v): %w", serverName, addr, err)
		}
		si.certificate = cert
	}

	negotiatedProtocol := state.NegotiatedProtocol
	for _, p := range clientConfig.NextProtos {
		if p == negotiatedProtocol {
			break
		}
		si.protocols[p] = false
	}
	si.protocols[negotiatedProtocol] = true
	tl.serverInfoCache[serverName] = si

	return si.certificate, state.NegotiatedProtocol, nil
}

func (tl *tlsListener) Close() error   { return tl.listener.Close() }
func (tl *tlsListener) Addr() net.Addr { return tl.listener.Addr() }

const (
	recordHeaderLen     = 5
	recordTypeHandshake = 22
)

var (
	errUnexpectedRecordType = errors.New("unexpected record type")
	errInvalidClientHello   = errors.New("invalid ClientHello")
)

func peekClientHello(conn PeekReader, msg *clientHelloMsg) error {
	hdr, err := conn.Peek(recordHeaderLen)
	if err != nil {
		return err
	}

	typ := uint8(hdr[0])
	ver := uint16(hdr[1])<<8 | uint16(hdr[2])

	if typ != recordTypeHandshake || ver > 0x1000 {
		return fmt.Errorf("%w: type=%v, ver=%v", errUnexpectedRecordType, typ, ver)
	}
	n := int(hdr[3])<<8 | int(hdr[4])

	fragment, err := conn.Peek(n)
	if err != nil {
		return fmt.Errorf("failed to read the fragment: %w", err)
	}

	if !unmarshalClientHello(fragment, msg) {
		return errInvalidClientHello
	}
	return nil
}
