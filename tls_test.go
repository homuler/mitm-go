package mitm_test

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/homuler/mitm-proxy-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type tlsEchoServer struct {
	l  net.Listener
	tl net.Listener

	err error
}

func newTLSEchoServer(cn string) (*tlsEchoServer, error) {
	l, err := net.ListenTCP("tcp", &net.TCPAddr{})
	if err != nil {
		return nil, err
	}
	return &tlsEchoServer{l: l}, nil
}

func (s *tlsEchoServer) addr() string {
	return s.l.Addr().String()
}

func (s *tlsEchoServer) close() error {
	if s.tl != nil {
		return s.tl.Close()
	}
	return s.l.Close()
}

func (s *tlsEchoServer) start(config *tls.Config) error {
	if s.tl != nil {
		return errors.New("already started")
	}
	s.tl = tls.NewListener(s.l, config)

	go func() {
		var lerr error
		for {
			conn, err := s.tl.Accept()
			if err != nil {
				lerr = err
				break
			}

			go func() {
				_, err := io.Copy(conn, conn)
				if err != nil {
					s.err = errors.Join(s.err, err)
				}
			}()
		}

		s.err = errors.Join(lerr, s.tl.Close())
	}()

	return nil
}

func issueCertificate(subject pkix.Name, dnsNames []string) (*tls.Certificate, error) {
	cert, err := mitm.ForgeCertificate(rootCACert, &x509.Certificate{
		Subject:   subject,
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(1 * time.Hour),
		DNSNames:  dnsNames,
	})
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func assertTLSError(t *testing.T, err error, expected string) bool {
	t.Helper()

	if expected == "" {
		return assert.NoError(t, err)
	} else {
		return assert.ErrorContains(t, err, expected)
	}
}

func TestNewTLSListener_fails_if_the_root_certificate_is_missing(t *testing.T) {
	t.Parallel()

	_, err := mitm.NewTLSListener(nil, &mitm.TLSConfig{})
	assert.ErrorIs(t, err, mitm.ErrMissingRootCertificate)
}

func TestNewTLSListner_dials_remote_server(t *testing.T) {
	t.Parallel()

	if rootCACert == nil {
		t.Fatal("rootCACert is not initialized")
	}

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(rootCACert.Leaf)

	clientRootCAs := x509.NewCertPool()
	clientRootCAs.AddCert(mitmCACert.Leaf)

	getInvalidServerConfig := func(t *testing.T, _ *tlsEchoServer) *tls.Config {
		serverCert, err := issueCertificate(pkix.Name{CommonName: "example.com"}, nil)
		require.NoError(t, err, "failed to issue the server certificate")

		return &tls.Config{Certificates: []tls.Certificate{*serverCert}}
	}
	getValidServerConfig := func(t *testing.T, s *tlsEchoServer) *tls.Config {
		serverCert, err := issueCertificate(pkix.Name{CommonName: "example.com"}, []string{s.addr()})
		require.NoError(t, err, "failed to issue the server certificate")

		return &tls.Config{Certificates: []tls.Certificate{*serverCert}}
	}

	cases := []struct {
		name               string
		mitmListenerConfig *mitm.TLSConfig
		getServerConfig    func(*testing.T, *tlsEchoServer) *tls.Config
		mitmErr            string
		clientErr          string
	}{
		{
			name: "server certificate is not valid for any names",
			mitmListenerConfig: &mitm.TLSConfig{
				RootCertificate: mitmCACert,
				GetClientConfig: func(serverName string, _ []string) *tls.Config {
					return &tls.Config{ServerName: serverName, RootCAs: rootCAs}
				},
			},
			getServerConfig: getInvalidServerConfig,
			mitmErr:         "tls: no certificates configured",
			clientErr:       "remote error: tls:",
		},
		{
			name: "server certificate is not valid but the validation is skipped",
			mitmListenerConfig: &mitm.TLSConfig{
				RootCertificate: mitmCACert,
				GetClientConfig: func(serverName string, _ []string) *tls.Config {
					return &tls.Config{ServerName: serverName, InsecureSkipVerify: true}
				},
			},
			getServerConfig: getInvalidServerConfig,
			mitmErr:         "remote error: tls: bad certificate",
			clientErr:       "tls: failed to verify certificate",
		},
		{
			name: "server certificate is signed by unknown authority",
			mitmListenerConfig: &mitm.TLSConfig{
				RootCertificate: mitmCACert,
			},
			getServerConfig: getValidServerConfig,
			mitmErr:         "tls: no certificates configured",
			clientErr:       "remote error: tls:",
		},
		{
			name: "server certificate is valid",
			mitmListenerConfig: &mitm.TLSConfig{
				RootCertificate: mitmCACert,
				GetClientConfig: func(serverName string, _ []string) *tls.Config {
					return &tls.Config{ServerName: serverName, RootCAs: rootCAs}
				},
			},
			getServerConfig: getValidServerConfig,
		},
	}

	for _, c := range cases {
		c := c

		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			// start a true server
			tlsServer, err := newTLSEchoServer("example.com")
			require.NoError(t, err, "failed to create a TLS echo server")

			serverConfig := c.getServerConfig(t, tlsServer)
			err = tlsServer.start(serverConfig)
			require.NoError(t, err, "failed to start a TLS echo server")
			defer tlsServer.close()

			// start an MITM server
			l, err := net.ListenTCP("tcp", &net.TCPAddr{})
			require.NoError(t, err, "failed to create an MITM server")

			tl, err := mitm.NewTLSListener(l, c.mitmListenerConfig)
			require.NoError(t, err, "failed to create an MITM listener")
			defer tl.Close()

			done := make(chan struct{})

			go func() {
				// only serve the first connection
				conn, err := tl.Accept()
				if !assert.NoErrorf(t, err, "unexpected listener error") {
					return
				}
				defer conn.Close()

				_, err = io.Copy(io.Discard, conn)
				assertTLSError(t, err, c.mitmErr)
				close(done)
			}()

			// a client dials the MITM server
			mitmAddr := tl.Addr()

			clientConn, err := tls.Dial(mitmAddr.Network(), mitmAddr.String(), &tls.Config{
				ServerName: tlsServer.addr(),
				RootCAs:    clientRootCAs,
			})
			assertTLSError(t, err, c.clientErr)
			if clientConn != nil {
				clientConn.Close()
			}
			<-done
		})
	}
}

func TestNewTLSListner_supports_ALPN(t *testing.T) {
	t.Parallel()

	if rootCACert == nil {
		t.Fatal("rootCACert is not initialized")
	}

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(rootCACert.Leaf)

	clientRootCAs := x509.NewCertPool()
	clientRootCAs.AddCert(mitmCACert.Leaf)

	cases := []struct {
		name             string
		serverNextProtos []string
		mitmNextProtos   []string
		clientNextProtos []string
		expectedProto    string
		mitmErr          string
		clientErr        string
	}{
		{
			name:           "server & client does not support ALPN",
			mitmNextProtos: []string{"a", "b", "c", "d"},
			expectedProto:  "",
		},
		{
			name:             "server rejects all",
			serverNextProtos: []string{"c"},
			clientNextProtos: []string{"a", "b"},
			expectedProto:    "",
			mitmErr:          "tls: client requested unsupported application protocols",
			clientErr:        "remote error: tls: no application protocol",
		},
		{
			name:             "server accepts the 2nd",
			serverNextProtos: []string{"b", "c"},
			clientNextProtos: []string{"a", "b"},
			expectedProto:    "b",
		},
		{
			name:             "server accepts the first",
			serverNextProtos: []string{"a", "b"},
			clientNextProtos: []string{"a", "b"},
			expectedProto:    "a",
		},
		{
			name:             "MITM server rejects the first",
			serverNextProtos: []string{"a", "b"},
			mitmNextProtos:   []string{"b"},
			clientNextProtos: []string{"a", "b"},
			expectedProto:    "b",
		},
		{
			name:             "client does not support ALPN",
			serverNextProtos: []string{"a", "b"},
			expectedProto:    "",
		},
	}

	for _, c := range cases {
		c := c

		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			// start a true server
			tlsServer, err := newTLSEchoServer("example.com")
			require.NoError(t, err, "failed to create a TLS echo server")

			serverCert, err := issueCertificate(pkix.Name{CommonName: "example.com"}, []string{tlsServer.addr()})
			require.NoError(t, err, "failed to issue the server certificate")

			err = tlsServer.start(&tls.Config{
				Certificates: []tls.Certificate{*serverCert},
				NextProtos:   c.serverNextProtos,
			})
			require.NoError(t, err, "failed to start a TLS echo server")
			defer tlsServer.close()

			// start an MITM server
			l, err := net.ListenTCP("tcp", &net.TCPAddr{})
			require.NoError(t, err, "failed to create an MITM server")

			tl, err := mitm.NewTLSListener(l, &mitm.TLSConfig{
				RootCertificate: mitmCACert,
				NextProtos:      c.mitmNextProtos,
				GetClientConfig: func(serverName string, alpnProtocols []string) *tls.Config {
					return &tls.Config{ServerName: serverName, RootCAs: rootCAs, NextProtos: alpnProtocols}
				},
			})
			require.NoError(t, err, "failed to create an MITM listener")
			defer tl.Close()

			done := make(chan struct{})

			go func() {
				// only serve the first connection
				conn, err := tl.Accept()
				if !assert.NoError(t, err, "unexpected listener error") {
					return
				}
				defer conn.Close()

				_, err = io.Copy(io.Discard, conn)
				assertTLSError(t, err, c.mitmErr)

				close(done)
			}()

			// a client dials the MITM server
			mitmAddr := tl.Addr()

			clientConn, err := tls.Dial(mitmAddr.Network(), mitmAddr.String(), &tls.Config{
				ServerName: tlsServer.addr(),
				RootCAs:    clientRootCAs,
				NextProtos: c.clientNextProtos,
			})
			assertTLSError(t, err, c.clientErr)
			if clientConn == nil {
				assert.Emptyf(t, c.expectedProto, "expected proto %s, but client connection is nil", c.expectedProto)
			} else {
				assert.Equalf(t, c.expectedProto, clientConn.ConnectionState().NegotiatedProtocol, "unexpected negotiated protocol")
				clientConn.Close()
			}

			<-done
		})
	}
}

func TestNewTLSListner_can_serve_different_protocols(t *testing.T) {
	t.Parallel()

	if rootCACert == nil {
		t.Fatal("rootCACert is not initialized")
	}

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(rootCACert.Leaf)

	clientRootCAs := x509.NewCertPool()
	clientRootCAs.AddCert(mitmCACert.Leaf)

	// start a true server
	tlsServer, err := newTLSEchoServer("example.com")
	require.NoError(t, err, "failed to create a TLS echo server")

	serverCert, err := issueCertificate(pkix.Name{CommonName: "example.com"}, []string{tlsServer.addr()})
	require.NoError(t, err, "failed to issue the server certificate")

	err = tlsServer.start(&tls.Config{
		Certificates: []tls.Certificate{*serverCert},
		NextProtos:   []string{"a", "b"},
	})
	require.NoError(t, err, "failed to start a TLS echo server")
	defer tlsServer.close()

	// start an MITM server
	l, err := net.ListenTCP("tcp", &net.TCPAddr{})
	require.NoError(t, err, "failed to create an MITM server")

	tl, err := mitm.NewTLSListener(l, &mitm.TLSConfig{
		RootCertificate: mitmCACert,
		GetClientConfig: func(serverName string, alpnProtocols []string) *tls.Config {
			return &tls.Config{ServerName: serverName, RootCAs: rootCAs, NextProtos: alpnProtocols}
		},
	})
	require.NoError(t, err, "failed to create an MITM listener")
	defer tl.Close()

	errs := make(chan error)

	go func() {
		for {
			conn, err := tl.Accept()
			if err != nil {
				break
			}
			defer conn.Close()

			go func() {
				_, err := io.Copy(io.Discard, conn)
				errs <- err
			}()
		}
	}()

	// multiple client dials the MITM server
	mitmAddr := tl.Addr()

	cases := []struct {
		name          string
		nextProtos    []string
		expectedProto string
		mitmErr       string
		clientErr     string
	}{
		{
			name:          "client does not support ALPN",
			expectedProto: "",
		},
		{
			name:          "client and server agree on the 1st protocol",
			nextProtos:    []string{"a", "b"},
			expectedProto: "a",
		},
		{
			name:          "client and server agree on the 2nd protocol",
			nextProtos:    []string{"c", "b"},
			expectedProto: "b",
		},
		{
			name:          "MITM server knows the server supports the 1st protocol",
			nextProtos:    []string{"a", "c"},
			expectedProto: "a",
		},
		{
			name:          "MITM server knows the server supports the 2nd protocol",
			nextProtos:    []string{"c", "a"},
			expectedProto: "a",
		},
		{
			name:       "MITM server knows the server doesn't support all the requested protocols",
			nextProtos: []string{"c"},
			mitmErr:    "tls: client requested unsupported application protocols",
			clientErr:  "remote error: tls: no application protocol",
		},
	}

	for _, c := range cases {
		c := c

		t.Run(c.name, func(t *testing.T) {
			clientConn, err := tls.Dial(mitmAddr.Network(), mitmAddr.String(), &tls.Config{
				ServerName: tlsServer.addr(),
				RootCAs:    clientRootCAs,
				NextProtos: c.nextProtos,
			})
			assertTLSError(t, err, c.clientErr)
			if clientConn == nil {
				assert.Emptyf(t, c.expectedProto, "expected proto %s, but client connection is nil", c.expectedProto)
			} else {
				assert.Equalf(t, c.expectedProto, clientConn.ConnectionState().NegotiatedProtocol, "unexpected negotiated protocol")
				clientConn.Close()
			}

			err = <-errs
			assertTLSError(t, err, c.mitmErr)
		})
	}
}

func TestNewTLSListner_can_handle_invalid_client(t *testing.T) {
	t.Parallel()

	if rootCACert == nil {
		t.Fatal("rootCACert is not initialized")
	}

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(rootCACert.Leaf)

	clientRootCAs := x509.NewCertPool()
	clientRootCAs.AddCert(mitmCACert.Leaf)

	// start a true server
	tlsServer, err := newTLSEchoServer("example.com")
	require.NoError(t, err, "failed to create a TLS echo server")

	// serverCert, err := issueCertificate(pkix.Name{CommonName: "example.com"}, []string{tlsServer.addr()})
	require.NoError(t, err, "failed to issue the server certificate")

	err = tlsServer.start(nil)
	//&tls.Config{
	// Certificates: []tls.Certificate{*serverCert},
	//})
	require.NoError(t, err, "failed to start a TLS echo server")
	defer tlsServer.close()

	// start an MITM server
	l, err := net.ListenTCP("tcp", &net.TCPAddr{})
	require.NoError(t, err, "failed to create an MITM server")

	tl, err := mitm.NewTLSListener(l, &mitm.TLSConfig{
		RootCertificate: mitmCACert,
		GetClientConfig: func(serverName string, alpnProtocols []string) *tls.Config {
			return &tls.Config{ServerName: serverName, RootCAs: rootCAs}
		},
	})
	require.NoError(t, err, "failed to create an MITM listener")
	defer tl.Close()

	go func() {
		// only serve the first connection
		conn, err := tl.Accept()
		if !assert.NoError(t, err, "unexpected listener error") {
			return
		}
		defer conn.Close()

		_, err = io.Copy(io.Discard, conn)
		assertTLSError(t, err, "tls: first record does not look like a TLS handshake")
		conn.Close()
	}()

	mitmAddr := tl.Addr()

	clientConn, err := net.Dial(mitmAddr.Network(), mitmAddr.String())
	require.NoError(t, err, "failed to dial the MITM server")
	defer clientConn.Close()

	_, err = clientConn.Write([]byte("hello, world\n"))
	assert.NoError(t, err, "failed to write to the MITM server")

	_, err = io.ReadAll(clientConn)
	assert.ErrorContains(t, err, "read: connection reset by peer")
}
