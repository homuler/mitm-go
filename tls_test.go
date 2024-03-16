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
				io.Copy(conn, conn)
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
		err                error
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
			err:             mitm.ErrHandshakeWithServer,
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
			err:             nil,
		},
		{
			name: "server certificate is signed by unknown authority",
			mitmListenerConfig: &mitm.TLSConfig{
				RootCertificate: mitmCACert,
			},
			getServerConfig: getValidServerConfig,
			err:             mitm.ErrHandshakeWithServer,
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
			err:             nil,
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

			go func() {
				// only serve the first connection
				conn, err := tl.Accept()
				defer tl.Close()

				assert.ErrorIs(t, err, c.err, "unexpected MITM error")

				if err == nil {
					io.Copy(io.Discard, conn)
					conn.Close()
				}
			}()

			// a client dials the MITM server
			mitmAddr := tl.Addr()

			clientConn, err := tls.Dial(mitmAddr.Network(), mitmAddr.String(), &tls.Config{
				ServerName: tlsServer.addr(),
				RootCAs:    clientRootCAs,
			})

			// when err != nil, it's caused by the server and is already checked in the goroutine, so we ignore it here.
			if err == nil {
				clientConn.Close()
			}
			// NOTE: handshake is already done, so we don't need to wait the goroutine to finish
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
		err              error
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
			err:              mitm.ErrHandshakeWithServer,
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

			go func() {
				// only serve the first connection
				conn, err := tl.Accept()
				defer tl.Close()

				assert.ErrorIsf(t, err, c.err, "unexpected MITM error")

				if err == nil {
					io.Copy(io.Discard, conn)
					conn.Close()
				}
			}()

			// a client dials the MITM server
			mitmAddr := tl.Addr()

			clientConn, err := tls.Dial(mitmAddr.Network(), mitmAddr.String(), &tls.Config{
				ServerName: tlsServer.addr(),
				RootCAs:    clientRootCAs,
				NextProtos: c.clientNextProtos,
			})
			if err != nil {
				assert.NotNilf(t, c.err, "unexpected client error: %v", err)
				return
			}
			defer clientConn.Close()

			assert.Equalf(t, c.expectedProto, clientConn.ConnectionState().NegotiatedProtocol, "unexpected negotiated protocol")
		})
	}
}
