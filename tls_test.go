// Copyright (c) 2024 homuler
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package mitm_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509/pkix"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/homuler/mitm-go"
	"github.com/homuler/mitm-go/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type tlsEchoServer struct {
	l  net.Listener
	tl net.Listener

	err error
}

func newTLSEchoServer(t *testing.T) *tlsEchoServer {
	l := testutil.NewTCPListener(t)
	return &tlsEchoServer{l: l}
}

func (s *tlsEchoServer) addr() net.Addr {
	return s.l.Addr()
}

func (s *tlsEchoServer) serverName() string {
	addr := s.addr().String()
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		panic(err)
	}
	return host
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

func setupServer(t *testing.T, mitmConfig *mitm.TLSConfig) (*tlsEchoServer, net.Listener) {
	t.Helper()

	// start a true server
	tlsServer := newTLSEchoServer(t)

	// start an MITM server
	l := testutil.NewTCPListener(t)
	mitmConfig.GetDestination = func(conn net.Conn, serverName string) net.Addr {
		return tlsServer.addr()
	}
	tl, err := mitm.NewTLSListener(l, mitmConfig)
	require.NoError(t, err, "failed to create an MITM listener")

	return tlsServer, tl
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
	assert.ErrorIs(t, err, mitm.ErrInvalidTLSConfig)
}

func TestNewTLSListner_dials_remote_server(t *testing.T) {
	t.Parallel()

	mitmCACert := testutil.MITMCACert(t)
	rootCAs := testutil.RootCAs(t)
	clientRootCAs := testutil.ClientRootCAs(t)

	getInvalidServerConfig := func(t *testing.T, _ *tlsEchoServer) *tls.Config {
		serverCert := testutil.MustIssueCertificate(t, pkix.Name{CommonName: "example.com"}, &net.IPAddr{})
		return &tls.Config{Certificates: []tls.Certificate{*serverCert}}
	}
	getValidServerConfig := func(t *testing.T, s *tlsEchoServer) *tls.Config {
		serverCert := testutil.MustIssueCertificate(t, pkix.Name{CommonName: "example.com"}, s.addr())
		return &tls.Config{Certificates: []tls.Certificate{*serverCert}, NextProtos: []string{"a", "b"}}
	}

	cases := []struct {
		name               string
		mitmListenerConfig *mitm.TLSConfig
		getServerConfig    func(*testing.T, *tlsEchoServer) *tls.Config
		nextProtos         []string
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
			mitmErr:         mitm.ErrHandshakeWithServer.Error(),
			clientErr:       "remote error: tls: internal error",
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
			mitmErr:         mitm.ErrHandshakeWithServer.Error(),
			clientErr:       "remote error: tls: internal error",
		},
		{
			name: "server certificate is invalid and client supports ALPN",
			mitmListenerConfig: &mitm.TLSConfig{
				RootCertificate: mitmCACert,
			},
			getServerConfig: getValidServerConfig,
			nextProtos:      []string{"a"},
			mitmErr:         mitm.ErrHandshakeWithServer.Error(),
			clientErr:       "remote error: tls: internal error",
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

			tlsServer, tl := setupServer(t, c.mitmListenerConfig)
			defer tlsServer.close()
			defer tl.Close()

			// start a true server
			serverConfig := c.getServerConfig(t, tlsServer)
			err := tlsServer.start(serverConfig)
			require.NoError(t, err, "failed to start a TLS echo server")

			// start an MITM server
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
				ServerName: tlsServer.serverName(),
				RootCAs:    clientRootCAs,
				NextProtos: c.nextProtos,
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

	mitmCACert := testutil.MITMCACert(t)
	rootCAs := testutil.RootCAs(t)
	clientRootCAs := testutil.ClientRootCAs(t)

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
			mitmErr:          mitm.ErrHandshakeWithServer.Error(),
			clientErr:        "remote error: tls: internal error",
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
		{
			name:             "server does not support ALPN",
			serverNextProtos: nil,
			mitmNextProtos:   []string{"a", "b"},
			clientNextProtos: []string{"a", "b"},
			expectedProto:    "",
		},
	}

	for _, c := range cases {
		c := c

		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			tlsServer, tl := setupServer(t, &mitm.TLSConfig{
				RootCertificate: mitmCACert,
				NextProtos:      c.mitmNextProtos,
				GetClientConfig: func(serverName string, alpnProtocols []string) *tls.Config {
					return &tls.Config{ServerName: serverName, RootCAs: rootCAs, NextProtos: alpnProtocols}
				},
			})
			defer tlsServer.close()
			defer tl.Close()

			// start a true server
			serverCert := testutil.MustIssueCertificate(t, pkix.Name{CommonName: "example.com"}, tlsServer.addr())

			err := tlsServer.start(&tls.Config{
				Certificates: []tls.Certificate{*serverCert},
				NextProtos:   c.serverNextProtos,
			})
			require.NoError(t, err, "failed to start a TLS echo server")

			// start an MITM server
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
				ServerName: tlsServer.serverName(),
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

	mitmCACert := testutil.MITMCACert(t)
	rootCAs := testutil.RootCAs(t)
	clientRootCAs := testutil.ClientRootCAs(t)

	tlsServer, tl := setupServer(t, &mitm.TLSConfig{
		RootCertificate: mitmCACert,
		GetClientConfig: func(serverName string, alpnProtocols []string) *tls.Config {
			return &tls.Config{ServerName: serverName, RootCAs: rootCAs, NextProtos: alpnProtocols}
		},
	})
	defer tlsServer.close()
	defer tl.Close()

	// start a true server
	serverCert := testutil.MustIssueCertificate(t, pkix.Name{CommonName: "example.com"}, tlsServer.addr())

	err := tlsServer.start(&tls.Config{
		Certificates: []tls.Certificate{*serverCert},
		NextProtos:   []string{"a", "b"},
	})
	require.NoError(t, err, "failed to start a TLS echo server")

	// start an MITM server
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
			name:          "client and server supports the same protocols",
			nextProtos:    []string{"a", "b"},
			expectedProto: "a",
		},
		{
			name:          "client and server supports the same protocols but the preference is different",
			nextProtos:    []string{"b", "a"},
			expectedProto: "a",
		},
		{
			name:          "client and server agree on the 2nd protocol",
			nextProtos:    []string{"c", "b"},
			expectedProto: "b",
		},
		{
			name:       "client and server fail to agree on the protocol",
			nextProtos: []string{"c"},
			mitmErr:    mitm.ErrHandshakeWithServer.Error(),
			clientErr:  "remote error: tls: internal error",
		},
		{
			name:          "client have requested the same nextProtos once (ok)",
			nextProtos:    []string{"c", "b"},
			expectedProto: "b",
		},
		{
			name:       "client have requested the same naxtProtos once (error)",
			nextProtos: []string{"c"},
			mitmErr:    mitm.ErrHandshakeWithServer.Error(),
			clientErr:  "remote error: tls: internal error",
		},
	}

	for _, c := range cases {
		c := c

		t.Run(c.name, func(t *testing.T) {
			clientConn, err := tls.Dial(mitmAddr.Network(), mitmAddr.String(), &tls.Config{
				ServerName: tlsServer.serverName(),
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

func TestNewTLSListner_can_read_messages_from_client(t *testing.T) {
	t.Parallel()

	mitmCACert := testutil.MITMCACert(t)
	rootCAs := testutil.RootCAs(t)
	clientRootCAs := testutil.ClientRootCAs(t)

	tlsServer, tl := setupServer(t, &mitm.TLSConfig{
		RootCertificate: mitmCACert,
		GetClientConfig: func(serverName string, alpnProtocols []string) *tls.Config {
			return &tls.Config{RootCAs: rootCAs}
		},
	})
	defer tlsServer.close()
	defer tl.Close()

	// start a true server
	serverCert := testutil.MustIssueCertificate(t, pkix.Name{CommonName: "example.com"}, tlsServer.addr())

	err := tlsServer.start(&tls.Config{
		Certificates: []tls.Certificate{*serverCert},
	})
	require.NoError(t, err, "failed to start a TLS echo server")

	// start an MITM server
	done := make(chan struct{})
	buf := bytes.NewBuffer(nil)

	go func() {
		// only serve the first connection
		conn, err := tl.Accept()
		if !assert.NoError(t, err, "unexpected listener error") {
			return
		}
		defer conn.Close()

		_, err = io.Copy(buf, conn)
		assert.NoError(t, err)

		close(done)
	}()

	mitmAddr := tl.Addr()

	clientConn, err := tls.Dial(mitmAddr.Network(), mitmAddr.String(), &tls.Config{
		ServerName: tlsServer.serverName(),
		RootCAs:    clientRootCAs,
	})
	require.NoError(t, err, "failed to dial the MITM server")

	msg := "hello, world\n"
	_, err = clientConn.Write([]byte(msg))
	require.NoError(t, err, "failed to send a message to the MITM server")

	clientConn.Close()

	<-done

	assert.Equal(t, msg, buf.String(), "MITM server received an unexpected message")
}

func TestNewTLSListner_can_serve_if_client_does_not_support_SNI(t *testing.T) {
	t.Parallel()

	mitmCACert := testutil.MITMCACert(t)
	rootCAs := testutil.RootCAs(t)
	clientRootCAs := testutil.ClientRootCAs(t)

	// start a true server
	tlsServer := newTLSEchoServer(t)

	serverCert := testutil.MustIssueCertificate(t, pkix.Name{CommonName: "example.com"}, tlsServer.addr())

	err := tlsServer.start(&tls.Config{
		Certificates: []tls.Certificate{*serverCert},
	})
	require.NoError(t, err, "failed to start a TLS echo server")
	defer tlsServer.close()

	// start an MITM server
	l := testutil.NewTCPListener(t)
	tl, err := mitm.NewTLSListener(l, &mitm.TLSConfig{
		RootCertificate: mitmCACert,
		GetDestination: func(conn net.Conn, serverName string) net.Addr {
			return tlsServer.addr()
		},
		GetClientConfig: func(serverName string, alpnProtocols []string) *tls.Config {
			return &tls.Config{RootCAs: rootCAs}
		},
	})
	require.NoError(t, err, "failed to create an MITM listener")
	defer tl.Close()

	done := make(chan struct{})
	buf := bytes.NewBuffer(nil)

	go func() {
		// only serve the first connection
		conn, err := tl.Accept()
		if !assert.NoError(t, err, "unexpected listener error") {
			return
		}
		defer conn.Close()

		_, err = io.Copy(buf, conn)
		assert.NoError(t, err)

		close(done)
	}()

	mitmAddr := tl.Addr()

	clientConn, err := tls.Dial(mitmAddr.Network(), mitmAddr.String(), &tls.Config{
		RootCAs: clientRootCAs,
	})
	require.NoError(t, err, "failed to dial the MITM server")

	msg := "hello, world\n"
	_, err = clientConn.Write([]byte(msg))
	require.NoError(t, err, "failed to send a message to the MITM server")

	clientConn.Close()

	<-done

	assert.Equal(t, msg, buf.String(), "MITM server received an unexpected message")
}

func TestNewTLSListner_can_handle_invalid_client(t *testing.T) {
	t.Parallel()

	mitmCACert := testutil.MITMCACert(t)
	rootCAs := testutil.RootCAs(t)

	tlsServer, tl := setupServer(t, &mitm.TLSConfig{
		RootCertificate: mitmCACert,
		GetClientConfig: func(serverName string, alpnProtocols []string) *tls.Config {
			return &tls.Config{ServerName: serverName, RootCAs: rootCAs}
		},
	})
	defer tlsServer.close()
	defer tl.Close()

	// start a true server
	serverCert := testutil.MustIssueCertificate(t, pkix.Name{CommonName: "example.com"}, tlsServer.addr())

	err := tlsServer.start(&tls.Config{
		Certificates: []tls.Certificate{*serverCert},
	})
	require.NoError(t, err, "failed to start a TLS echo server")

	// start an MITM server
	done := make(chan struct{})

	go func() {
		// only serve the first connection
		conn, err := tl.Accept()
		if !assert.NoError(t, err, "unexpected listener error") {
			return
		}
		defer conn.Close()

		_, err = io.Copy(io.Discard, conn)
		assertTLSError(t, err, "tls: first record does not look like a TLS handshake")

		close(done)
	}()

	mitmAddr := tl.Addr()

	clientConn, err := net.Dial(mitmAddr.Network(), mitmAddr.String())
	require.NoError(t, err, "failed to dial the MITM server")
	defer clientConn.Close()

	_, err = clientConn.Write([]byte("hello, world\n"))
	assert.NoError(t, err, "failed to write to the MITM server")

	<-done
}

func TestNewTLSServer_fails_if_the_root_certificate_is_missing(t *testing.T) {
	t.Parallel()

	_, err := mitm.NewTLSServer(nil, &mitm.TLSConfig{})
	assert.ErrorIs(t, err, mitm.ErrInvalidTLSConfig)
}
