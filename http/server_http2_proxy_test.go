// Copyright (c) 2024 homuler
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

//go:build curl_proxy_http2

package http_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"testing"

	mitmHttp "github.com/homuler/mitm-go/http"
	"github.com/homuler/mitm-go/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

func createTempCertPEM(t *testing.T, cert *tls.Certificate, name string) *os.File {
	t.Helper()

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Certificate[0],
	})

	f, err := os.CreateTemp("", name)
	require.NoErrorf(t, err, "failed to create a temp PEM file")

	_, err = f.Write(certPEM.Bytes())
	require.NoErrorf(t, err, "failed to write the cert PEM")

	return f
}

func runHTTP2ProxyTests(t *testing.T, server *httptest.Server, proxyURL *url.URL, proto string) {
	t.Helper()

	scheme := "http"
	if server.TLS != nil {
		scheme = "https"
	}

	rootCACertFile := createTempCertPEM(t, testutil.RootCACert(t), "rootCA.pem")
	defer os.Remove(rootCACertFile.Name())

	mitmCACertFile := createTempCertPEM(t, testutil.MITMCACert(t), "mitmCA.pem")
	defer os.Remove(mitmCACertFile.Name())

	buildCurlArgs := func(c httpTestCase) []string {
		url := fmt.Sprintf("%s://%s%s?status=%d", scheme, server.Listener.Addr(), c.path, c.status)

		args := make([]string, 0)
		if c.method == http.MethodHead {
			args = append(args, "--head")
		} else {
			args = append(args, "-X", c.method, "-d", c.body)
		}

		if proto == "HTTP/2.0" {
			args = append(args, "--http2")
		} else if proto == "HTTP/1.1" {
			args = append(args, "--http1.1")
		}

		args = append(args,
			"-s", "--proxy-cacert", rootCACertFile.Name(), "--proxy-http2", "-x", proxyURL.String(),
			"--cacert", mitmCACertFile.Name(), url)
		return args
	}

	for _, c := range httpTestCases {
		c := c

		t.Run(c.name, func(t *testing.T) {
			// TODO: stop using curl
			args := buildCurlArgs(c)
			curl := exec.Command("curl", args...)
			bs, err := curl.CombinedOutput()
			require.NoErrorf(t, err, "failed to execute curl: %s", string(bs))

			if c.method == http.MethodHead {
				return // no body
			}

			// the request that the true server received
			var serverReq request
			require.NoErrorf(t, json.NewDecoder(bytes.NewBuffer(bs)).Decode(&serverReq), "failed to decode the response body")

			assert.Equal(t, c.method, serverReq.Method, "unexpected method")
			assert.Equal(t, fmt.Sprintf("%s?status=%d", c.path, c.status), serverReq.URL, "unexpected url")
			assert.Equal(t, proto, serverReq.Proto, "unexpected protocol version")

			body, err := io.ReadAll(serverReq.Body)
			require.NoError(t, err)
			assert.Equal(t, c.body, string(body))
		})
	}
}

func TestProxyServer_can_proxy_through_http2(t *testing.T) {
	t.Parallel()

	rootCAs := testutil.RootCAs(t)

	httpServer := newHTTPServer()
	httpServer.Start()
	t.Cleanup(httpServer.Close)

	httpsServer := newHTTPServer()
	cert := testutil.MustIssueCertificate(t, pkix.Name{CommonName: "example.com"}, httpsServer.Listener.Addr())
	httpsServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	httpsServer.StartTLS()
	t.Cleanup(httpsServer.Close)

	cases := []struct {
		name     string
		server   *httptest.Server
		handler  http.HandlerFunc
		protocol string
	}{
		{
			name:   "proxy HTTP",
			server: httpServer,
			handler: mitmHttp.NewRoundTripHandler(func(r *http.Request) http.RoundTripper {
				assert.Equalf(t, "HTTP/2.0", r.Proto, "unexpected protocol version")
				assert.NotNilf(t, r.TLS, "unexpected non-TLS connection")

				return &http.Transport{}
			}),
			protocol: "HTTP/1.1",
		},
		{
			name:   "proxy HTTPS",
			server: httpsServer,
			handler: mitmHttp.NewRoundTripHandler(func(r *http.Request) http.RoundTripper {
				assert.Equalf(t, "HTTP/1.1", r.Proto, "unexpected protocol version")
				assert.NotNilf(t, r.TLS, "unexpected non-TLS connection")

				return &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs: rootCAs,
					},
				}
			}),
			protocol: "HTTP/1.1",
		},
		{
			name:   "proxy HTTP/2.0",
			server: httpsServer,
			handler: mitmHttp.NewRoundTripHandler(func(r *http.Request) http.RoundTripper {
				assert.Equalf(t, "HTTP/2.0", r.Proto, "unexpected protocol version")
				assert.NotNilf(t, r.TLS, "unexpected non-TLS connection")

				return &http2.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs:    rootCAs,
						NextProtos: []string{"h2"},
					},
				}
			}),
			protocol: "HTTP/2.0",
		},
	}

	for _, c := range cases {
		c := c

		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			// start HTTP(S) proxy server
			l := testutil.NewTCPListener(t)
			defer l.Close()

			proxyCert := testutil.MustIssueCertificate(t, pkix.Name{CommonName: "mitm-go.org"}, l.Addr())
			proxyServer := newHTTPSProxyServer(t,
				// NOTE: use HTTP/2 CONNECT
				mitmHttp.TLSConfig(&tls.Config{Certificates: []tls.Certificate{*proxyCert}}),
				mitmHttp.Handler(c.handler))
			defer proxyServer.Close()

			go func() {
				proxyServer.ServeTLS(l, "", "")
			}()

			proxyURL, err := url.Parse(fmt.Sprintf("https://%s", l.Addr().String()))
			require.NoError(t, err)

			runHTTP2ProxyTests(t, c.server, proxyURL, c.protocol)
		})
	}
}

func checkIfCurlSupportsHTTP2Proxy() bool {
	cmd := exec.Command("curl", "--http2")
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}
