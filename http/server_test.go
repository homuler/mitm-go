// Copyright (c) 2024 homuler
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package http_test

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/homuler/mitm-go"
	mitmHttp "github.com/homuler/mitm-go/http"
	"github.com/homuler/mitm-go/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

func newHTTPServer() *httptest.Server {
	mux := http.NewServeMux()

	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		codeStr := r.URL.Query().Get("status")
		code, err := strconv.Atoi(codeStr)
		if err != nil {
			panic(err)
		}

		w.WriteHeader(code)

		if r.Method == http.MethodHead {
			return
		}
		serializeRequest(w, r)
	}))

	return httptest.NewUnstartedServer(mux)
}

func newHTTPSProxyServer(t *testing.T, options ...mitmHttp.ProxyServerOption) mitmHttp.ProxyServer {
	return mitmHttp.NewProxyServer(&mitm.TLSConfig{
		RootCertificate: testutil.MITMCACert(t),
		GetClientConfig: func(serverName string, alpnProtocols []string) *tls.Config {
			return &tls.Config{
				RootCAs:    testutil.RootCAs(t),
				ServerName: serverName,
				NextProtos: alpnProtocols,
			}
		},
	}, options...)
}

func newTProxyServer(t *testing.T, destination net.Addr, options ...mitmHttp.ProxyServerOption) mitmHttp.TProxyServer {
	return mitmHttp.NewTProxyServer(&mitm.TLSConfig{
		RootCertificate: testutil.MITMCACert(t),
		GetDestination: func(net.Conn, string) net.Addr {
			return destination
		},
		GetClientConfig: func(serverName string, alpnProtocols []string) *tls.Config {
			return &tls.Config{
				RootCAs:    testutil.RootCAs(t),
				ServerName: serverName,
				NextProtos: alpnProtocols,
			}
		},
	}, options...)
}

type request struct {
	Proto  string
	Method string
	URL    string
	Header http.Header
	Body   *jsonStringReader
}

type jsonStringReader struct {
	io.Reader
}

var _ json.Marshaler = &jsonStringReader{}
var _ json.Unmarshaler = &jsonStringReader{}

func (r *jsonStringReader) MarshalJSON() ([]byte, error) {
	data, err := io.ReadAll(r.Reader)
	if err != nil {
		return nil, err
	}
	return json.Marshal(string(data))
}

func (r *jsonStringReader) UnmarshalJSON(data []byte) error {
	var str string
	if data == nil {
		return nil
	}
	json.NewDecoder(bytes.NewReader(data)).Decode(&str)
	r.Reader = bytes.NewReader([]byte(str))
	return nil
}

func serializeRequest(w io.Writer, r *http.Request) {
	req := request{
		Proto:  r.Proto,
		Method: r.Method,
		URL:    r.URL.String(),
		Header: r.Header,
		Body:   &jsonStringReader{r.Body},
	}

	json.NewEncoder(w).Encode(req)
}

type httpTestCase struct {
	name   string
	method string
	path   string
	body   string
	status int
}

var httpTestCases = []httpTestCase{
	{
		name:   "GET / (OK)",
		method: http.MethodGet,
		path:   "/",
		status: http.StatusOK,
	},
	{
		name:   "HEAD / (OK)",
		method: http.MethodHead,
		path:   "/foo",
		status: http.StatusOK,
	},
	{
		name:   "POST /foo/1 (Created)",
		method: http.MethodPost,
		path:   "/foo/1",
		body:   "hello",
		status: http.StatusCreated,
	},
	{
		name:   "PUT /foo/2 (Not Found)",
		method: http.MethodPut,
		path:   "/foo/2",
		body:   "world",
		status: http.StatusBadRequest,
	},
	{
		name:   "PATCH /foo/1 (Method Not Allowed)",
		method: http.MethodPatch,
		path:   "/foo/1",
		body:   "world",
		status: http.StatusMethodNotAllowed,
	},
	{
		name:   "DELETE /foo/bar (Internal Server Error)",
		method: http.MethodDelete,
		path:   "/foo/bar",
		status: http.StatusInternalServerError,
	},
	{
		name:   "OPTIONS /foo/1 (OK)",
		method: http.MethodOptions,
		path:   "/foo/1",
		status: http.StatusOK,
	},
}

func runHTTP1ProxyTests(t *testing.T, server *httptest.Server, client *http.Client, proto string) {
	scheme := "http"
	if server.TLS != nil {
		scheme = "https"
	}

	for _, c := range httpTestCases {
		c := c

		t.Run(c.name, func(t *testing.T) {
			url := fmt.Sprintf("%s://%s%s?status=%d", scheme, server.Listener.Addr().String(), c.path, c.status)
			req, err := http.NewRequest(c.method, url, strings.NewReader(c.body))
			require.NoErrorf(t, err, "failed to create a request")

			resp, err := client.Do(req)
			require.NoErrorf(t, err, "failed to send a request")
			defer resp.Body.Close()

			assert.Equalf(t, c.status, resp.StatusCode, "unexpected status code")

			if c.method == http.MethodHead {
				return // no body
			}

			// the request that the true server received
			var serverReq request
			require.NoErrorf(t, json.NewDecoder(resp.Body).Decode(&serverReq), "failed to decode the response body")

			assert.Equal(t, c.method, serverReq.Method, "unexpected method")
			assert.Equal(t, fmt.Sprintf("%s?status=%d", c.path, c.status), serverReq.URL, "unexpected url")
			assert.Equal(t, proto, serverReq.Proto, "unexpected protocol version")

			body, err := io.ReadAll(serverReq.Body)
			require.NoError(t, err)
			assert.Equal(t, c.body, string(body))
		})
	}
}

func TestProxyServer_can_proxy_through_http1(t *testing.T) {
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
				assert.Equalf(t, "HTTP/1.1", r.Proto, "unexpected protocol version")

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

			proxyServer := newHTTPSProxyServer(t, mitmHttp.Handler(c.handler))
			defer proxyServer.Close()

			go func() {
				proxyServer.Serve(l)
			}()

			proxyURL, err := url.Parse(fmt.Sprintf("http://%s", l.Addr().String()))
			require.NoError(t, err, "failed to parse the proxy URL")

			client := &http.Client{
				Transport: &http.Transport{
					Proxy: http.ProxyURL(proxyURL),
					TLSClientConfig: &tls.Config{
						RootCAs: testutil.ClientRootCAs(t),
					},
					ForceAttemptHTTP2: c.protocol == "HTTP/2.0",
				},
			}

			runHTTP1ProxyTests(t, c.server, client, c.protocol)
		})

		t.Run(fmt.Sprintf("%s (secure)", c.name), func(t *testing.T) {
			t.Parallel()

			// start HTTP(S) proxy server
			l := testutil.NewTCPListener(t)
			defer l.Close()

			proxyCert := testutil.MustIssueCertificate(t, pkix.Name{CommonName: "mitm-go.org"}, l.Addr())
			proxyServer := newHTTPSProxyServer(t,
				// NOTE: use HTTP/1.1 CONNECT
				mitmHttp.TLSConfig(&tls.Config{Certificates: []tls.Certificate{*proxyCert}, NextProtos: []string{"http/1.1"}}),
				mitmHttp.Handler(c.handler))
			defer proxyServer.Close()

			go func() {
				proxyServer.ServeTLS(l, "", "")
			}()

			proxyURL, err := url.Parse(fmt.Sprintf("https://%s", l.Addr().String()))
			require.NoError(t, err, "failed to parse the proxy URL")

			client := &http.Client{
				Transport: &http.Transport{
					Proxy: http.ProxyURL(proxyURL),
					TLSClientConfig: &tls.Config{
						RootCAs: testutil.ClientRootCAs(t),
					},
					ForceAttemptHTTP2: c.protocol == "HTTP/2.0",
				},
			}

			runHTTP1ProxyTests(t, c.server, client, c.protocol)
		})
	}
}

func assertHTTPRequest(t *testing.T, c httpTestCase, conn net.Conn, server *httptest.Server, proto string) {
	scheme := "http"
	if server.TLS != nil {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s%s?status=%d", scheme, server.Listener.Addr().String(), c.path, c.status)
	req, err := http.NewRequest(c.method, url, strings.NewReader(c.body))
	require.NoErrorf(t, err, "failed to create a request")

	err = req.Write(conn)
	require.NoError(t, err, "failed to send a request")

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	require.NoError(t, err, "failed to read the response")
	defer resp.Body.Close()

	assertHTTPResponse(t, c, proto, resp)
}

func assertHTTPResponse(t *testing.T, c httpTestCase, proto string, resp *http.Response) {
	assert.Equalf(t, c.status, resp.StatusCode, "unexpected status code")

	if c.method == http.MethodHead {
		return // no body
	}

	// the request that the true server received
	var serverReq request
	require.NoErrorf(t, json.NewDecoder(resp.Body).Decode(&serverReq), "failed to decode the response body")

	assert.Equal(t, c.method, serverReq.Method, "unexpected method")
	assert.Equal(t, fmt.Sprintf("%s?status=%d", c.path, c.status), serverReq.URL, "unexpected url")
	assert.Equal(t, proto, serverReq.Proto, "unexpected protocol version")

	body, err := io.ReadAll(serverReq.Body)
	require.NoError(t, err)
	assert.Equal(t, c.body, string(body))
}

func TestTProxyServer_can_proxy_http(t *testing.T) {
	t.Parallel()

	httpServer := newHTTPServer()
	httpServer.Start()
	t.Cleanup(httpServer.Close)

	// start HTTP(S) proxy server
	l := testutil.NewTCPListener(t)
	defer l.Close()

	handler := mitmHttp.NewRoundTripHandler(func(r *http.Request) http.RoundTripper {
		assert.Equalf(t, "HTTP/1.1", r.Proto, "unexpected protocol version")
		assert.Nilf(t, r.TLS, "unexpected TLS connection")

		return &http.Transport{}
	})
	proxyServer := newTProxyServer(t, httpServer.Listener.Addr(), mitmHttp.Handler(handler))
	defer proxyServer.Close()

	go func() {
		proxyServer.Serve(l)
	}()

	for _, c := range httpTestCases {
		c := c

		t.Run(c.name, func(t *testing.T) {
			conn, err := net.Dial("tcp", l.Addr().String())
			require.NoError(t, err, "failed to dial the proxy server")
			defer conn.Close()

			assertHTTPRequest(t, c, conn, httpServer, "HTTP/1.1")
		})
	}
}

func TestTProxyServer_can_proxy_https(t *testing.T) {
	t.Parallel()

	httpsServer := newHTTPServer()
	cert := testutil.MustIssueCertificate(t, pkix.Name{CommonName: "example.com"}, httpsServer.Listener.Addr())
	httpsServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	httpsServer.StartTLS()
	t.Cleanup(httpsServer.Close)

	// start HTTP(S) proxy server
	l := testutil.NewTCPListener(t)
	defer l.Close()

	proxyCert := testutil.MustIssueCertificate(t, pkix.Name{CommonName: "mitm-go.org"}, l.Addr())
	handler := mitmHttp.NewRoundTripHandler(func(r *http.Request) http.RoundTripper {
		assert.Equalf(t, "HTTP/1.1", r.Proto, "unexpected protocol version")
		assert.NotNilf(t, r.TLS, "unexpected non-TLS connection")

		return &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: testutil.RootCAs(t),
			},
		}
	})
	proxyServer := newTProxyServer(t, httpsServer.Listener.Addr(),
		mitmHttp.TLSConfig(&tls.Config{Certificates: []tls.Certificate{*proxyCert}}),
		mitmHttp.Handler(handler))
	defer proxyServer.Close()

	go func() {
		proxyServer.ServeTLS(l, "", "")
	}()

	for _, c := range httpTestCases {
		c := c

		t.Run(c.name, func(t *testing.T) {
			conn, err := tls.Dial("tcp", l.Addr().String(), &tls.Config{RootCAs: testutil.ClientRootCAs(t), NextProtos: []string{"http/1.1"}})
			require.NoError(t, err, "failed to dial the proxy server")
			defer conn.Close()

			assertHTTPRequest(t, c, conn, httpsServer, "HTTP/1.1")
		})
	}
}

func TestTProxyServer_can_proxy_http2(t *testing.T) {
	t.Parallel()

	httpsServer := newHTTPServer()
	cert := testutil.MustIssueCertificate(t, pkix.Name{CommonName: "example.com"}, httpsServer.Listener.Addr())
	httpsServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	httpsServer.StartTLS()
	t.Cleanup(httpsServer.Close)

	// start HTTP(S) proxy server
	l := testutil.NewTCPListener(t)
	defer l.Close()

	proxyCert := testutil.MustIssueCertificate(t, pkix.Name{CommonName: "mitm-go.org"}, l.Addr())
	handler := mitmHttp.NewRoundTripHandler(func(r *http.Request) http.RoundTripper {
		assert.Equalf(t, "HTTP/2.0", r.Proto, "unexpected protocol version")
		assert.NotNilf(t, r.TLS, "unexpected non-TLS connection")

		return &http2.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: testutil.RootCAs(t),
			},
		}
	})
	proxyServer := newTProxyServer(t, httpsServer.Listener.Addr(),
		mitmHttp.TLSConfig(&tls.Config{Certificates: []tls.Certificate{*proxyCert}, NextProtos: []string{"h2"}}),
		mitmHttp.Handler(handler))
	defer proxyServer.Close()

	go func() {
		proxyServer.ServeTLS(l, "", "")
	}()

	for _, c := range httpTestCases {
		c := c

		t.Run(c.name, func(t *testing.T) {
			conn, err := tls.Dial("tcp", l.Addr().String(), &tls.Config{RootCAs: testutil.ClientRootCAs(t), NextProtos: []string{"h2"}})
			require.NoError(t, err, "failed to dial the proxy server")
			defer conn.Close()

			tr := &http2.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: testutil.ClientRootCAs(t),
				},
			}

			http2Conn, err := tr.NewClientConn(conn)
			require.NoError(t, err, "failed to create a new HTTP/2 connection")
			defer http2Conn.Close()

			url := fmt.Sprintf("https://%s%s?status=%d", httpsServer.Listener.Addr().String(), c.path, c.status)
			req, err := http.NewRequest(c.method, url, strings.NewReader(c.body))
			require.NoErrorf(t, err, "failed to create a request")

			resp, err := http2Conn.RoundTrip(req)
			require.NoError(t, err, "failed to send a request")
			defer resp.Body.Close()

			assertHTTPResponse(t, c, "HTTP/2.0", resp)
		})
	}
}
