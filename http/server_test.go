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
	"strconv"
	"strings"
	"testing"

	"github.com/homuler/mitm-proxy-go"
	mitmHttp "github.com/homuler/mitm-proxy-go/http"
	"github.com/homuler/mitm-proxy-go/internal/testutil"
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
			curl.Env = append(curl.Env, "SSLKEYLOGFILE=/home/homuler/sslkeylogfile.txt")
			bs, err := curl.CombinedOutput()
			require.NoErrorf(t, err, "failed to execute curl")

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

func TestProxyServer_can_proxy_http1_through_http2(t *testing.T) {
	t.Parallel()

	server := newHTTPServer()
	server.Start()
	defer server.Close()

	l := testutil.NewTCPListener(t)
	defer l.Close()

	rootCAs := testutil.RootCAs(t)
	proxyCert := testutil.MustIssueCertificate(t, pkix.Name{CommonName: "mitm-go.org"}, l.Addr())
	handler := mitmHttp.NewRoundTripHandler(func(r *http.Request) http.RoundTripper {
		assert.Equalf(t, "HTTP/2.0", r.Proto, "unexpected protocol version")

		return &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: rootCAs,
			},
		}
	})
	proxyServer := newHTTPSProxyServer(t,
		mitmHttp.TLSConfig(&tls.Config{Certificates: []tls.Certificate{*proxyCert}}), // use HTTP/2 CONNECT
		mitmHttp.Handler(handler))
	defer proxyServer.Close()

	go func() {
		proxyServer.ServeTLS(l, "", "")
	}()

	proxyURL, err := url.Parse(fmt.Sprintf("https://%s", l.Addr().String()))
	require.NoError(t, err)

	runHTTP2ProxyTests(t, server, proxyURL, "HTTP/1.1")
}

func TestProxyServer_can_proxy_http1_secure_through_http2(t *testing.T) {
	t.Parallel()

	server := newHTTPServer()
	cert := testutil.MustIssueCertificate(t, pkix.Name{}, server.Listener.Addr())
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	server.StartTLS()
	defer server.Close()

	l := testutil.NewTCPListener(t)
	defer l.Close()

	rootCAs := testutil.RootCAs(t)
	proxyCert := testutil.MustIssueCertificate(t, pkix.Name{CommonName: "mitm-go.org"}, l.Addr())
	handler := mitmHttp.NewRoundTripHandler(func(r *http.Request) http.RoundTripper {
		assert.Equalf(t, "HTTP/1.1", r.Proto, "unexpected protocol version")

		return &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: rootCAs,
			},
		}
	})
	proxyServer := newHTTPSProxyServer(t,
		mitmHttp.TLSConfig(&tls.Config{Certificates: []tls.Certificate{*proxyCert}}), // use HTTP/2 CONNECT
		mitmHttp.Handler(handler))
	defer proxyServer.Close()

	go func() {
		proxyServer.ServeTLS(l, "", "")
	}()

	proxyURL, err := url.Parse(fmt.Sprintf("https://%s", l.Addr().String()))
	require.NoError(t, err)

	runHTTP2ProxyTests(t, server, proxyURL, "HTTP/1.1")
}

func TestProxyServer_can_proxy_http2_through_http2(t *testing.T) {
	t.Parallel()

	server := newHTTPServer()
	cert := testutil.MustIssueCertificate(t, pkix.Name{}, server.Listener.Addr())
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	server.StartTLS()
	defer server.Close()

	l := testutil.NewTCPListener(t)
	defer l.Close()

	rootCAs := testutil.RootCAs(t)
	proxyCert := testutil.MustIssueCertificate(t, pkix.Name{CommonName: "mitm-go.org"}, l.Addr())
	handler := mitmHttp.NewRoundTripHandler(func(r *http.Request) http.RoundTripper {
		assert.Equalf(t, "HTTP/2.0", r.Proto, "unexpected protocol version")

		return &http2.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    rootCAs,
				NextProtos: []string{"h2"},
			},
		}
	})
	proxyServer := newHTTPSProxyServer(t,
		mitmHttp.TLSConfig(&tls.Config{Certificates: []tls.Certificate{*proxyCert}}), // use HTTP/2 CONNECT
		mitmHttp.Handler(handler))
	defer proxyServer.Close()

	go func() {
		proxyServer.ServeTLS(l, "", "")
	}()

	proxyURL, err := url.Parse(fmt.Sprintf("https://%s", l.Addr().String()))
	require.NoError(t, err)

	runHTTP2ProxyTests(t, server, proxyURL, "HTTP/2.0")
}
