package http_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	mitmHttp "github.com/homuler/mitm-proxy-go/http"
	"github.com/homuler/mitm-proxy-go/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		serializeRequest(w, r)
	}))

	return httptest.NewServer(mux)
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

func TestProxyServer_can_proxy_http1_by_default(t *testing.T) {
	t.Parallel()

	mitmCACert := testutil.MITMCACert(t)

	server := newHTTPServer()
	defer server.Close()

	proxyServer := mitmHttp.NewProxyServer(*mitmCACert)
	defer proxyServer.Close()

	l := testutil.NewTCPListener(t)
	defer l.Close()

	go func() {
		proxyServer.Serve(l)
	}()

	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", l.Addr().String()))
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	cases := []struct {
		name   string
		method string
		path   string
		body   string
		status int
	}{
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

	for _, c := range cases {
		c := c

		t.Run(c.name, func(t *testing.T) {
			url := fmt.Sprintf("http://%s%s?status=%d", server.Listener.Addr().String(), c.path, c.status)
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
			assert.Equal(t, "HTTP/1.1", serverReq.Proto, "unexpected protocol version")

			body, err := io.ReadAll(serverReq.Body)
			require.NoError(t, err)
			assert.Equal(t, c.body, string(body))
		})
	}
}
