package mitm_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/homuler/mitm-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/nettest"
)

func TestNewTamperedConn_default(t *testing.T) {
	t.Parallel()

	nettest.TestConn(t, func() (c1, c2 net.Conn, stop func(), err error) {
		p1, p2 := net.Pipe()
		c1 = mitm.NewTamperedConn(p1)
		c2 = mitm.NewTamperedConn(p2)
		stop = func() {
			c1.Close()
			c2.Close()
		}
		return
	})
}

func TestTamperConnRead(t *testing.T) {
	t.Parallel()

	str := "Hello, World!"
	in := strings.NewReader(str)
	out := bytes.NewBuffer(nil)
	rd := io.TeeReader(in, out)
	conn := mitm.NewTamperedConn(nil, mitm.TamperConnRead(rd.Read))
	defer conn.Close()

	bs, err := io.ReadAll(conn)
	require.NoError(t, err)
	assert.Equal(t, str, string(bs))
	assert.Equal(t, str, out.String())
}

func TestTamperConnWrite(t *testing.T) {
	t.Parallel()

	buf := bytes.NewBuffer(nil)
	conn := mitm.NewTamperedConn(nil, mitm.TamperConnWrite(buf.Write))

	str := "Hello, World!"
	conn.Write([]byte(str))

	assert.Equal(t, str, buf.String())
}

func TestTamperConnClose(t *testing.T) {
	t.Parallel()

	done := make(chan struct{})
	conn := mitm.NewTamperedConn(nil, mitm.TamperConnClose(func() error {
		close(done)
		return nil
	}))

	go func() { conn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	select {
	case <-ctx.Done():
		t.Fatal("timeout")
	case <-done:
		assert.NoError(t, conn.Close())
	}
}
