// Copyright (c) 2024 homuler
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package mitm_test

import (
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/homuler/mitm-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemorizingReader_Read_can_read_regardless_of_the_initial_buffer(t *testing.T) {
	str := "Hello, World!"

	cases := []struct {
		name string
		buf  []byte
		outs []byte
	}{
		{
			name: "buf == nil",
			outs: make([]byte, 1),
		},
		{
			name: "cap(buf) == 0",
			buf:  make([]byte, 0),
		},
		{
			name: "len(buf) == 0",
			buf:  make([]byte, 0, len(str)),
		},
		{
			name: "len(buf) < len(str)",
			buf:  make([]byte, 5),
		},
		{
			name: "len(buf) == len(str)",
			buf:  make([]byte, len(str)),
		},
		{
			name: "len(buf) > len(str)",
			buf:  make([]byte, len(str)+1),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mr := mitm.NewMemorizingReader(strings.NewReader(str), c.buf)
			err := iotest.TestReader(mr, []byte(str))
			assert.NoError(t, err)
		})
	}
}

func TestMemorizingReader_Read_can_read_regardless_of_the_argument(t *testing.T) {
	str := "Hello, World!"

	cases := []struct {
		name string
		buf  []byte
		p    []byte

		// expected
		n1 int
		n2 int
	}{
		{
			name: "len(p) == 0",
			n1:   0,
			n2:   0,
		},
		{
			name: "len(p) < len(buf)",
			buf:  make([]byte, 6),
			p:    make([]byte, 5),
			n1:   5,
			n2:   1, // read from the buffer
		},
		{
			name: "len(p) == len(buf)",
			buf:  make([]byte, 6),
			p:    make([]byte, 6),
			n1:   6,
			n2:   6,
		},
		{
			name: "len(p) > len(buf)",
			buf:  make([]byte, 6),
			p:    make([]byte, 7),
			n1:   7,
			n2:   6, // read to the end
		},
		{
			name: "len(buf) >= len(str)",
			buf:  make([]byte, len(str)),
			p:    make([]byte, 5),
			n1:   5,
			n2:   5,
		},
		{
			name: "len(p) >= len(str)",
			buf:  nil,
			p:    make([]byte, len(str)),
			n1:   len(str),
			n2:   0,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mr := mitm.NewMemorizingReader(strings.NewReader(str), c.buf)
			n1, err := mr.Read(c.p)
			assert.NoError(t, err)
			assert.Equalf(t, c.n1, n1, "the reader should read the expected number of bytes (1st time)")
			assert.Equalf(t, str[:n1], string(c.p[:n1]), "the reader should read the expected bytes (1st time)")

			n2, _ := mr.Read(c.p)
			assert.Equalf(t, c.n2, n2, "the reader should read the expected number of bytes (2nd time)")
			assert.Equal(t, str[n1:n1+n2], string(c.p[:n2]), "the reader should read the expected bytes (2nd time)")
		})
	}
}

func TestMemorizingReader_Read_from_ErrReader(t *testing.T) {
	mr := mitm.NewMemorizingReader(iotest.ErrReader(io.EOF), nil)
	p := make([]byte, 2)
	n, err := mr.Read(p)
	assert.Equal(t, 0, n)
	assert.ErrorIs(t, err, io.EOF)
}

func TestMemorizingReader_Read_from_HalfReader(t *testing.T) {
	str := "Hello, World!"
	buf := make([]byte, len(str))
	mr := mitm.NewMemorizingReader(iotest.HalfReader(strings.NewReader(str)), buf)
	res, err := io.ReadAll(mr)
	assert.NoError(t, err)
	assert.Equal(t, str, string(res))
}

func TestMemorizingReader_Read_from_DataErrReader(t *testing.T) {
	str := "Hello, World!"
	buf := make([]byte, len(str))
	mr := mitm.NewMemorizingReader(iotest.DataErrReader(strings.NewReader(str)), buf)
	res, err := io.ReadAll(mr)
	assert.NoError(t, err)
	assert.Equal(t, str, string(res))
}

func TestMemorizingReader_Peek_returns_the_specified_number_of_bytes(t *testing.T) {
	str := "Hello, World!"

	cases := []struct {
		name string
		n    int
		buf  []byte
	}{
		{
			name: "n == 0",
			n:    0,
		},
		{
			name: "n < len(buf)",
			n:    5,
			buf:  make([]byte, 6),
		},
		{
			name: "n == len(buf)",
			n:    5,
			buf:  make([]byte, 5),
		},
		{
			name: "n == len(str)",
			n:    len(str),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mr := mitm.NewMemorizingReader(iotest.HalfReader(strings.NewReader(str)), c.buf)

			// Peek should return the same result every time
			for i := 0; i < 2; i++ {
				bs, err := mr.Peek(c.n)
				assert.NoError(t, err)
				assert.Equal(t, str[:c.n], string(bs))
			}
		})
	}
}

func TestMemorizingReader_Read_after_Peek_does_not_corrupt_the_buffer(t *testing.T) {
	str := "Hello, World!"
	mr := mitm.NewMemorizingReader(strings.NewReader(str), nil)

	_, err := mr.Peek(5)
	require.NoError(t, err)

	res, err := io.ReadAll(mr)
	assert.NoError(t, err)
	assert.Equal(t, str, string(res))

	_, err = mr.Seek(0, io.SeekStart)
	require.NoError(t, err)
	assert.Equal(t, str, string(mr.Memorized()))
}

func TestMemorizingReader_Peek_returns_error_when_failed_to_read_the_specified_number_of_bytes(t *testing.T) {
	str := "Hello, World!"
	mr := mitm.NewMemorizingReader(strings.NewReader(str), nil)
	bs, err := mr.Peek(len(str) + 1)
	assert.ErrorIs(t, err, io.EOF)
	assert.Equal(t, str, string(bs))
}

func TestMemorizingReader_Peek_from_ErrReader(t *testing.T) {
	mr := mitm.NewMemorizingReader(iotest.ErrReader(io.EOF), nil)
	bs, err := mr.Peek(1)
	assert.ErrorIs(t, err, io.EOF)
	assert.Empty(t, bs)
}

func TestMemorizingReader_Peek_from_DataErrReader(t *testing.T) {
	str := "Hello, World!"
	mr := mitm.NewMemorizingReader(iotest.DataErrReader(strings.NewReader(str)), nil)
	bs, err := mr.Peek(len(str))
	assert.ErrorIs(t, err, io.EOF)
	assert.Equal(t, str, string(bs))
}

func TestMemorizingReader_Seek_from_Start(t *testing.T) {
	str := "Hello, World!"
	mr := mitm.NewMemorizingReader(strings.NewReader(str), nil)

	n, err := mr.Read(make([]byte, 5))
	require.NoError(t, err)
	require.True(t, n > 0)
	assert.Equal(t, 0, mr.Buffered())

	pos, err := mr.Seek(0, io.SeekStart)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), pos)
	assert.Equal(t, n, mr.Buffered())

	// Seek beyond the beginning
	_, err = mr.Seek(-1, io.SeekStart)
	assert.Error(t, err)

	// Seek to the end of the buffer
	pos, err = mr.Seek(int64(n), io.SeekStart)
	assert.NoError(t, err)
	assert.Equal(t, int64(n), pos)
	assert.Equal(t, 0, mr.Buffered())

	// Seek beyond the end of the buffer
	pos, err = mr.Seek(int64(n)+1, io.SeekStart)
	assert.ErrorIs(t, err, io.EOF)
	assert.Equal(t, int64(n), pos)
}

func TestMemorizingReader_Seek_from_Current(t *testing.T) {
	str := "Hello, World!"
	mr := mitm.NewMemorizingReader(strings.NewReader(str), nil)

	n, err := mr.Read(make([]byte, 5))
	require.NoError(t, err)
	require.True(t, n > 0)
	assert.Equal(t, 0, mr.Buffered())

	// Seek to the end of the buffer
	pos, err := mr.Seek(0, io.SeekCurrent)
	assert.NoError(t, err)
	assert.Equal(t, int64(n), pos)
	assert.Equal(t, 0, mr.Buffered())

	// Seek beyond the end of the buffer
	pos, err = mr.Seek(1, io.SeekCurrent)
	assert.ErrorIs(t, err, io.EOF)
	assert.Equal(t, int64(n), pos)

	// Seek to the begeinning
	pos, err = mr.Seek(int64(-n), io.SeekCurrent)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), pos)
	assert.Equal(t, n, mr.Buffered())

	// Seek beyond the beginning
	_, err = mr.Seek(-1, io.SeekCurrent)
	assert.Error(t, err)
}

func TestMemorizingReader_Seek_from_End(t *testing.T) {
	str := "Hello, World!"
	mr := mitm.NewMemorizingReader(strings.NewReader(str), nil)

	n, err := mr.Read(make([]byte, 5))
	require.NoError(t, err)
	require.True(t, n > 0)

	_, err = mr.Seek(0, io.SeekEnd)
	assert.Error(t, err)
}

func TestMemorizingReader_Memorized(t *testing.T) {
	str := "Hello, World!"
	cases := []struct {
		name  string
		start int
		end   int
	}{
		{
			name:  "not read yet",
			start: 0,
			end:   0,
		},
		{
			name:  "start == end",
			start: 5,
			end:   5,
		},
		{
			name:  "from the beginning",
			start: 0,
			end:   5,
		},
		{
			name:  "from the middle",
			start: 5,
			end:   10,
		},
		{
			name:  "all",
			start: 0,
			end:   len(str),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mr := mitm.NewMemorizingReader(strings.NewReader(str), nil)
			_, err := mr.Peek(c.end)
			require.NoError(t, err)

			_, err = mr.Seek(int64(c.start), io.SeekStart)
			require.NoError(t, err)
			assert.Equal(t, str[c.start:c.end], string(mr.Memorized()))
		})
	}
}

func TestMemorizingReader_Forget(t *testing.T) {
	str := "Hello, World!"

	cases := []struct {
		name          string
		read          int
		peek          int
		forget        int
		expectedStart int
	}{
		{
			name:          "before Read",
			read:          0,
			forget:        10,
			expectedStart: 0,
		},
		{
			name:          "forget all read bytes",
			read:          5,
			forget:        5,
			expectedStart: 5,
		},
		{
			name:          "forget less than read",
			read:          5,
			forget:        3,
			expectedStart: 3,
		},
		{
			name:          "forget more than read",
			read:          5,
			forget:        10,
			expectedStart: 5,
		},
		{
			name:          "forget all",
			read:          len(str),
			forget:        len(str),
			expectedStart: len(str),
		},
		{
			name:          "forget all peeked bytes",
			peek:          5,
			forget:        5,
			expectedStart: 5,
		},
		{
			name:          "forget less than peeked",
			peek:          5,
			forget:        3,
			expectedStart: 3,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mr := mitm.NewMemorizingReader(strings.NewReader(str), nil)
			_, err := mr.Read(make([]byte, c.read))
			require.NoError(t, err)

			_, err = mr.Peek(c.peek)
			require.NoError(t, err)

			n := mr.Forget(c.forget)
			assert.Equal(t, c.expectedStart, n)

			_, err = io.ReadAll(mr)
			require.NoError(t, err)
			_, err = mr.Seek(0, io.SeekStart)
			require.NoError(t, err)

			assert.Equal(t, str[c.expectedStart:], string(mr.Memorized()))
		})
	}
}
