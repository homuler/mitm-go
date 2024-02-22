package mitm

import (
	"io"
)

type peeker interface {
	Peek(int) ([]byte, error)
}

type PeekReader interface {
	io.Reader
	peeker
}

type peekReader struct {
	rd  io.Reader
	buf []byte

	r, w int
}

func NewPeekReader(r io.Reader, buf []byte) PeekReader {
	return &peekReader{rd: r, buf: buf}
}

func (pr *peekReader) Read(b []byte) (int, error) {
	if pr.w != pr.r {
		n := pr.readBuf(b)
		return n, nil
	}
	return pr.rd.Read(b)
}

func (pr *peekReader) Peek(n int) ([]byte, error) {
	if pr.available() < n {
		pr.grow(n)
	}
	bs := pr.buf[pr.w : pr.w+n]
	m, err := pr.rd.Read(bs)
	pr.w += m
	return bs[:m], err
}

func (pr *peekReader) available() int {
	return cap(pr.buf) - pr.w
}

func (pr *peekReader) grow(n int) {
	if pr.available() >= n {
		return
	}
	pr.buf = append(pr.buf[:cap(pr.buf)], make([]byte, n-pr.available())...)
}

func (pr *peekReader) readBuf(p []byte) int {
	n := copy(p, pr.buf[pr.r:pr.w])
	pr.r += n

	if pr.r == pr.w {
		pr.r, pr.w = 0, 0
	}
	return n
}
