package mitm

import (
	"bytes"
	"errors"
	"io"
)

// memorizingReader is a reader that memorizes the read bytes.
// After reading, you can seek back to the position that has been read and read from there again.
type memorizingReader struct {
	rd  io.Reader
	buf []byte

	r, w int
	eof  bool
}

var _ io.ReadSeeker = &memorizingReader{}

// NewMemorizingReader returns a new memorizingReader.
func NewMemorizingReader(r io.Reader, buf []byte) *memorizingReader {
	return &memorizingReader{rd: r, buf: buf}
}

// Read reads data into p and memorizes them.
// It returns the number of bytes read into p.
// Note that the returned value can be less than len(p).
func (mr *memorizingReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	if mr.w != mr.r {
		return mr.readBuf(p), nil
	}

	mr.ensureBufferSize(len(p))
	n, err := mr.read()
	if n > 0 {
		return mr.readBuf(p), err
	}
	return n, err
}

func (mr *memorizingReader) read() (int, error) {
	n, err := mr.rd.Read(mr.buf[mr.w:])
	mr.w += n
	if err == io.EOF {
		mr.eof = true
	}
	return n, err
}

func (mr *memorizingReader) readBuf(p []byte) int {
	n := copy(p, mr.buf[mr.r:mr.w])
	mr.r += n
	return n
}

// Peek returns the next n bytes without advancing the reader.
func (mr *memorizingReader) Peek(n int) ([]byte, error) {
	err := mr.bufferAtLeast(n)
	last := mr.r + n
	if last > mr.w {
		last = mr.w
	}
	return mr.buf[mr.r:last], err
}

func (mr *memorizingReader) bufferAtLeast(n int) error {
	buffered := mr.Buffered()
	if buffered >= n {
		return nil
	}
	mr.ensureBufferSize(n - buffered)

	for mr.w-mr.r < n {
		_, err := mr.read()
		if err != nil {
			return err
		}
	}
	return nil
}

var (
	errWhence    = errors.New("Seek: invalid whence")
	errOffset    = errors.New("Seek: invalid offset")
	errBeforeEOF = errors.New("Seek: cannot seek from end before EOF")
)

// Seek implements io.Seeker
// It can only seek to the position that has been read.
// If whence is io.SeekEnd and the reader has not reached EOF, it returns an error.
func (mr *memorizingReader) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		// do nothing
	case io.SeekCurrent:
		offset += int64(mr.r)
	case io.SeekEnd:
		if mr.eof {
			offset += int64(mr.w)
		} else {
			return 0, errBeforeEOF
		}
	default:
		return 0, errWhence
	}
	if offset < 0 {
		return 0, errOffset
	}
	if offset > int64(mr.w) {
		mr.r = mr.w
		return int64(mr.r), io.EOF
	}
	mr.r = int(offset)
	return offset, nil
}

func (mr *memorizingReader) Buffered() int {
	return mr.w - mr.r
}

// Forget try to forget the first n bytes from the buffer and returns the number of bytes forgotten.
// If n is greater than the byte size that has been read, it will forget all the read bytes.
// In this case, the returned value can be less than n.
func (mr *memorizingReader) Forget(n int) (s int) {
	if n > mr.w {
		s = mr.w
	} else {
		s = n
	}
	copy(mr.buf, mr.buf[s:mr.w])
	mr.w -= s
	mr.r -= s
	if mr.r < 0 {
		mr.r = 0
	}
	return s
}

// Memorized returns a reader that reads the memorized bytes from the current position if any.
// Note that to read from the beginning, you need to call Seek(0, io.SeekStart) first.
func (mr *memorizingReader) Memorized() io.Reader {
	return bytes.NewReader(mr.buf[mr.r:mr.w])
}

func (mr *memorizingReader) available() int {
	return len(mr.buf) - mr.w
}

func (mr *memorizingReader) ensureBufferSize(n int) {
	rem := mr.available()
	if rem >= n {
		return
	}
	mr.buf = append(mr.buf, make([]byte, n-rem)...)
}

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
