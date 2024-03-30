package mitm_test

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/homuler/mitm-go"
)

func Example_memorizingReader_Memorized() {
	mr := mitm.NewMemorizingReader(strings.NewReader("Hello, World!"), nil)
	io.ReadAll(mr)
	mr.Seek(0, io.SeekStart)
	fmt.Println(string(mr.Memorized()))
	// Output: Hello, World!
}

func Example_memorizingReader_OneTimeReader() {
	mr := mitm.NewMemorizingReader(strings.NewReader("Hello, World!"), nil)
	bs, err := mr.Next(5)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(bs))

	// read from the beginning again without memorizing.
	if _, err = mr.Seek(0, io.SeekStart); err != nil {
		log.Fatal(err)
	}
	if _, err := io.Copy(os.Stdout, mr.OneTimeReader()); err != nil {
		log.Fatal(err)
	}
	// Output:
	// Hello
	// Hello, World!
}

func ExampleNewTamperedConn() {
	server, client := net.Pipe()

	done := make(chan struct{})
	sconn := mitm.NewTamperedConn(server,
		mitm.TamperConnRead(func(bs []byte) (int, error) {
			n, err := server.Read(bs)
			// echo to stdout
			io.CopyN(os.Stdout, bytes.NewReader(bs), int64(n))
			return n, err
		}),
		mitm.TamperConnClose(func() error {
			err := server.Close()
			close(done)
			return err
		}))

	go func() {
		defer sconn.Close()
		io.Copy(io.Discard, sconn)
	}()

	client.Write([]byte("Hello, World!\n"))
	client.Close()
	<-done
	// Output: Hello, World!
}

func processListener(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()

			io.Copy(os.Stdout, conn)
		}()
	}
}

func ExampleOneTimeListener() {
	server, client := net.Pipe()

	done := make(chan struct{})
	sconn := mitm.NewTamperedConn(server, mitm.TamperConnClose(func() error {
		err := server.Close()
		close(done)
		return err
	}))
	// when an existing API demands a net.Listener instead of a net.Conn, you can use OneTimeListener.
	ln := mitm.NewOneTimeListener(sconn)

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		processListener(ln)
		wg.Done()
	}()

	client.Write([]byte("Hello"))
	client.Close()
	<-done
	ln.Close()

	wg.Wait()
	// Output:
	// Hello
}
