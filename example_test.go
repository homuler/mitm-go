package mitm_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

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

func mustLoadCACert(cn string) *tls.Certificate {
	cert, err := mitm.CreateCACert(pkix.Name{CommonName: cn}, 1*time.Hour)
	if err != nil {
		panic(err)
	}
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		panic(err)
	}
	return &cert
}

func mustIssueLocalCert(ca *tls.Certificate, cn string) *tls.Certificate {
	cert, err := mitm.ForgeCertificate(ca, &x509.Certificate{
		Subject:     pkix.Name{CommonName: cn},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(1 * time.Hour),
		DNSNames:    []string{cn},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	})
	if err != nil {
		panic(err)
	}

	return &cert
}

func ExampleNewTLSListener() {
	rootCACert := mustLoadCACert("root")
	mitmCACert := mustLoadCACert("mitm")

	defaultPool := x509.NewCertPool()
	defaultPool.AddCert(rootCACert.Leaf)

	mitmPool := x509.NewCertPool()
	mitmPool.AddCert(mitmCACert.Leaf)

	// true server
	l1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	trueCert := mustIssueLocalCert(rootCACert, "echo")
	l1 = tls.NewListener(l1, &tls.Config{
		Certificates: []tls.Certificate{*trueCert},
	})
	defer l1.Close()

	go func() {
		for {
			conn, err := l1.Accept()
			if err != nil {
				break
			}

			go func() {
				defer conn.Close()
				io.Copy(conn, conn) // echo
			}()
		}
	}()

	// MITM server
	l2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}

	l2, err = mitm.NewTLSListener(l2, &mitm.TLSConfig{
		RootCertificate: mitmCACert, // self-signed certificate
		GetClientConfig: func(serverName string, alpnProtocols []string) *tls.Config {
			c := mitm.DefaultGetTLSClientConfig(serverName, alpnProtocols)
			c.RootCAs = defaultPool
			return c
		},
		GetDestination: func(conn net.Conn, serverName string) net.Addr {
			return l1.Addr()
		},
	})
	if err != nil {
		panic(err)
	}
	defer l2.Close()

	go func() {
		for {
			conn, err := l2.Accept()
			if err != nil {
				break
			}

			go func() {
				defer conn.Close()

				io.Copy(os.Stdout, conn)
				conn.Write([]byte("Bye!\n"))
			}()
		}
	}()

	clientConn, err := tls.Dial(l2.Addr().Network(), l2.Addr().String(), &tls.Config{
		ServerName: "echo",
		RootCAs:    mitmPool,
	})
	if err != nil {
		panic(err)
	}
	defer clientConn.Close()

	clientConn.Write([]byte("Hello, World!\n"))
	clientConn.CloseWrite()
	io.Copy(os.Stdout, clientConn)
	// Output:
	// Hello, World!
	// Bye!
}

func ExampleNewTLSServer() {
	rootCACert := mustLoadCACert("root")
	mitmCACert := mustLoadCACert("mitm")

	defaultPool := x509.NewCertPool()
	defaultPool.AddCert(rootCACert.Leaf)

	mitmPool := x509.NewCertPool()
	mitmPool.AddCert(mitmCACert.Leaf)

	// true server
	l1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	trueCert := mustIssueLocalCert(rootCACert, "echo")
	l1 = tls.NewListener(l1, &tls.Config{
		Certificates: []tls.Certificate{*trueCert},
	})
	defer l1.Close()

	go func() {
		for {
			conn, err := l1.Accept()
			if err != nil {
				break
			}

			go func() {
				defer conn.Close()
				io.Copy(conn, conn) // echo
			}()
		}
	}()

	// MITM server
	l2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer l2.Close()

	go func() {
		for {
			conn, err := l2.Accept()
			if err != nil {
				break
			}

			go func() {
				defer conn.Close()

				tlsConn, err := mitm.NewTLSServer(conn, &mitm.TLSConfig{
					RootCertificate: mitmCACert, // self-signed certificate
					GetClientConfig: func(serverName string, alpnProtocols []string) *tls.Config {
						c := mitm.DefaultGetTLSClientConfig(serverName, alpnProtocols)
						c.RootCAs = defaultPool
						return c
					},
					GetDestination: func(conn net.Conn, serverName string) net.Addr {
						return l1.Addr()
					},
				})
				if err != nil {
					return
				}
				defer tlsConn.Close()

				io.Copy(os.Stdout, tlsConn)
				tlsConn.Write([]byte("Bye!\n"))
			}()
		}
	}()

	clientConn, err := tls.Dial(l2.Addr().Network(), l2.Addr().String(), &tls.Config{
		ServerName: "echo",
		RootCAs:    mitmPool,
	})
	if err != nil {
		panic(err)
	}
	defer clientConn.Close()

	clientConn.Write([]byte("Hello, World!\n"))
	clientConn.CloseWrite()
	io.Copy(os.Stdout, clientConn)
	// Output:
	// Hello, World!
	// Bye!
}
