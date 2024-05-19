// Copyright (c) 2024 homuler
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/homuler/mitm-go"
	"github.com/homuler/mitm-go/http"
	"github.com/homuler/mitm-go/http3"
)

var (
	rootCACertPath = flag.String("rootCACert", "", "Root CA certificate file path")
	rootCAKeyPath  = flag.String("rootCAKey", "", "Root CA key file path")
)

func main() {
	flag.Parse()

	if *rootCACertPath == "" {
		panic(errors.New("rootCACert is required"))
	}
	if *rootCAKeyPath == "" {
		panic(errors.New("rootCAKey is required"))
	}

	rootCert, err := mitm.LoadCertificate(*rootCACertPath, *rootCAKeyPath)
	if err != nil {
		panic(err)
	}

	getDest := func(conn net.Conn, serverName string) net.Addr {
		return conn.LocalAddr()
	}

	mitmHttpServer := http.NewTProxyServer(&mitm.TLSConfig{RootCertificate: &rootCert, GetDestination: getDest})
	mitmHttpsServer := http.NewTProxyServer(&mitm.TLSConfig{RootCertificate: &rootCert, GetDestination: getDest})
	mitmHttp3Server := http3.NewTProxyServer(&mitm.QUICConfig{RootCertificate: &rootCert, GetDestination: getDest})

	httpLn, err := mitm.ListenTCPTProxy("tcp", &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 8080})
	if err != nil {
		panic(err)
	}
	defer httpLn.Close()

	httpsLn, err := mitm.ListenTCPTProxy("tcp", &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 8443})
	if err != nil {
		panic(err)
	}
	defer httpsLn.Close()

	http3Ln, err := mitm.ListenUDPTProxy("udp", &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 443})
	if err != nil {
		panic(err)
	}
	defer http3Ln.Close()

	errCh := make(chan error, 1)

	go func() {
		errCh <- mitmHttpServer.Serve(httpLn)
	}()

	go func() {
		errCh <- mitmHttpsServer.ServeTLS(httpsLn, "", "")
	}()

	go func() {
		errCh <- mitmHttp3Server.Serve(http3Ln)
	}()

	err = <-errCh
	fmt.Println(err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		if err := mitmHttpServer.Shutdown(ctx); err != nil {
			fmt.Println(err)
		}
	}()

	go func() {
		defer wg.Done()
		if err := mitmHttpsServer.Shutdown(ctx); err != nil {
			fmt.Println(err)
		}
	}()

	go func() {
		defer wg.Done()
		if err := mitmHttp3Server.Close(); err != nil {
			fmt.Println(err)
		}
	}()

	wg.Wait()
}
