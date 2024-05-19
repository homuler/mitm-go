// Copyright (c) 2024 homuler
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

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
	mitmhttp "github.com/homuler/mitm-go/http"
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

	mitmHttpServer := mitmhttp.NewProxyServer(&mitm.TLSConfig{RootCertificate: &rootCert})
	mitmHttpsServer := mitmhttp.NewProxyServer(&mitm.TLSConfig{RootCertificate: &rootCert})

	httpLn, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 8080})
	if err != nil {
		panic(err)
	}
	defer httpLn.Close()

	httpsLn, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 8443})
	if err != nil {
		panic(err)
	}
	defer httpsLn.Close()

	errCh := make(chan error, 1)

	go func() {
		errCh <- mitmHttpServer.Serve(httpLn)
	}()

	go func() {
		errCh <- mitmHttpsServer.ServeTLS(httpsLn, "rootCACert.pem", "rootCAKey.pem")
	}()

	err = <-errCh
	fmt.Println(err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

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

	wg.Wait()
}
