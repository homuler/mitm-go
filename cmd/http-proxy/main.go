package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	mitmhttp "github.com/homuler/mitm-proxy-go/http"
	"github.com/homuler/mitm-proxy-go/tproxy"
)

func main() {
	mitmHttpServer := mitmhttp.NewProxyServer()
	mitmHttpsServer := mitmhttp.NewProxyServer()

	httpLn, err := tproxy.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 8080})
	if err != nil {
		panic(err)
	}
	defer httpLn.Close()

	httpsLn, err := tproxy.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 8443})
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
		fmt.Println("https server is shutting down")
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
