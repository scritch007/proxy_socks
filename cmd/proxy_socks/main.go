package main

import (
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/scritch007/proxy_socks/pkg/dispatcher"

	"github.com/scritch007/proxy_socks/pkg/http_proxy"

	"github.com/scritch007/proxy_socks/pkg/socks5"

	"github.com/elazarl/goproxy"
)

var proxy *goproxy.ProxyHttpServer

func main() {
	wg := sync.WaitGroup{}
	wg.Add(2)

	l, err := net.Listen("tcp", ":1080")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer l.Close()

	httpHandler := http_proxy.NewHandler()
	socksHandler := socks5.NewHandler()

	router, err := dispatcher.NewServer(
		httpHandler,
		socksHandler,
	)
	if err != nil {
		panic(err)
	}

	go func() {
		httpHandler.Start(l)
		wg.Done()
		log.Printf("Exiting http proxy")
	}()
	go func() {

		for {
			log.Printf("Accepting new connection")
			c, err := l.Accept()
			if err != nil {
				break
			}
			log.Printf("Connection accepted")

			h, conn, err := router.NewConnection(c)
			if err != nil {
				log.Printf("Couldn't handle connection: %w", err)
				continue
			}
			go func() {
				h.Handle(conn)
				conn.Close()
			}()
		}

		wg.Done()
	}()

	wg.Wait()
}

var (
	addr = "127.0.0.1:8080"
)
