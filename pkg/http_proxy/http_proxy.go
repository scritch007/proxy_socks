package http_proxy

import (
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/elazarl/goproxy"
)

type Handler struct {
	connChan chan net.Conn
	server   *http.Server
}

func NewHandler() *Handler {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true

	server := &http.Server{Addr: fmt.Sprintf(":1080"), Handler: proxy}

	return &Handler{
		server:   server,
		connChan: make(chan net.Conn),
	}
}

func (h *Handler) Start(l net.Listener) error {
	newL := &SplitListener{listener: h.connChan, addr: l.Addr()}
	return h.server.Serve(newL)
}

func (h *Handler) Handle(conn net.Conn) error {
	h.connChan <- conn
	return nil
}

type SplitListener struct {
	listener chan net.Conn
	addr     net.Addr
}

func (l *SplitListener) Close() error {
	return nil
}

func (l *SplitListener) Addr() net.Addr {
	return l.addr
}

func (l *SplitListener) Accept() (net.Conn, error) {
	log.Println("In listener")
	con := <-l.listener
	if con == nil {
		return nil, fmt.Errorf("something went wrong stopping")
	}

	log.Println("HTTP")
	return con, nil
}
