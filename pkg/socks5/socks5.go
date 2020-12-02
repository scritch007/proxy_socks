package socks5

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
)

var (
	Connect      byte = 0x1
	Bind         byte = 0x2
	UDPAssociate byte = 0x3

	ErrIsHTTP error = fmt.Errorf("request is HTTP")
)

type Conn interface {
	// Read reads data from the connection.
	// Read can be made to time out and return an Error with Timeout() == true
	// after a fixed time limit; see SetDeadline and SetReadDeadline.
	Read(b []byte) (n int, err error)

	// Write writes data to the connection.
	// Write can be made to time out and return an Error with Timeout() == true
	// after a fixed time limit; see SetDeadline and SetWriteDeadline.
	Write(b []byte) (n int, err error)

	// Close closes the connection.
	// Any blocked Read or Write operations will be unblocked and return errors.
	Close() error

	// LocalAddr returns the local network address.
	LocalAddr() net.Addr
}

type Sock struct {
	con    Conn
	remote Conn
	dialer func(network, address string) (Conn, error)
}

func NewHandler() *Handler {
	return &Handler{}
}

type Handler struct {
}

func (h *Handler) Handle(conn net.Conn) error {
	s := NewSockConnection(conn)

	if err := s.Start(); err != nil {
		return fmt.Errorf("couldn't handle socks connection request: %w", err)
	}
	if err := s.Request(); err != nil {
		return fmt.Errorf("couldn't handle request %v", err)

	}
	if err := s.Loop(); err != nil {
		return fmt.Errorf("loop ended with %v", err)
	}
	return nil
}

func NewSockConnection(con Conn) *Sock {
	return &Sock{
		con: con,
		dialer: func(network, address string) (conn Conn, e error) {
			return net.Dial(network, address)
		},
	}
}

func (s *Sock) Start() error {
	b := make([]byte, 1)

	_, err := s.con.Read(b)
	if err != nil {
		return fmt.Errorf("couldn't read version: %w", err)
	}
	switch b[0] {
	case 0x05:
		return s.handleSocks5Connection()
	default:
		return fmt.Errorf("unknown version %x", b[0])
	}
}

func (s *Sock) handleSocks5Connection() error {
	// Check for authentication methods
	b := make([]byte, 1)
	_, err := s.con.Read(b)
	if err != nil {
		return fmt.Errorf("couldn't read number auth methods: %w", err)
	}
	if b[0] == 0 {
		return fmt.Errorf("client should provided at least one method")
	}

	b = make([]byte, int(b[0]))

	_, err = s.con.Read(b)
	if err != nil {
		return fmt.Errorf("couldn't read auth methods: %w", err)
	}
	for _, m := range b {
		if m == 0x0 {
			return s.handleNoAuthConnection()
		}
	}
	return fmt.Errorf("no suitable authentication mechanism")
}

func (s *Sock) handleNoAuthConnection() error {
	_, err := s.con.Write([]byte{0x05, 0x00})
	return err
}

func (s *Sock) Request() error {
	b := make([]byte, 1)
	_, err := s.con.Read(b)
	if err != nil {
		return fmt.Errorf("couldn't read request: %w", err)
	}
	version := b[0]

	switch version {
	case 0x05:
		return s.handlerSocks5Request()
	}
	return fmt.Errorf("version %x not supported", version)
}

func (s *Sock) handlerSocks5Request() error {
	b := make([]byte, 3)
	_, err := s.con.Read(b)
	if err != nil {
		return fmt.Errorf("couldn't read request: %w", err)
	}
	cmd := b[0]
	addressType := b[2]
	var target string
	switch addressType {
	case 0x01:
		b = make([]byte, 4)
		_, err = s.con.Read(b)
		if err != nil {
			return fmt.Errorf("couldn't read ip address: %w", err)
		}
		target = fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
	case 0x03:
		// Read size for the domain name
		b = make([]byte, 1)
		_, err = s.con.Read(b)
		if err != nil {
			return fmt.Errorf("couldn't get domain name size: %w", err)
		}
		b = make([]byte, int(b[0]))
		_, err = s.con.Read(b)
		if err != nil {
			return fmt.Errorf("couldn't get domain name: %w", err)
		}
		target = string(b)
	default:
		return fmt.Errorf("%x not supported yet ", addressType)
	}
	// Read port
	b = make([]byte, 2)
	_, err = s.con.Read(b)
	if err != nil {
		return fmt.Errorf("couldn't read port: %w", err)
	}
	port := binary.BigEndian.Uint16(b)

	switch cmd {
	case Connect:
		return s.handleConnectRequest(fmt.Sprintf("%s:%d", target, port))
	case Bind, UDPAssociate:

	}
	return fmt.Errorf("stop for now at %s:%d cmd %x", target, port, cmd)
}

func (s *Sock) handleConnectRequest(address string) error {
	c, err := s.dialer("tcp", address)
	if err != nil {
		return fmt.Errorf("couldn't connect to client: %w", err)
	}
	split := strings.Split(c.LocalAddr().String(), ":")

	log.Printf("Please reconnect to %s:%s", split[0], split[1])
	bindAddress := net.ParseIP(split[0]).To4()
	portInt, _ := strconv.Atoi(split[1])
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(portInt))
	toWrite := []byte{0x05, 0, 0, 0x01}
	toWrite = append(toWrite, bindAddress...)
	toWrite = append(toWrite, port...)
	_, err = s.con.Write(toWrite)
	if err != nil {
		c.Close()
		return err
	}
	s.remote = c
	return nil
}

func (s *Sock) Loop() error {

	readWrite := func(name string, read, write Conn) error {
		data := make([]byte, 4096)
		n, err := read.Read(data)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		log.Printf("%s read %d", name, n)
		written := 0
		for {
			count, err := write.Write(data[written:n])
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			written += count
			if written == n {
				break
			}
		}
		return nil
	}

	go func() {
		for {
			if err := readWrite("local to out", s.con, s.remote); err != nil {
				log.Printf("%v", err)
				break
			}
		}
	}()
	for {
		if err := readWrite("out to local", s.remote, s.con); err != nil {
			return err
		}
	}
	return nil

}

func (s *Sock) Close() {
	if s.con != nil {
		s.con.Close()
	}
	if s.remote != nil {
		s.remote.Close()
	}
}
