package dispatcher

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"strings"
	"time"
)

type Server struct {
	HTTP      Handler
	Socks     Handler
	tlsConfig *tls.Config
}

func NewServer(HTTP, Socks Handler) (*Server, error) {
	pv, cert := generateCertificateAndPrivateKey()
	c, err := tls.X509KeyPair(cert, pv)
	return &Server{
		HTTP:  HTTP,
		Socks: Socks,
		tlsConfig: &tls.Config{
			Certificates:       []tls.Certificate{c},
			MaxVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true,
		},
	}, err
}

type Handler interface {
	Handle(net.Conn) error
}

func (s *Server) NewConnection(conn net.Conn) (Handler, net.Conn, error) {
	b := make([]byte, 1)

	_, err := conn.Read(b)
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't read version: %w", err)
	}

	cWrapper := &connectionWrapper{
		Conn: conn,
		b:    b[0],
		e:    nil,
		f:    true,
	}
	switch b[0] {
	case 0x05:
		log.Printf("Socks connection")
		return s.Socks, cWrapper, nil
	case 0x16:
		log.Printf("TLS connection")
		conn := tls.Server(cWrapper, s.tlsConfig)
		return s.NewConnection(conn)
	case 'C':
		log.Printf("Http connection")
		return s.HTTP, cWrapper, nil
	default:
		return nil, nil, fmt.Errorf("unknown version %x", b[0])
	}
}

type connectionWrapper struct {
	net.Conn
	b byte
	e error
	f bool
}

func (c *connectionWrapper) Read(b []byte) (int, error) {
	if c.f {
		c.f = false
		b[0] = c.b
		if len(b) > 1 && c.e == nil {
			n, e := c.Conn.Read(b[1:])
			if e != nil {
				c.Conn.Close()
			}
			return n + 1, e
		} else {
			return 1, c.e
		}
	}
	return c.Conn.Read(b)
}

func generateCertificateAndPrivateKey() (key, cert []byte) {

	host := "proxy"

	var priv interface{}
	var err error
	priv, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	notBefore := time.Now()

	notAfter := notBefore.Add(time.Hour * 24 * 365 * 10)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"ScritchProxy"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	hosts := strings.Split(host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}
	template.IsCA = true
	template.KeyUsage |= x509.KeyUsageCertSign

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.(*rsa.PrivateKey).Public(), priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}
	certOut := &bytes.Buffer{}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("Failed to write data to cert.pem: %v", err)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	keyOut := &bytes.Buffer{}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		log.Fatalf("Failed to write data to key.pem: %v", err)
	}
	return keyOut.Bytes(), certOut.Bytes()
}
