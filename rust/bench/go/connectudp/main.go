// Command connectudp is the bench's reference CONNECT-UDP proxy (RFC 9298
// over HTTP/3, datagrams by RFC 9297) on quic-go: it answers a CONNECT-UDP
// for /.well-known/masque/udp/<host>/<port>/ that carries the expected
// proxy-authorization with 200 and sends every datagram of the request
// stream back as it came. It is the other end the cronet patch of R6.1 is
// checked against (hot path plan, R6.1), an implementation that shares no
// code with Chromium; the exit's own server is the Rust pipe's (R6.2).
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
)

const pathPrefix = "/.well-known/masque/udp/"

// counts are what the proxy saw, printed every 10 s.
type counts struct {
	tunnels, refused, in, out, badContext atomic.Int64
}

func main() {
	listen := flag.String("listen", "127.0.0.1:4433", "UDP address of the HTTP/3 proxy")
	sni := flag.String("sni", "hk.example", "the proxy's domain on its certificate")
	rootsOut := flag.String("roots", "/bench/out/connectudp-roots.pem", "where the certificate's PEM goes for the client")
	auth := flag.String("auth", "basic aGs6YmVuY2g=", "the proxy-authorization a tunnel must carry")
	flag.Parse()

	// The socket first: once the roots are written, a client may come.
	conn, err := net.ListenPacket("udp", *listen)
	if err != nil {
		log.Fatalf("connectudp: listen: %v", err)
	}
	cert, err := certificate(*sni, *rootsOut)
	if err != nil {
		log.Fatalf("connectudp: certificate: %v", err)
	}
	c := &counts{}
	server := &http3.Server{
		TLSConfig:       http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
		QUICConfig:      &quic.Config{EnableDatagrams: true, MaxIdleTimeout: 60 * time.Second},
		EnableDatagrams: true,
		Handler:         http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { c.serve(w, r, *auth) }),
	}
	go c.print()
	log.Printf("connectudp: HTTP/3 proxy on %s for %s, certificate in %s", conn.LocalAddr(), *sni, *rootsOut)
	if err := server.Serve(conn); err != nil {
		log.Fatalf("connectudp: serve: %v", err)
	}
}

// serve takes one CONNECT-UDP and echoes its datagrams until the stream ends.
func (c *counts) serve(w http.ResponseWriter, r *http.Request, auth string) {
	host, port, ok := target(r.URL.EscapedPath())
	if r.Method != http.MethodConnect || r.Proto != "connect-udp" || !ok {
		c.refused.Add(1)
		log.Printf("connectudp: refused %s %s %s", r.Method, r.Proto, r.URL.Path)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if r.Header.Get("Proxy-Authorization") != auth {
		c.refused.Add(1)
		log.Printf("connectudp: refused %s:%d: proxy-authorization %q", host, port, r.Header.Get("Proxy-Authorization"))
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}
	w.Header().Set("Capsule-Protocol", "?1")
	w.WriteHeader(http.StatusOK)
	w.(http.Flusher).Flush()
	c.tunnels.Add(1)
	log.Printf("connectudp: tunnel to %s:%d, user-agent %q", host, port, r.Header.Get("User-Agent"))
	str := w.(http3.HTTPStreamer).HTTPStream()
	go func() {
		// The client ends the tunnel by closing the stream; reading it to
		// the end tells the datagram loop to stop.
		buf := make([]byte, 1024)
		for {
			if _, err := str.Read(buf); err != nil {
				str.CancelRead(0)
				str.Close()
				return
			}
		}
	}()
	ctx := r.Context()
	for {
		d, err := str.ReceiveDatagram(ctx)
		if err != nil {
			log.Printf("connectudp: tunnel to %s:%d ends: %v", host, port, err)
			return
		}
		c.in.Add(1)
		// RFC 9298, section 5: a UDP payload is context ID 0 and the
		// payload; anything else is not ours to echo.
		if len(d) == 0 || d[0] != 0 {
			c.badContext.Add(1)
			continue
		}
		if err := str.SendDatagram(d); err == nil {
			c.out.Add(1)
		}
	}
}

// target parses /.well-known/masque/udp/<host>/<port>/ (RFC 9298, the
// default template).
func target(path string) (string, int, bool) {
	rest, ok := strings.CutPrefix(path, pathPrefix)
	if !ok {
		return "", 0, false
	}
	parts := strings.Split(strings.TrimSuffix(rest, "/"), "/")
	if len(parts) != 2 || parts[0] == "" {
		return "", 0, false
	}
	port, err := strconv.Atoi(parts[1])
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, false
	}
	return parts[0], port, true
}

func (c *counts) print() {
	for range time.Tick(10 * time.Second) {
		fmt.Printf("connectudp tunnels=%d refused=%d in=%d out=%d bad_context=%d\n",
			c.tunnels.Load(), c.refused.Load(), c.in.Load(), c.out.Load(), c.badContext.Load())
	}
}

// certificate makes a self-signed certificate for sni and writes its PEM to
// rootsOut for the client to trust, as goexit's naive relay does.
func certificate(sni, rootsOut string) (tls.Certificate, error) {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames: []string{sni}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &pk.PublicKey, pk)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(pk)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(rootsOut, certPEM, 0o644); err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}

