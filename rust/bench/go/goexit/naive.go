package main

// The relay's stream channel for pool members, as the Go trunk/chromium
// test's exit (exitServer) and the relay box (hikkari-control
// edge/trunk_exit.go) answer them: TLS with a certificate for one domain,
// HTTP/2 CONNECT to trunk.Host behind the trunk key, Naive padding of the
// first 8 frames each way, the tunnel handed to trunk.Exit.ServeMember. It
// counts the hellos and whether they carried GREASE (Chromium's do, Go's
// TLS never), so a run shows whose hello reached it.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

type naiveExit struct {
	hellos, grease, tunnels atomic.Int64
}

// serveNaive listens on addr for domain sni and writes the certificate's
// PEM to rootsOut for the entry to trust.
func serveNaive(x *trunk.Exit, addr, sni, key, rootsOut string) (*naiveExit, error) {
	pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames: []string{sni}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &pk.PublicKey, pk)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(pk)
	pair, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(rootsOut, certPEM, 0o644); err != nil {
		return nil, err
	}
	n := &naiveExit{}
	cfg := &tls.Config{Certificates: []tls.Certificate{pair}, NextProtos: []string{"h2"},
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			n.hellos.Add(1)
			for _, c := range h.CipherSuites {
				if c&0x0f0f == 0x0a0a {
					n.grease.Add(1)
					break
				}
			}
			return nil, nil
		}}
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(trunk.User+":"+key))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{TLSConfig: cfg, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != trunk.Host || r.Header.Get("Proxy-Authorization") != auth || r.Header.Get("Padding") == "" {
			http.Error(w, "site", http.StatusNotFound)
			return
		}
		log.Printf("goexit: naive tunnel %d from %s (hellos %d, with GREASE %d)", n.tunnels.Add(1), r.RemoteAddr, n.hellos.Load(), n.grease.Load())
		w.Header().Set("Padding", "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		_ = rc.Flush()
		proxySide, relaySide := net.Pipe()
		go func() { _ = x.ServeMember(relaySide) }()
		go func() { _, _ = io.Copy(proxySide, &unpad{r: r.Body}); proxySide.Close() }()
		buf := make([]byte, 32<<10)
		frames := 0
		for {
			k, err := proxySide.Read(buf)
			if k > 0 {
				out := buf[:k]
				if frames < 8 {
					frames++
					out = append([]byte{byte(k >> 8), byte(k), 0}, out...)
				}
				if _, werr := w.Write(out); werr != nil {
					return
				}
				_ = rc.Flush()
			}
			if err != nil {
				return
			}
		}
	})}
	go func() { log.Print(srv.ServeTLS(ln, "", "")) }()
	return n, nil
}

// unpad strips Naive padding of the first 8 frames.
type unpad struct {
	r    io.Reader
	got  int
	left int
	pad  int
}

func (u *unpad) Read(b []byte) (int, error) {
	for u.got < 8 || u.left > 0 {
		if u.left == 0 {
			var h [3]byte
			if _, err := io.ReadFull(u.r, h[:]); err != nil {
				return 0, err
			}
			u.left, u.pad = int(h[0])<<8|int(h[1]), int(h[2])
			u.got++
			if u.left == 0 {
				if _, err := io.CopyN(io.Discard, u.r, int64(u.pad)); err != nil {
					return 0, err
				}
				continue
			}
		}
		if len(b) > u.left {
			b = b[:u.left]
		}
		n, err := u.r.Read(b)
		u.left -= n
		if u.left == 0 && n > 0 && u.pad > 0 {
			if _, err := io.CopyN(io.Discard, u.r, int64(u.pad)); err != nil {
				return n, err
			}
		}
		return n, err
	}
	return u.r.Read(b)
}
