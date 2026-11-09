package chromium

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

const testKey = "trunk-key-0123456789abcdef-xyz"

// exitServer is a relay's stream channel in miniature: TLS with the relay's
// certificate, HTTP/2 CONNECT behind the trunk credential, Naive padding,
// the tunnel handed to a trunk exit. It records whether the ClientHello
// carried GREASE (Chromium does, Go's TLS never).
type exitServer struct {
	addr   string
	roots  string
	grease atomic.Bool
	hellos atomic.Int64
	// strayPort: a hello came from a source port outside the pool's book.
	strayPort atomic.Bool
}

func newExitServer(t *testing.T, x *trunk.Exit) *exitServer {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames: []string{"hk.example"}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	pair, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	s := &exitServer{roots: string(certPEM)}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.addr = ln.Addr().String()
	cfg := &tls.Config{Certificates: []tls.Certificate{pair}, NextProtos: []string{"h2"},
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			s.hellos.Add(1)
			if p := h.Conn.RemoteAddr().(*net.TCPAddr).Port; p < 40000 || p > 41000 {
				s.strayPort.Store(true)
			}
			for _, c := range h.CipherSuites {
				if c&0x0f0f == 0x0a0a {
					s.grease.Store(true)
				}
			}
			return nil, nil
		}}
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(trunk.User+":"+testKey))
	srv := &http.Server{TLSConfig: cfg, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != trunk.Host || r.Header.Get("Proxy-Authorization") != auth || r.Header.Get("Padding") == "" {
			http.Error(w, "site", http.StatusNotFound)
			return
		}
		w.Header().Set("Padding", "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		_ = rc.Flush()
		proxySide, relaySide := net.Pipe()
		go func() { _ = x.ServeMember(relaySide) }()
		go func() { _, _ = io.Copy(proxySide, &unpad{r: r.Body}) }()
		buf := make([]byte, 32<<10)
		frames := 0
		for {
			n, err := proxySide.Read(buf)
			if n > 0 {
				out := buf[:n]
				if frames < 8 {
					frames++
					out = append([]byte{byte(n >> 8), byte(n), 0}, out...)
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
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { srv.Close() })
	return s
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

type echoLocal struct{ addr string }

func (e echoLocal) DialStream(ctx context.Context, port uint16) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", e.addr)
}
func (e echoLocal) DialFlow(context.Context, uint16) (net.Conn, error) {
	return nil, net.ErrClosed
}

// TestChromiumMembers: an entry whose members are Chromium carries a stream
// to the exit and back; the hello the exit saw is Chromium's.
func TestChromiumMembers(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	x := trunk.NewExit(trunk.Config{}, echoLocal{echo.Addr().String()})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go x.Run(ctx)
	srv := newExitServer(t, x)

	ports, _ := trunk.NewPortBook(40000, 41000, time.Minute)
	d := Dialer{Exit: srv.addr, SNI: "hk.example", Key: testKey, Roots: srv.roots}
	entry, err := trunk.NewEntry(trunk.Config{}, 3, d.Dial, ports, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	go entry.Run(ctx)
	deadline := time.Now().Add(20 * time.Second)
	for entry.Session().Stats().Members < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("members did not come up: %+v", entry.Session().Stats())
		}
		time.Sleep(20 * time.Millisecond)
	}
	client, edge := net.Pipe()
	go entry.Session().Carry(edge, 443)
	data := make([]byte, 2<<20)
	_, _ = rand.Read(data)
	go func() { _, _ = client.Write(data) }()
	got := make([]byte, len(data))
	_ = client.SetReadDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.ReadFull(client, got); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("stream through Chromium members: %v", err)
	}
	if srv.strayPort.Load() {
		t.Fatal("Chromium dialled from a port the pool did not choose")
	}
	if !srv.grease.Load() || srv.hellos.Load() < 3 {
		t.Fatalf("the exit saw %d hellos, GREASE %v: not Chromium's", srv.hellos.Load(), srv.grease.Load())
	}
	t.Logf("Chromium %s, %d hellos", Version(), srv.hellos.Load())
}

// TestWrongKey: the relay answers a wrong key with its site; no member.
func TestWrongKey(t *testing.T) {
	x := trunk.NewExit(trunk.Config{}, echoLocal{})
	srv := newExitServer(t, x)
	d := Dialer{Exit: srv.addr, SNI: "hk.example", Key: "trunk-key-WRONG-0123456789abc", Roots: srv.roots}
	if c, err := d.Dial(context.Background(), 40500); err == nil {
		c.Close()
		t.Fatal("a wrong key got a member")
	}
}
