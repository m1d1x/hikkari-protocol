// Package h3exit checks the Rust exit's Chromium QUIC wire (spec/trunk.md,
// h3dgram) under the Go brain (trunk/pipectl) with quic-go's HTTP/3 as the
// member: here and not in trunk/pipectl, whose module takes no dependency.
// HK_EXIT=/path/to/hk-exit; without it the test is skipped.
package h3exit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"

	"github.com/m1d1x/hikkari-protocol/trunk/h3dgram"
	"github.com/m1d1x/hikkari-protocol/trunk/pipectl"
)

// testKey is the trunk key the exit's wire takes.
const testKey = "h3exit-test-trunk-key-0123456789"

// h3Wire is the Chromium QUIC wire's id in these tests.
const h3Wire = 6

// The trunk's frames a member of the QUIC wire says (spec/trunk.md), built
// here byte by byte: the Rust exit is checked against the spec, not
// against its own code.
const (
	fHello = 1
	fDgram = 7
	fPing  = 8
	fPong  = 9
)

// TestTheExitServesTheQUICWireTheBrainGives: the brain gives hk-exit an
// h3dgram wire (its socket, the token of the trunk key, its certificate's
// files); a CONNECT-UDP with the token over quic-go's HTTP/3 is a member
// that says its hello and hears the trunk's call back, and one with
// another key's token is answered 404.
func TestTheExitServesTheQUICWireTheBrainGives(t *testing.T) {
	bin := os.Getenv("HK_EXIT")
	if bin == "" {
		t.Skip("HK_EXIT is not set: no exit's pipe to run")
	}
	x, err := pipectl.StartExit(pipectl.ExitConfig{Bin: bin, Stderr: os.Stderr, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { x.Close() })
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	cert, key := testCertificate(t)
	w := pipectl.ExitWire{ID: h3Wire, Form: pipectl.FormH3Dgram, Conn: c, Keys: []string{testKey}, CertFile: cert, KeyFile: key}
	if err := x.SetWire(w); err != nil {
		t.Fatal(err)
	}
	if err := x.SetPorts(nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	addr := c.LocalAddr().String()

	other, _ := h3dgram.Token("another trunk key")
	if _, status := connectUDP(t, ctx, addr, h3dgram.Authorization(other)); status != http.StatusNotFound {
		t.Fatalf("another key's token: status %d, want 404", status)
	}

	tok, err := h3dgram.Token(testKey)
	if err != nil {
		t.Fatal(err)
	}
	rs, status := connectUDP(t, ctx, addr, h3dgram.Authorization(tok))
	if status != http.StatusOK {
		t.Fatalf("the token's CONNECT-UDP: status %d, want 200", status)
	}
	got := make(chan []byte, 256)
	go func() {
		for {
			d, err := rs.ReceiveDatagram(ctx)
			if err != nil {
				close(got)
				return
			}
			got <- d
		}
	}()
	send := func(frames []byte) {
		// Context id 0, then the frames (RFC 9298, 5); quic-go puts the
		// quarter stream id before it.
		if err := rs.SendDatagram(append([]byte{0}, frames...)); err != nil {
			t.Fatalf("send: %v", err)
		}
	}

	session := [16]byte{7, 7, 7}
	hello := append(append([]byte{fHello}, "HKT2"...), session[:]...)
	hello = append(hello, make([]byte, 8)...)
	hello = append(hello, h3Wire, 2) // the wire, flags: a packet member
	answered, back := false, 0
	deadline := time.After(10 * time.Second)
	for seq := uint32(1); back < 50; {
		if !answered {
			send(hello)
		} else if seq <= 50 {
			d := []byte{fDgram}
			d = binary.BigEndian.AppendUint32(d, 1)   // stream
			d = binary.BigEndian.AppendUint32(d, seq) // seq
			d = binary.BigEndian.AppendUint16(d, 0)   // port 0: the trunk's call
			d = binary.BigEndian.AppendUint16(d, 4)
			d = binary.BigEndian.AppendUint32(d, seq)
			send(d)
			seq++
		}
		select {
		case d, ok := <-got:
			if !ok {
				t.Fatal("the request stream ended")
			}
			if len(d) == 0 || d[0] != 0 {
				t.Fatalf("a datagram of context %v", d[:min(1, len(d))])
			}
			for f := d[1:]; len(f) > 0; {
				switch f[0] {
				case fHello:
					answered = true
					f = f[min(len(f), 31):]
				case fPing:
					send(append([]byte{fPong}, f[1:9]...))
					f = f[9:]
				case fDgram:
					n := int(binary.BigEndian.Uint16(f[11:13]))
					if binary.BigEndian.Uint16(f[9:11]) == 0 && n == 4 {
						back++
					}
					f = f[13+n:]
				default:
					t.Fatalf("a frame of type %d", f[0])
				}
			}
		case <-time.After(20 * time.Millisecond):
		case <-deadline:
			t.Fatalf("hello answered %v, the call back %d of 50 times in 10 s", answered, back)
		}
	}
	for end := time.Now().Add(3 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if tk, _ := x.Tick(); tk.Members == 1 {
			break
		}
		if time.Now().After(end) {
			t.Fatal("the exit's tick does not count the member in 3 s")
		}
	}
}

// connectUDP opens a QUIC connection to addr and asks one CONNECT-UDP with
// this proxy-authorization: its request stream and the status.
func connectUDP(t *testing.T, ctx context.Context, addr, auth string) (*http3.RequestStream, int) {
	tc := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}, ServerName: "hk.example"}
	qc, err := quic.DialAddr(ctx, addr, tc, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatalf("QUIC to the exit: %v", err)
	}
	t.Cleanup(func() { qc.CloseWithError(0, "") })
	cc := (&http3.Transport{EnableDatagrams: true}).NewClientConn(qc)
	select {
	case <-cc.ReceivedSettings():
	case <-ctx.Done():
		t.Fatal("no SETTINGS from the exit")
	}
	if s := cc.Settings(); !s.EnableExtendedConnect || !s.EnableDatagrams {
		t.Fatalf("the exit's SETTINGS: extended CONNECT %v, datagrams %v", s.EnableExtendedConnect, s.EnableDatagrams)
	}
	rs, err := cc.OpenRequestStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("https://hk.example" + h3dgram.PathPrefix + "trunk.hikkari.arpa/443/")
	req := &http.Request{Method: http.MethodConnect, Proto: "connect-udp", Host: "hk.example", URL: u,
		Header: http.Header{"Capsule-Protocol": {"?1"}, "Proxy-Authorization": {auth}}}
	if err := rs.SendRequestHeader(req); err != nil {
		t.Fatal(err)
	}
	resp, err := rs.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	return rs, resp.StatusCode
}

// testCertificate writes a self-signed certificate for hk.example and its
// key (PEM) into the test's directory.
func testCertificate(t *testing.T) (cert, key string) {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"hk.example"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &pk.PublicKey, pk)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalPKCS8PrivateKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cert, key = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
		t.Fatal(err)
	}
	return cert, key
}
