package pipectl

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

// cronetLib is libcronet built with the CONNECT-UDP patch
// (rust/cronet/chromium): HK_CRONET=/path/to/libcronet.so. The QUIC wire's
// tests need it, a pipe (HK_PIPE) and the Rust exit (HK_EXIT).
func cronetLib(t *testing.T) string {
	lib := os.Getenv("HK_CRONET")
	if lib == "" {
		t.Skip("HK_CRONET is not set: no Chromium for the QUIC wire")
	}
	return lib
}

// selfSigned writes a certificate for hk.example and its key to dir: the
// exit's QUIC wire serves it, the pipe's members trust it as their roots.
func selfSigned(t *testing.T, dir string) (certFile, keyFile, roots string) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "hk.example"},
		DNSNames: []string{"hk.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	c := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, c, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile, string(c)
}

// TestAQuicWireUnderTheBrainCarriesCallsAndRenewsADeadMemberFromTheBook is
// R6.3's (hikkari-client plans/2026-11-11-entry-hot-path-and-unit-economics.md,
// «Труба на Rust»): the Rust exit with a QUIC wire, the pipe under this brain
// with the same wire (FormH3Dgram: four CONNECT-UDP tunnels through
// Chromium's QUIC, opened by the pipe), the selector and a call on it, four
// clients calling through the pipe. Every member's QUIC socket comes from
// the brain's book of ports. One member's path is cut: it dies by its
// stall, the pipe opens a new tunnel from another port of the book, the
// clients go on and no flow is reset.
func TestAQuicWireUnderTheBrainCarriesCallsAndRenewsADeadMemberFromTheBook(t *testing.T) {
	bin, xbin, lib := pipeBin(t), exitBin(t), cronetLib(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	certFile, keyFile, roots := selfSigned(t, t.TempDir())

	x, err := StartExit(ExitConfig{Bin: xbin, Stderr: os.Stderr, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	xc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if err := x.SetWire(ExitWire{ID: 6, Form: FormH3Dgram, Conn: xc, Keys: []string{testKey}, CertFile: certFile, KeyFile: keyFile}); err != nil {
		t.Fatal(err)
	}
	relay := udpEcho(t)
	if err := x.SetPorts([]uint16{relay}); err != nil {
		t.Fatal(err)
	}
	cut := newCutter(t, xc.LocalAddr().(*net.UDPAddr).AddrPort())

	p, err := Start(Config{Bin: bin, Stderr: os.Stderr, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	book := [2]uint16{31000, 31999}
	err = p.SetWire(Wire{ID: 6, Name: "h3dgram", Exit: cut.addr(), Key: testKey, Members: 4,
		H3: &H3Form{SNI: "hk.example", Cronet: lib, Roots: roots, Ports: book}})
	if err != nil {
		t.Fatal(err)
	}
	lc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Listen(0, lc, trunk.ClassVoice, relay, 1); err != nil {
		t.Fatal(err)
	}
	sel := trunk.NewSelector(trunk.SelectorConfig{}, trunk.Wire{ID: 6, Name: "h3dgram", Shape: "browser"})
	go p.Run(ctx, sel, []trunk.WireID{6}, nil, t.Logf)

	up := waitFor(t, 10*time.Second, "the QUIC wire's four members up", func() bool { return wireUp(p, 6, 4) })
	t.Logf("four members up after %v", up.Round(time.Millisecond))
	waitFor(t, 5*time.Second, "voice routed on the QUIC wire", func() bool { return p.Route().Voice == 6 })
	first := cut.firstSeen(nil)
	ports := members(cut)
	if len(first) != 4 || len(ports) != 4 {
		t.Fatalf("members came from %d sockets, want 4: %v", len(ports), ports)
	}
	for a := range ports {
		if a.Port() < book[0] || a.Port() > book[1] {
			t.Fatalf("a member's QUIC socket is at %v, not from the book %v", a, book)
		}
	}
	var clients []*client
	for i := 0; i < 4; i++ {
		clients = append(clients, runClient(ctx, t, lc.LocalAddr().(*net.UDPAddr).AddrPort()))
	}
	time.Sleep(3 * time.Second)
	for i, cl := range clients {
		if g, n := cl.gapMax(time.Now().Add(-2*time.Second), time.Now()); n < 80 || g > 150*time.Millisecond {
			t.Fatalf("client %d heard %d answers in 2 s, longest pause %v", i, n, g)
		}
	}
	tk, _ := p.Tick()
	flows := tk.Flows

	var dead netip.AddrPort
	for a := range ports {
		dead = a
		break
	}
	cutAt := time.Now()
	cut.cutOne(dead)
	back := waitFor(t, 10*time.Second, "a new member from the book", func() bool {
		ps := members(cut)
		return len(ps) == 5 && wireUp(p, 6, 4)
	})
	t.Logf("member at %v cut: four up again after %v", dead, back.Round(time.Millisecond))
	for a := range members(cut) {
		if ports[a] {
			continue
		}
		if a.Port() < book[0] || a.Port() > book[1] || a.Port() == dead.Port() {
			t.Fatalf("the new member's socket is at %v: not from the book %v, or the dead one's port", a, book)
		}
	}
	time.Sleep(2 * time.Second)
	end := time.Now()
	for i, cl := range clients {
		g, n := cl.gapMax(cutAt, end)
		t.Logf("client %d: %d answers over the cut, longest pause %v", i, n, g.Round(time.Millisecond))
		if after, m := cl.gapMax(cutAt.Add(back).Add(time.Second), end); m < 40 || after > 150*time.Millisecond {
			t.Errorf("client %d does not go on after the member came back: %d answers, longest pause %v", i, m, after)
		}
	}
	tk, _ = p.Tick()
	if tk.Flows != flows || flows != 4 {
		t.Errorf("flows at the pipe %d → %d, want 4 all along", flows, tk.Flows)
	}
	for _, w := range tk.Wires {
		t.Logf("wire %d: up %d/%d, in %d, out %d, dgrams %d, dropped %d", w.ID, w.Up, w.Members, w.UpPkts, w.DownPkts, w.Dgrams, w.Dropped)
	}
}

// members is every source address the cutter heard members from.
func members(c *cutter) map[netip.AddrPort]bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[netip.AddrPort]bool{}
	for a := range c.seen {
		out[a] = true
	}
	return out
}
