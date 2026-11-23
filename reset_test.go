package hikkari_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/client"
	"github.com/m1d1x/hikkari-protocol/internal/testcert"
	"github.com/m1d1x/hikkari-protocol/server"
	"github.com/sagernet/quic-go"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// udpSwitch forwards a client's datagrams to one relay and, on move, to
// another, closing the old bindings: what a cascade's entry does when it
// moves a country's flows to another country's relay (hikkari-control
// trunkentry auto_egress.go).
type udpSwitch struct {
	ln       *net.UDPConn
	mu       sync.Mutex
	to       netip.AddrPort
	bindings map[netip.AddrPort]*net.UDPConn
}

func newUDPSwitch(t *testing.T, to netip.AddrPort) *udpSwitch {
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	s := &udpSwitch{ln: ln, to: to, bindings: map[netip.AddrPort]*net.UDPConn{}}
	go s.serve()
	return s
}

func (s *udpSwitch) addr() string { return s.ln.LocalAddr().String() }

func (s *udpSwitch) serve() {
	b := make([]byte, 2048)
	for {
		n, peer, err := s.ln.ReadFromUDPAddrPort(b)
		if err != nil {
			return
		}
		s.mu.Lock()
		up := s.bindings[peer]
		if up == nil {
			if up, err = net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(s.to)); err == nil {
				s.bindings[peer] = up
				go s.back(peer, up)
			}
		}
		s.mu.Unlock()
		if up != nil {
			_, _ = up.Write(b[:n])
		}
	}
}

func (s *udpSwitch) back(peer netip.AddrPort, up *net.UDPConn) {
	b := make([]byte, 2048)
	for {
		n, err := up.Read(b)
		if err != nil {
			return
		}
		_, _ = s.ln.WriteToUDPAddrPort(b[:n], peer)
	}
}

func (s *udpSwitch) move(to netip.AddrPort) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.to = to
	for peer, up := range s.bindings {
		up.Close()
		delete(s.bindings, peer)
	}
}

func (s *udpSwitch) close() {
	s.move(s.to)
	s.ln.Close()
}

// A client whose packets are moved to another relay of the same group gets
// a stateless reset from it and carries UDP again within seconds; with keys
// of their own the second relay stays silent and the client waits out its
// idle timeout (30 s), as on the stand 2026-11-23 (H8, UDP 30 s).
func TestARelayOfTheGroupResetsAMovedClientsConnection(t *testing.T) {
	cert, pool := testcert.New("hk.example")
	groupKey, err := server.GroupResetKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		keys   [2]*quic.StatelessResetKey
		within time.Duration
		moves  bool
	}{
		{"one group key", [2]*quic.StatelessResetKey{groupKey, groupKey}, 3 * time.Second, true},
		{"keys of their own", [2]*quic.StatelessResetKey{nil, nil}, 3 * time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := movedClientCarriesAgain(t, cert, pool, tc.keys, tc.within)
			if got != tc.moves {
				t.Fatalf("UDP through the second relay within %s: %t, want %t", tc.within, got, tc.moves)
			}
		})
	}
}

func movedClientCarriesAgain(t *testing.T, cert tls.Certificate, pool *x509.CertPool, keys [2]*quic.StatelessResetKey, within time.Duration) bool {
	const key = "subscriber-key-0123456789abcdef"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	echo := echoUDP(t)
	defer echo.Close()
	var relays [2]netip.AddrPort
	for i := range relays {
		listen := freeUDP(t)
		d, err := server.ListenDatagram(ctx, server.DatagramOptions{
			Listen:            listen,
			ConnectionIDs:     server.GenerationIDs{Gen: byte(10 + i)},
			StatelessResetKey: keys[i],
			Certificate:       func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil },
			Admitter:          &roster{keys: map[string]bool{key: true}, slots: map[int]context.CancelFunc{}},
			Exit:              loopbackExit{},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		d.SetKeys([]string{key})
		relays[i] = netip.MustParseAddrPort(listen)
	}
	sw := newUDPSwitch(t, relays[0])
	defer sw.close()
	dc, err := client.NewDatagram(client.DatagramOptions{
		Context: ctx, Dialer: N.SystemDialer, Server: M.ParseSocksaddr(sw.addr()), Password: key,
		TLS: &testcert.Client{Config: &tls.Config{ServerName: "hk.example", RootCAs: pool}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer dc.Close()
	dest := M.SocksaddrFromNet(echo.LocalAddr())
	first, err := dc.DialContext(ctx, "udp", dest)
	if err != nil {
		t.Fatal(err)
	}
	if got := call(t, first, 10); got < 9 {
		t.Fatalf("through the first relay: echoed %d of 10", got)
	}
	first.Close()

	sw.move(relays[1])
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		conn, err := dc.DialContext(ctx, "udp", dest)
		if err == nil {
			got := call(t, conn, 3)
			conn.Close()
			if got > 0 {
				return true
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}
