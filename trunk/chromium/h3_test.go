package chromium

import (
	"context"
	"net"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// TestH3GivesChromiumTheSocketItself: the engine's UDP socket to the exit is
// a plain *net.UDPConn (cronet hands its descriptor to Chromium, no copy in
// Go), TCP and other addresses are refused, and cronet's word that it relayed
// a socket moves the count from direct to relayed.
func TestH3GivesChromiumTheSocketItself(t *testing.T) {
	exit, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer exit.Close()
	s := &h3Sockets{exit: M.SocksaddrFromNet(exit.LocalAddr())}
	c, err := s.DialContext(context.Background(), N.NetworkUDP, s.exit)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, ok := c.(*net.UDPConn); !ok {
		t.Fatalf("socket %T, want *net.UDPConn", c)
	}
	if _, err := s.DialContext(context.Background(), N.NetworkTCP, s.exit); err == nil {
		t.Fatal("TCP dialled")
	}
	if _, err := s.DialContext(context.Background(), N.NetworkUDP, M.ParseSocksaddr("127.0.0.1:1")); err == nil {
		t.Fatal("a stranger dialled")
	}
	(&h3Logger{socks: s}).DebugContext(context.Background(), "relaying UDP connection to ", s.exit)
	if s.direct.Load() != 0 || s.relayed.Load() != 1 || s.tcp.Load() != 1 {
		t.Fatalf("direct %d relayed %d tcp %d", s.direct.Load(), s.relayed.Load(), s.tcp.Load())
	}
	if _, err := h3Congestion("vegas"); err == nil {
		t.Fatal("unknown congestion taken")
	}
}
