package hikkari_test

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/client"
	"github.com/m1d1x/hikkari-protocol/internal/testcert"
	"github.com/m1d1x/hikkari-protocol/server"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// dupUDP is another descriptor of the same socket, as a child process
// inherits it.
func dupUDP(t *testing.T, c *net.UDPConn) *net.UDPConn {
	f, err := c.File()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pc, err := net.FilePacketConn(f)
	if err != nil {
		t.Fatal(err)
	}
	return pc.(*net.UDPConn)
}

// A relay's datagram channel handed from one generation to the next on the
// same socket: the old generation's live flow keeps echoing, a new client
// lands on the new generation, and once the old one is gone its client is
// told so rather than left hanging.
func TestDatagramGenerationHandover(t *testing.T) {
	const key = "subscriber-key-0123456789abcdef"
	cert, pool := testcert.New("hk.example")
	dir, err := os.MkdirTemp("/tmp", "hkgen")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	listen := sock.LocalAddr().String()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	echo := echoUDP(t)
	defer echo.Close()

	start := func(gen byte, s *net.UDPConn) (*server.Datagram, *server.GenerationConn) {
		gc, err := server.NewGenerationConn(s, gen, dir)
		if err != nil {
			t.Fatal(err)
		}
		d, err := server.ListenDatagram(ctx, server.DatagramOptions{
			Conn:          gc,
			ConnectionIDs: server.GenerationIDs{Gen: gen},
			Certificate:   func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil },
			Admitter:      &roster{keys: map[string]bool{key: true}, slots: map[int]context.CancelFunc{}},
			Exit:          loopbackExit{},
		})
		if err != nil {
			t.Fatal(err)
		}
		d.SetKeys([]string{key})
		return d, gc
	}
	dial := func() (*client.Datagram, net.Conn) {
		dc, err := client.NewDatagram(client.DatagramOptions{
			Context: ctx, Dialer: N.SystemDialer, Server: M.ParseSocksaddr(listen), Password: key,
			TLS: &testcert.Client{Config: &tls.Config{ServerName: "hk.example", RootCAs: pool}},
		})
		if err != nil {
			t.Fatal(err)
		}
		conn, err := dc.DialContext(ctx, "udp", M.SocksaddrFromNet(echo.LocalAddr()))
		if err != nil {
			t.Fatal(err)
		}
		return dc, conn
	}

	oldGen, newGen := byte(200), byte(201)
	old, oldConn := start(oldGen, sock)
	dc1, c1 := dial()
	defer dc1.Close()
	if got := call(t, c1, 20); got < 19 {
		t.Fatalf("before handover: echoed %d of 20", got)
	}

	// The next generation starts on its own descriptor of the same socket,
	// then the old one hands the socket over.
	next, _ := start(newGen, dupUDP(t, sock))
	defer next.Close()
	oldConn.Drain(newGen)

	if got := call(t, c1, 50); got < 48 {
		t.Fatalf("old generation's flow after handover: echoed %d of 50", got)
	}
	dc2, c2 := dial()
	defer dc2.Close()
	if got := call(t, c2, 50); got < 48 {
		t.Fatalf("new client after handover: echoed %d of 50", got)
	}
	if old.Conns() != 1 || next.Conns() != 1 {
		t.Fatalf("connections: old generation %d, new %d; want 1 and 1", old.Conns(), next.Conns())
	}
	// Both keep working side by side.
	if got := call(t, c1, 20); got < 19 {
		t.Fatalf("old generation's flow later: echoed %d of 20", got)
	}

	// The old generation finishes: its client gets no more echoes, the new
	// generation's client still does.
	old.Close()
	if got := call(t, c1, 5); got != 0 {
		t.Fatalf("finished generation's flow echoed %d", got)
	}
	if got := call(t, c2, 20); got < 19 {
		t.Fatalf("new client after the old generation left: echoed %d of 20", got)
	}
	_ = time.Second
}

func TestGenerationIDs(t *testing.T) {
	for _, gen := range []byte{0, 1, 77, 255} {
		id, err := server.GenerationIDs{Gen: gen}.GenerateConnectionID()
		if err != nil {
			t.Fatal(err)
		}
		b := id.Bytes()
		if len(b) != server.GenerationCIDLen || b[0]^b[1] != gen {
			t.Fatalf("gen %d: id %x", gen, b)
		}
	}
}
