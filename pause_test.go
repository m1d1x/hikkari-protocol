package hikkari_test

import (
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/client"
	"github.com/m1d1x/hikkari-protocol/internal/testcert"
	"github.com/m1d1x/hikkari-protocol/observe"
	"github.com/m1d1x/hikkari-protocol/server"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// heldDown holds the datagram channel's answers to the client while hold is
// set and lets them through all at once after: a path that stalls one way.
type heldDown struct {
	inner client.Channel
	hold  atomic.Bool
}

func (h *heldDown) DialContext(ctx context.Context, network string, dest M.Socksaddr) (net.Conn, error) {
	return h.inner.DialContext(ctx, network, dest)
}

func (h *heldDown) ListenPacket(ctx context.Context, dest M.Socksaddr) (net.PacketConn, error) {
	p, err := h.inner.ListenPacket(ctx, dest)
	if err != nil {
		return nil, err
	}
	return &heldConn{PacketConn: p, hold: &h.hold}, nil
}

type heldConn struct {
	net.PacketConn
	hold *atomic.Bool
}

func (c *heldConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	for c.hold.Load() {
		time.Sleep(time.Millisecond)
	}
	return n, addr, err
}

// TestAPauseOnTheWayShowsAtOneEndOnly sends video-sized packets every 20 ms
// through a relay and holds the way down for 400 ms. The relay takes the
// answers in from the service without that pause; the client hands them out
// with it: the pause is the path's, and v1.06 tells it by the two ends.
func TestAPauseOnTheWayShowsAtOneEndOnly(t *testing.T) {
	const key = "subscriber-key-0123456789abcdef"
	cert, pool := testcert.New("hk.example")
	keys := &roster{keys: map[string]bool{key: true}, slots: map[int]context.CancelFunc{}}
	listen := freeUDP(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relayBook, clientBook := observe.NewBook(), observe.NewBook()
	hub := server.NewDupHub(loopbackExit{}, 0)
	hub.Observe(relayBook)
	d, err := server.ListenDatagram(ctx, server.DatagramOptions{
		Listen:      listen,
		Certificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil },
		Admitter:    keys,
		Exit:        loopbackExit{},
		Dup:         hub,
		Book:        relayBook,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	d.SetKeys([]string{key})
	dc, err := client.NewDatagram(client.DatagramOptions{
		Context: ctx, Dialer: N.SystemDialer, Server: M.ParseSocksaddr(listen), Password: key,
		TLS:  &testcert.Client{Config: &tls.Config{ServerName: "hk.example", RootCAs: pool}},
		Book: clientBook,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer dc.Close()
	held := &heldDown{inner: dc}
	c := client.New(client.Options{Stream: &hubStream{hub: hub, key: key}, Datagram: held, Dup: true, Book: clientBook})
	echo := newSourceEcho(t)
	defer echo.Close()
	conn, err := c.ListenPacket(ctx, M.Socksaddr{})
	if err != nil {
		t.Fatal(err)
	}
	if got, _, _ := callStats(conn, echo.LocalAddr(), 50, 1000, 20*time.Millisecond); got < 48 {
		t.Fatalf("before the hold: %d/50", got)
	}
	go func() {
		time.Sleep(200 * time.Millisecond)
		held.hold.Store(true)
		time.Sleep(400 * time.Millisecond)
		held.hold.Store(false)
	}()
	if got, _, _ := callStats(conn, echo.LocalAddr(), 50, 1000, 20*time.Millisecond); got < 40 {
		t.Fatalf("through the hold: %d/50", got)
	}
	_ = conn.Close()

	relay := relayBook.Take()[key]
	own := clientBook.Take()[client.Group]
	if relay == nil || relay.Pauses == nil || own == nil || own.Pauses == nil {
		t.Fatalf("no pauses: relay %+v, client %+v", relay, own)
	}
	in, out := relay.Pauses.In.Video, own.Pauses.Out.Video
	t.Logf("relay in %+v, client out %+v, relay out %+v, client in %+v", in, out, relay.Pauses.Out.Video, own.Pauses.In.Video)
	// The test's own wait between its two calls is a pause at every point;
	// it cancels between the ends. Only the hold is the path's.
	if in.Packets < 90 || out.Over300 != in.Over300+1 || out.MSOver150-in.MSOver150 < 300 {
		t.Fatalf("the hold is not the one pause the client added: relay in %+v, client out %+v", in, out)
	}
	if up, from := relay.Pauses.Out.Video, own.Pauses.In.Video; up.Over300 != from.Over300 {
		t.Fatalf("the way up added a pause: client in %+v, relay out %+v", from, up)
	}
}
