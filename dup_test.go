package hikkari_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/client"
	"github.com/m1d1x/hikkari-protocol/dup"
	"github.com/m1d1x/hikkari-protocol/internal/testcert"
	"github.com/m1d1x/hikkari-protocol/server"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestFrameAndWindow(t *testing.T) {
	var id dup.Session
	id[0], id[15] = 7, 9
	in := dup.Frame{Kind: dup.KindPacket, Session: id, Seq: 42, Addr: M.ParseSocksaddr("1.2.3.4:3478"), Payload: []byte("opus")}
	raw, err := dup.Append(nil, in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := dup.Decode(raw)
	if err != nil || out.Session != id || out.Seq != 42 || out.Addr.String() != "1.2.3.4:3478" || string(out.Payload) != "opus" {
		t.Fatalf("round trip: %+v %v", out, err)
	}
	named, _ := dup.Append(nil, dup.Frame{Kind: dup.KindPacket, Session: id, Seq: 1, Addr: M.ParseSocksaddr("stun.example:3478")})
	if f, err := dup.Decode(named); err != nil || f.Addr.Fqdn != "stun.example" || len(f.Payload) != 0 {
		t.Fatalf("named: %+v %v", f, err)
	}
	attach, _ := dup.Append(nil, dup.Frame{Kind: dup.KindAttach, Session: id})
	if f, err := dup.Decode(attach); err != nil || f.Kind != dup.KindAttach {
		t.Fatalf("attach: %+v %v", f, err)
	}
	if _, err := dup.Decode(append([]byte{2}, raw[1:]...)); err != dup.ErrVersion {
		t.Fatal("unknown version accepted")
	}
	var b bytes.Buffer
	_ = dup.WriteStream(&b, raw)
	if got, err := dup.ReadStream(&b, make([]byte, dup.MaxFrame)); err != nil || !bytes.Equal(got, raw) {
		t.Fatal("stream framing")
	}

	var w dup.Window
	for _, c := range []struct {
		seq uint64
		ok  bool
	}{{1, true}, {1, false}, {3, true}, {2, true}, {2, false}, {0, false}, {3 + dup.WindowSize, true}, {3, false}, {4, true}, {4, false}, {5 + dup.WindowSize, true}, {4 + dup.WindowSize, true}} {
		if got := w.Accept(c.seq); got != c.ok {
			t.Fatalf("Accept(%d) = %v, want %v", c.seq, got, c.ok)
		}
	}
}

// sourceEcho echoes UDP and records every source it saw and how many packets.
type sourceEcho struct {
	*net.UDPConn
	mu      sync.Mutex
	sources map[string]int
}

func newSourceEcho(t *testing.T) *sourceEcho {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	e := &sourceEcho{UDPConn: c, sources: map[string]int{}}
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := c.ReadFromUDP(b)
			if err != nil {
				return
			}
			e.mu.Lock()
			e.sources[from.String()]++
			e.mu.Unlock()
			_, _ = c.WriteToUDP(b[:n], from)
		}
	}()
	return e
}

func (e *sourceEcho) seen() (int, int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	total := 0
	for _, n := range e.sources {
		total += n
	}
	return len(e.sources), total
}

// hubStream is the stream channel as the relay's Naive front serves a CONNECT
// to dup.Host: the tunnel's far end goes to the hub. stall holds every byte
// of the tunnel, as a stalled TCP path does.
type hubStream struct {
	hub   *server.DupHub
	key   string
	dials atomic.Int64
	stall atomic.Bool
}

func (s *hubStream) DialContext(ctx context.Context, network string, dest M.Socksaddr) (net.Conn, error) {
	if network != "tcp" || !dup.IsHost(dest.AddrString()) {
		a, _ := net.Pipe()
		return a, nil
	}
	s.dials.Add(1)
	a, b := net.Pipe()
	go func() { _ = s.hub.ServeStream(context.Background(), s.key, &stallConn{Conn: b, stall: &s.stall}) }()
	return a, nil
}

func (s *hubStream) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

type stallConn struct {
	net.Conn
	stall *atomic.Bool
}

func (c *stallConn) Read(p []byte) (int, error) {
	for c.stall.Load() {
		time.Sleep(5 * time.Millisecond)
	}
	return c.Conn.Read(p)
}

func (c *stallConn) Write(p []byte) (int, error) {
	for c.stall.Load() {
		time.Sleep(5 * time.Millisecond)
	}
	return c.Conn.Write(p)
}

// lossyDatagram drops everything on the datagram channel while drop is set.
type lossyDatagram struct {
	inner client.Channel
	drop  atomic.Bool
}

func (l *lossyDatagram) DialContext(ctx context.Context, network string, dest M.Socksaddr) (net.Conn, error) {
	return l.inner.DialContext(ctx, network, dest)
}

func (l *lossyDatagram) ListenPacket(ctx context.Context, dest M.Socksaddr) (net.PacketConn, error) {
	p, err := l.inner.ListenPacket(ctx, dest)
	if err != nil {
		return nil, err
	}
	return &lossyConn{PacketConn: p, drop: &l.drop}, nil
}

type lossyConn struct {
	net.PacketConn
	drop *atomic.Bool
}

func (c *lossyConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.drop.Load() {
		return len(p), nil
	}
	return c.PacketConn.WriteTo(p, addr)
}

func (c *lossyConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if err != nil || !c.drop.Load() {
			return n, addr, err
		}
	}
}

// callStats sends n packets of size bytes every gap and counts echoes, the
// longest silence between echoes and duplicates.
func callStats(conn net.PacketConn, to net.Addr, n, size int, gap time.Duration) (got, dups int, worst time.Duration) {
	seen := map[byte]map[byte]bool{}
	var mu sync.Mutex
	done := make(chan struct{})
	last := time.Now()
	go func() {
		defer close(done)
		b := make([]byte, 2048)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			k, _, err := conn.ReadFrom(b)
			if err != nil {
				return
			}
			mu.Lock()
			if k >= 2 {
				if seen[b[0]] == nil {
					seen[b[0]] = map[byte]bool{}
				}
				if seen[b[0]][b[1]] {
					dups++
				} else {
					seen[b[0]][b[1]] = true
					got++
				}
			}
			if d := time.Since(last); d > worst {
				worst = d
			}
			last = time.Now()
			mu.Unlock()
		}
	}()
	for i := 0; i < n; i++ {
		p := make([]byte, size)
		p[0], p[1] = byte(i>>8), byte(i)
		_, _ = conn.WriteTo(p, to)
		time.Sleep(gap)
	}
	<-done
	mu.Lock()
	defer mu.Unlock()
	return got, dups, worst
}

func TestDuplicatedCall(t *testing.T) {
	const key = "subscriber-key-0123456789abcdef"
	cert, pool := testcert.New("hk.example")
	keys := &roster{keys: map[string]bool{key: true}, slots: map[int]context.CancelFunc{}}
	listen := freeUDP(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hub := server.NewDupHub(loopbackExit{}, 0)
	d, err := server.ListenDatagram(ctx, server.DatagramOptions{
		Listen:      listen,
		Certificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil },
		Admitter:    keys,
		Exit:        loopbackExit{},
		Dup:         hub,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	d.SetKeys([]string{key})
	dc, err := client.NewDatagram(client.DatagramOptions{
		Context: ctx, Dialer: N.SystemDialer, Server: M.ParseSocksaddr(listen), Password: key,
		TLS: &testcert.Client{Config: &tls.Config{ServerName: "hk.example", RootCAs: pool}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer dc.Close()
	stream := &hubStream{hub: hub, key: key}
	lossy := &lossyDatagram{inner: dc}
	c := client.New(client.Options{Stream: stream, Datagram: lossy, Dup: true})

	t.Run("bulk stays single", func(t *testing.T) {
		echo := newSourceEcho(t)
		defer echo.Close()
		conn, err := c.ListenPacket(ctx, M.Socksaddr{})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		// 1200 B at 250 pps for 2 s: video-shaped, never duplicated.
		got, dups, _ := callStats(conn, echo.LocalAddr(), 500, 1200, 4*time.Millisecond)
		if got < 450 || dups != 0 || stream.dials.Load() != 0 {
			t.Fatalf("bulk: echoed %d/500, dups %d, stream dials %d", got, dups, stream.dials.Load())
		}
	})

	t.Run("voice goes twice, first copy wins", func(t *testing.T) {
		echo := newSourceEcho(t)
		defer echo.Close()
		conn, err := c.ListenPacket(ctx, M.Socksaddr{})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		got, dups, _ := callStats(conn, echo.LocalAddr(), 150, 160, 20*time.Millisecond)
		sources, total := echo.seen()
		if got < 148 || dups != 0 {
			t.Fatalf("voice: echoed %d/150, dups %d", got, dups)
		}
		if stream.dials.Load() != 1 {
			t.Fatalf("stream copy dials %d, want 1", stream.dials.Load())
		}
		// One exit socket for both carriers, and each packet left it once.
		if sources != 1 || total > 150 {
			t.Fatalf("far end saw %d sources, %d packets", sources, total)
		}

		// The datagram channel goes silent mid-call: the stream copy carries it.
		lossy.drop.Store(true)
		got, dups, worst := callStats(conn, echo.LocalAddr(), 100, 160, 20*time.Millisecond)
		lossy.drop.Store(false)
		if got < 98 || dups != 0 || worst > 150*time.Millisecond {
			t.Fatalf("datagram lost: echoed %d/100, dups %d, worst gap %v", got, dups, worst)
		}
		// The stream channel stalls: the datagram copy carries it.
		stream.stall.Store(true)
		got, dups, worst = callStats(conn, echo.LocalAddr(), 100, 160, 20*time.Millisecond)
		stream.stall.Store(false)
		if got < 98 || dups != 0 || worst > 150*time.Millisecond {
			t.Fatalf("stream stalled: echoed %d/100, dups %d, worst gap %v", got, dups, worst)
		}
		if sources, _ := echo.seen(); sources != 1 {
			t.Fatalf("far end saw %d sources", sources)
		}
	})

	if hub.Sessions() == 0 {
		t.Fatal("hub holds no session")
	}
}
