package hikkari_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/client"
	"github.com/m1d1x/hikkari-protocol/connect"
	"github.com/m1d1x/hikkari-protocol/dup"
	"github.com/m1d1x/hikkari-protocol/internal/testcert"
	"github.com/m1d1x/hikkari-protocol/server"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// countries admits keys as roster does and puts each key's source on its
// session, as a relay that serves several countries does (H8: a key per
// pair of user and country).
type countries struct {
	*roster
	source map[string]connect.Source
}

func (c *countries) Admit(ctx context.Context, key string) (context.Context, func(), func(up, down int), bool) {
	ctx, done, count, ok := c.roster.Admit(ctx, key)
	if !ok {
		return ctx, done, count, ok
	}
	return connect.WithSource(ctx, c.source[key]), done, count, true
}

// addrEcho echoes UDP and TCP on one loopback port and records the source
// address (not port) every packet and stream came from.
type addrEcho struct {
	udp *net.UDPConn
	tcp net.Listener
	mu  sync.Mutex
	got map[netip.Addr]int
}

func newAddrEcho(t *testing.T) *addrEcho {
	u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", u.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	e := &addrEcho{udp: u, tcp: l, got: map[netip.Addr]int{}}
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := u.ReadFromUDPAddrPort(b)
			if err != nil {
				return
			}
			e.saw(from.Addr())
			_, _ = u.WriteToUDPAddrPort(b[:n], from)
		}
	}()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			e.saw(c.RemoteAddr().(*net.TCPAddr).AddrPort().Addr())
			go func() {
				defer c.Close()
				b := make([]byte, 2048)
				n, _ := c.Read(b)
				_, _ = c.Write(b[:n])
			}()
		}
	}()
	t.Cleanup(func() { _ = u.Close(); _ = l.Close() })
	return e
}

func (e *addrEcho) saw(a netip.Addr) {
	e.mu.Lock()
	e.got[a.Unmap()]++
	e.mu.Unlock()
}

// take returns the addresses seen since the last take.
func (e *addrEcho) take() map[netip.Addr]int {
	e.mu.Lock()
	defer e.mu.Unlock()
	got := e.got
	e.got = map[netip.Addr]int{}
	return got
}

// keyStream is the stream channel of one key as the relay's Naive front
// serves a CONNECT to dup.Host, on the session context the front builds.
type keyStream struct {
	hub *server.DupHub
	ctx context.Context
	key string
}

func (s *keyStream) DialContext(ctx context.Context, network string, dest M.Socksaddr) (net.Conn, error) {
	a, b := net.Pipe()
	if network == "tcp" && dup.IsHost(dest.AddrString()) {
		go func() { _ = s.hub.ServeStream(s.ctx, s.key, b) }()
	}
	return a, nil
}

func (s *keyStream) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

// Two keys of one user, two countries: every way a session leaves the relay
// (a UDP flow, a stream over the datagram channel, a voice call copied over
// both carriers) leaves from the source of the key it came with, so the box
// routes each country into its own egress.
func TestTwoCountriesLeaveFromTwoSources(t *testing.T) {
	const keyA, keyB = "subscriber-key-netherlands-0123", "subscriber-key-germany-01234567"
	srcA, srcB := netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.3")
	cert, pool := testcert.New("hk.example")
	admit := &countries{
		roster: &roster{keys: map[string]bool{keyA: true, keyB: true}, slots: map[int]context.CancelFunc{}},
		source: map[string]connect.Source{keyA: {V4: srcA}, keyB: {V4: srcB}},
	}
	listen := freeUDP(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exit := server.NewPolicyExit(nil, nil, nil)
	hub := server.NewDupHub(exit, 0)
	d, err := server.ListenDatagram(ctx, server.DatagramOptions{
		Listen:      listen,
		Certificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil },
		Admitter:    admit,
		Exit:        exit,
		Dup:         hub,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	d.SetKeys([]string{keyA, keyB})
	echo := newAddrEcho(t)
	to := M.SocksaddrFromNet(echo.udp.LocalAddr())

	for _, country := range []struct {
		key  string
		want netip.Addr
	}{{keyA, srcA}, {keyB, srcB}} {
		dc, err := client.NewDatagram(client.DatagramOptions{
			Context: ctx, Dialer: N.SystemDialer, Server: M.ParseSocksaddr(listen), Password: country.key,
			TLS: &testcert.Client{Config: &tls.Config{ServerName: "hk.example", RootCAs: pool}},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer dc.Close()
		only := func(what string) {
			t.Helper()
			got := echo.take()
			if len(got) != 1 || got[country.want] == 0 {
				t.Fatalf("%s of %s: far end saw %v, want only %v", what, country.key, got, country.want)
			}
		}

		conn, err := dc.DialContext(ctx, "udp", to)
		if err != nil {
			t.Fatal(err)
		}
		if got := call(t, conn, 20); got < 19 {
			t.Fatalf("UDP flow of %s echoed %d of 20", country.key, got)
		}
		conn.Close()
		only("a UDP flow")

		stream, err := dc.DialContext(ctx, "tcp", to)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = stream.Write([]byte("hello"))
		_ = stream.SetReadDeadline(time.Now().Add(2 * time.Second))
		if n, err := stream.Read(make([]byte, 16)); n != 5 {
			t.Fatalf("stream of %s: %d bytes, %v", country.key, n, err)
		}
		stream.Close()
		only("a stream over the datagram channel")

		session := connect.WithSource(ctx, admit.source[country.key])
		c := client.New(client.Options{Stream: &keyStream{hub: hub, ctx: session, key: country.key}, Datagram: dc, Dup: true})
		voice, err := c.ListenPacket(ctx, M.Socksaddr{})
		if err != nil {
			t.Fatal(err)
		}
		if got, _, _ := callStats(voice, echo.udp.LocalAddr(), 50, 160, 20*time.Millisecond); got < 48 {
			t.Fatalf("voice of %s echoed %d of 50", country.key, got)
		}
		voice.Close()
		only("a voice call over both carriers")
	}
}
