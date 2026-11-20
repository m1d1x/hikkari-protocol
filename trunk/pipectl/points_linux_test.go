package pipectl

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

// Border points (points_linux.go; the pipe's points.rs; spec/trunk.md,
// "Border points"): one exit, the core, listening at 127.0.0.1, and two
// border points at 127.0.0.2 and 127.0.0.3 that only forward the core's
// ports to it, as the nft DNAT of hikkari-control internal/entry/border.go
// does. The entry is given the core's own address as 127.0.0.9, where
// nothing answers: the core out of its reach, as the egress that holds
// everyone's sessions is from Russia (hikkari-client
// plans/2026-11-19-border-forwarders.md, G1). The entry holds one session
// with every wire's members spread over the two points.

// point forwards UDP and TCP from its address to the core on the same
// ports, keeping nothing of its own: a border point. It can die, and it can
// freeze (drop every packet both ways for a while, as a VM the hypervisor
// stops: ams3 19.11, 0.15-0.3 s in series of 2-3).
type point struct {
	ip   netip.Addr
	core netip.Addr
	udp  *net.UDPConn
	tcp  net.Listener
	mu   sync.Mutex
	// peers is each entry address's socket to the core; conns every TCP
	// connection both ways.
	peers map[netip.AddrPort]*net.UDPConn
	conns []net.Conn
	// frozenUntil is when the point is heard again (unix ns; 0: never
	// frozen); dead the point killed.
	frozenUntil atomic.Int64
	dead        atomic.Bool
}

func newPoint(t *testing.T, ip, core netip.Addr, wirePort, poolPort uint16) (*point, error) {
	u, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, wirePort)))
	if err != nil {
		return nil, err
	}
	l, err := net.Listen("tcp", netip.AddrPortFrom(ip, poolPort).String())
	if err != nil {
		u.Close()
		return nil, err
	}
	f := &point{ip: ip, core: core, udp: u, tcp: l, peers: map[netip.AddrPort]*net.UDPConn{}}
	t.Cleanup(f.kill)
	go f.upUDP(wirePort)
	go f.acceptTCP(poolPort)
	return f, nil
}

// passes says whether a packet goes through the point now.
func (f *point) passes() bool {
	return !f.dead.Load() && time.Now().UnixNano() >= f.frozenUntil.Load()
}

func (f *point) upUDP(port uint16) {
	b := make([]byte, 2048)
	for {
		n, from, err := f.udp.ReadFromUDPAddrPort(b)
		if err != nil {
			return
		}
		if !f.passes() {
			continue
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		f.mu.Lock()
		c := f.peers[from]
		if c == nil {
			c, err = net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(f.core, port)))
			if err != nil {
				f.mu.Unlock()
				continue
			}
			f.peers[from] = c
			go f.downUDP(c, from)
		}
		f.mu.Unlock()
		_, _ = c.Write(b[:n])
	}
}

func (f *point) downUDP(c *net.UDPConn, to netip.AddrPort) {
	b := make([]byte, 2048)
	for {
		n, err := c.Read(b)
		if err != nil {
			return
		}
		if f.passes() {
			_, _ = f.udp.WriteToUDPAddrPort(b[:n], to)
		}
	}
}

func (f *point) acceptTCP(port uint16) {
	for {
		c, err := f.tcp.Accept()
		if err != nil {
			return
		}
		up, err := net.Dial("tcp", netip.AddrPortFrom(f.core, port).String())
		if err != nil {
			c.Close()
			continue
		}
		f.mu.Lock()
		f.conns = append(f.conns, c, up)
		f.mu.Unlock()
		go f.pipe(up, c)
		go f.pipe(c, up)
	}
}

// pipe copies from src to dst, holding bytes while the point is frozen (a
// frozen VM's TCP waits, it does not drop what it buffered).
func (f *point) pipe(dst, src net.Conn) {
	b := make([]byte, 32<<10)
	for {
		n, err := src.Read(b)
		if err != nil {
			dst.Close()
			return
		}
		for !f.passes() {
			if f.dead.Load() {
				return
			}
			time.Sleep(time.Millisecond)
		}
		if _, err := dst.Write(b[:n]); err != nil {
			src.Close()
			return
		}
	}
}

// freeze drops everything through the point for d.
func (f *point) freeze(d time.Duration) {
	f.frozenUntil.Store(time.Now().Add(d).UnixNano())
}

// kill takes the point off the net at once, as a machine gone.
func (f *point) kill() {
	f.dead.Store(true)
	f.udp.Close()
	f.tcp.Close()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.peers {
		c.Close()
	}
	for _, c := range f.conns {
		c.Close()
	}
	f.peers, f.conns = map[netip.AddrPort]*net.UDPConn{}, nil
}

// peersSeen is how many entry addresses on the wire and connections on the
// pool came through the point.
func (f *point) peersSeen() (udp, tcp int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.peers), len(f.conns) / 2
}

// unreached is the core's own address as the entry is given it: nothing
// answers there.
var unreached = netip.MustParseAddr("127.0.0.9")

// coreAndPoints stands the core at 127.0.0.1 and border points at
// 127.0.0.2 and 127.0.0.3 on one pair of free ports.
func coreAndPoints(t *testing.T, ctx context.Context) (core *receiver, a, b *point, wirePort, poolPort uint16) {
	ipCore := netip.MustParseAddr("127.0.0.1")
	ipA, ipB := netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.3")
	for try := 0; try < 20; try++ {
		wp, pp := freeUDPPort(t, ipCore), freeTCPPort(t, ipCore)
		c, err := newReceiver(t, ctx, ipCore, wp, pp)
		if err != nil {
			continue
		}
		fa, err := newPoint(t, ipA, ipCore, wp, pp)
		if err != nil {
			c.kill()
			continue
		}
		fb, err := newPoint(t, ipB, ipCore, wp, pp)
		if err != nil {
			fa.kill()
			c.kill()
			continue
		}
		return c, fa, fb, wp, pp
	}
	t.Fatal("no pair of ports free on the core and the points")
	return nil, nil, nil, 0, 0
}

// pointsOf is the two points' addresses, as the brain gives them.
func pointsOf(a, b *point) []netip.Addr {
	return []netip.Addr{a.ip, b.ip}
}

// wires gives a pipe the stand's wires to the core's own address: a bare
// UDP wire of 4 members carrying voice, a pool of 4 carrying streams.
func wires(t *testing.T, p *Pipe, wirePort, poolPort uint16) {
	t.Helper()
	if err := p.SetWire(Wire{ID: dgramWire, Name: "udp", Exit: netip.AddrPortFrom(unreached, wirePort), Key: testKey, Members: 4}); err != nil {
		t.Fatal(err)
	}
	if err := p.SetPool(Pool{ID: trunk.PoolWire, Members: 4, Exit: netip.AddrPortFrom(unreached, poolPort)}); err != nil {
		t.Fatal(err)
	}
	p.SetRoute(trunk.Route{Voice: dgramWire, Bulk: trunk.PoolWire})
}

// pointsPipe is a pipe under this brain to the core through the two points
// alone, given before the wires: a bare UDP wire of 4 members carrying
// voice with copies, a pool of 4 carrying streams, a client port of each.
func pointsPipe(t *testing.T, a, b *point, wirePort, poolPort uint16, copies int) (p *Pipe, voice netip.AddrPort, streams string) {
	p, err := Start(Config{Bin: pipeBin(t), Args: []string{"--flow-idle-ms", "2000"}, Stderr: os.Stderr, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	if err := p.SetPoints(pointsOf(a, b)); err != nil {
		t.Fatal(err)
	}
	wires(t, p, wirePort, poolPort)
	waitFor(t, 10*time.Second, "every member up through the two points", func() bool {
		return wireUp(p, dgramWire, 4) && wireUp(p, trunk.PoolWire, 4)
	})
	return p, voice0(t, p, copies), streams0(t, p)
}

// voice0 is the pipe's client port of voice with copies.
func voice0(t *testing.T, p *Pipe, copies int) netip.AddrPort {
	lc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lc.Close() })
	if err := p.Listen(0, lc, trunk.ClassVoice, udpEcho(t), copies); err != nil {
		t.Fatal(err)
	}
	return lc.LocalAddr().(*net.UDPAddr).AddrPort()
}

// streams0 is the pipe's client port of streams.
func streams0(t *testing.T, p *Pipe) string {
	tl, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.TCPListen(1, tl, tcpEcho(t)); err != nil {
		t.Fatal(err)
	}
	return tl.Addr().String()
}

// TestAWiresMembersLiveThroughTwoPointsInOneSession: the core's own
// address does not answer; every member of the wire and of the pool comes
// through one point or the other, two of each through each, and the core
// counts one session: a call and a stream go through it.
func TestAWiresMembersLiveThroughTwoPointsInOneSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	core, a, b, wp, pp := coreAndPoints(t, ctx)
	_, voice, streams := pointsPipe(t, a, b, wp, pp, 1)
	for name, pt := range map[string]*point{"A": a, "B": b} {
		if u, c := pt.peersSeen(); u != 2 || c != 2 {
			t.Errorf("through point %s: %d wire members, %d pool members; want 2 and 2", name, u, c)
		}
	}
	k := newCaller(t, voice)
	k.call()
	s, err := net.Dial("tcp", streams)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := echoed(s, 4<<20, nil); err != nil {
		t.Fatalf("a stream over both points: %v", err)
	}
	time.Sleep(time.Second)
	k.hangUp()
	sent, back, gap := k.heard()
	t.Logf("the call over both points: %d sent, %d back, longest pause %v", sent, back, gap)
	if back < sent*95/100 {
		t.Errorf("the call over both points: %d of %d back", back, sent)
	}
	if n, _ := core.x.Stats(); n != 1 {
		t.Errorf("the core counts %d sessions, want 1: the members of both points in one", n)
	}
}

// TestAPointsDeathCutsNothing (plans/2026-11-19-border-forwarders.md, G1:
// "a point's death cuts nothing"): under a call and a stream, point B dies.
// Its members are buried and dial it in vain; the stream goes on byte for
// byte on point A's members, the call's flow is the same at the core, and
// nothing is cut.
func TestAPointsDeathCutsNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	core, a, b, wp, pp := coreAndPoints(t, ctx)
	p, voice, streams := pointsPipe(t, a, b, wp, pp, 1)
	k := newCaller(t, voice)
	k.call()
	s, err := net.Dial("tcp", streams)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := echoOpen(s, 64<<10); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)

	b.kill()
	waitFor(t, 5*time.Second, "point B's members buried", func() bool {
		return wireUp(p, dgramWire, 2) && wireUp(p, trunk.PoolWire, 2)
	})
	if err := echoOpen(s, 4<<20); err != nil {
		t.Fatalf("the stream after point B died: %v", err)
	}
	time.Sleep(time.Second)
	k.hangUp()
	sent, back, gap := k.heard()
	t.Logf("the call across point B's death: %d sent, %d back, longest pause %v", sent, back, gap)
	n, st := core.x.Stats()
	if st.Flows != 1 || st.StreamsOpened != 1 || st.StreamsReset != 0 || n != 1 {
		t.Errorf("the core after point B died: %d flows, %d streams opened, %d reset, %d sessions; want 1, 1, 0, 1: nothing cut", st.Flows, st.StreamsOpened, st.StreamsReset, n)
	}
}

// TestAFrozenPointIsNotHeardInACall (plans/2026-11-19-border-forwarders.md,
// G1): point B freezes as ams3 did on 19.11 (0.3 s, in series of three
// 150 ms apart, again and again) under a call of two copies and a stream.
// Each datagram has a copy through point A while B holds the other: the
// call is not heard to pause past 60 ms, and nothing is cut.
func TestAFrozenPointIsNotHeardInACall(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	core, a, b, wp, pp := coreAndPoints(t, ctx)
	_, voice, streams := pointsPipe(t, a, b, wp, pp, 2)
	k := newCaller(t, voice)
	k.call()
	s, err := net.Dial("tcp", streams)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := echoOpen(s, 64<<10); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	for series := 0; series < 4; series++ {
		for i := 0; i < 3; i++ {
			b.freeze(300 * time.Millisecond)
			time.Sleep(450 * time.Millisecond)
		}
		time.Sleep(time.Second)
	}
	if err := echoOpen(s, 4<<20); err != nil {
		t.Fatalf("the stream after the freezes: %v", err)
	}
	k.hangUp()
	sent, back, gap := k.heard()
	t.Logf("the call across 12 freezes of point B: %d sent, %d back, longest pause %v", sent, back, gap)
	if gap > 60*time.Millisecond {
		t.Errorf("the call paused %v under point B's freezes, want at most 60 ms", gap)
	}
	if back < sent*99/100 {
		t.Errorf("the call: %d of %d back", back, sent)
	}
	n, st := core.x.Stats()
	if st.Flows != 1 || st.StreamsOpened != 1 || st.StreamsReset != 0 || n != 1 {
		t.Errorf("the core after the freezes: %d flows, %d streams opened, %d reset, %d sessions; want 1, 1, 0, 1", st.Flows, st.StreamsOpened, st.StreamsReset, n)
	}
}

// TestPointsGivenLateBringTheMembersUpAtOnce (spec/trunk.md, "Border
// points"): the wires come first, to the core's own address where nothing
// answers, and the pool's members fail for 10 s, their backoff grown to its
// most (5 s); then the points come. Every member is up through them within
// 2 s: the backoff was the old address's.
func TestPointsGivenLateBringTheMembersUpAtOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	_, a, b, wp, pp := coreAndPoints(t, ctx)
	p, err := Start(Config{Bin: pipeBin(t), Stderr: os.Stderr, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	wires(t, p, wp, pp)
	time.Sleep(10 * time.Second)
	if n := upNow(t, p, dgramWire) + upNow(t, p, trunk.PoolWire); n != 0 {
		t.Fatalf("%d member(s) came up at the core's own address, which nothing answers", n)
	}
	at := time.Now()
	if err := p.SetPoints(pointsOf(a, b)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 2*time.Second, "every member up through the points given late", func() bool {
		return wireUp(p, dgramWire, 4) && wireUp(p, trunk.PoolWire, 4)
	})
	t.Logf("every member up through the points %v after they came", time.Since(at).Round(time.Millisecond))
}

// upNow is how many members of wire id are up by the pipe's latest
// tick, which is fresh.
func upNow(t *testing.T, p *Pipe, id trunk.WireID) int {
	t.Helper()
	tk, at := p.Tick()
	if time.Since(at) > 2*time.Second {
		t.Fatal("no fresh tick from the pipe")
	}
	for _, w := range tk.Wires {
		if w.ID == id {
			return w.Up
		}
	}
	return 0
}
