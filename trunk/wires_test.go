package trunk

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Wires in tests: the pool and a second stream wire on net.Pipe, a packet
// wire on an in-memory datagram pipe that may lose packets. Each wire can be
// cut (its members black-holed, its dials failing) and counts the bytes its
// members carried from the entry and back.

const (
	testQuic WireID = 1
	testUDP  WireID = 2
)

type testWire struct {
	cut      atomic.Bool
	out, in  atomic.Int64 // bytes the entry wrote / read on this wire's members
	dials    atomic.Int64
	lossPerK atomic.Int64 // packet wire: datagrams lost per 1000, each way
}

type wireHarness struct {
	exit  *Exit
	entry *Entry
	wires map[WireID]*testWire
}

func newWireHarness(t *testing.T, cfg Config, pool, quic, udp int) *wireHarness {
	t.Helper()
	h := &wireHarness{exit: NewExit(cfg, newLoopLocal(t, nil)), wires: map[WireID]*testWire{PoolWire: {}, testQuic: {}, testUDP: {}}}
	ports, err := NewPortBook(20000, 30000, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	replaceSpread = 20 * time.Millisecond
	streamDial := func(id WireID) Dial {
		tw := h.wires[id]
		return func(ctx context.Context, port int) (io.ReadWriteCloser, error) {
			tw.dials.Add(1)
			if tw.cut.Load() {
				return nil, ErrSilent
			}
			a, b := net.Pipe()
			go func() { _ = h.exit.ServeMember(b) }()
			return &wireConn{Conn: a, w: tw, closed: make(chan struct{})}, nil
		}
	}
	logf := func(format string, a ...any) { t.Logf(format, a...) }
	h.entry, err = NewEntry(cfg, pool, streamDial(PoolWire), ports, logf)
	if err != nil {
		t.Fatal(err)
	}
	if quic > 0 {
		if err := h.entry.AddWire(Wire{ID: testQuic, Name: "quic", Shape: "browser", Members: quic, Dial: streamDial(testQuic), Streams: true}); err != nil {
			t.Fatal(err)
		}
	}
	if udp > 0 {
		tw := h.wires[testUDP]
		dial := func(ctx context.Context, port int) (io.ReadWriteCloser, error) {
			tw.dials.Add(1)
			if tw.cut.Load() {
				return nil, ErrSilent
			}
			a, b := packetPipe(tw)
			go func() { _ = h.exit.ServeMember(b) }()
			return &wireConn{Conn: a, w: tw, closed: make(chan struct{})}, nil
		}
		if err := h.entry.AddWire(Wire{ID: testUDP, Name: "udp", Shape: "random", Members: udp, Dial: dial, Packet: true}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	exitCtx, exitCancel := context.WithCancel(context.Background())
	go h.exit.Run(exitCtx)
	ran := make(chan struct{})
	go func() { h.entry.Run(ctx); close(ran) }()
	t.Cleanup(func() { cancel(); <-ran; exitCancel() })
	waitFor(t, func() bool {
		w := h.entry.Wires()
		return w[PoolWire].Members == pool && w[testQuic].Members == quic && w[testUDP].Members == udp
	})
	return h
}

func (h *wireHarness) carry() net.Conn {
	client, edge := net.Pipe()
	go h.entry.Session().Carry(edge, 443)
	return client
}

// wireConn is the entry's end of a member of a test wire: it counts, and a
// cut wire swallows what is written and gives nothing to read.
type wireConn struct {
	net.Conn
	w      *testWire
	closed chan struct{}
	once   sync.Once
}

func (c *wireConn) Write(p []byte) (int, error) {
	if c.w.cut.Load() {
		return len(p), nil
	}
	c.w.out.Add(int64(len(p)))
	return c.Conn.Write(p)
}

func (c *wireConn) Read(p []byte) (int, error) {
	if c.w.cut.Load() {
		<-c.closed
		return 0, net.ErrClosed
	}
	n, err := c.Conn.Read(p)
	if c.w.cut.Load() {
		<-c.closed
		return 0, net.ErrClosed
	}
	c.w.in.Add(int64(n))
	return n, err
}

func (c *wireConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// packetPipe is two ends of a datagram path: a write is one datagram, a
// read gives one whole (cut to the buffer, as UDP does), and the wire's
// loss drops datagrams each way.
func packetPipe(w *testWire) (net.Conn, net.Conn) {
	ab, ba := make(chan []byte, 1024), make(chan []byte, 1024)
	done := make(chan struct{})
	var once sync.Once
	shut := func() { once.Do(func() { close(done) }) }
	return &packetEnd{in: ba, out: ab, done: done, shut: shut, w: w}, &packetEnd{in: ab, out: ba, done: done, shut: shut, w: w}
}

type packetEnd struct {
	net.Conn // nil: only what a member uses is here
	in, out  chan []byte
	done     chan struct{}
	shut     func()
	w        *testWire
}

func (p *packetEnd) Write(b []byte) (int, error) {
	select {
	case <-p.done:
		return 0, net.ErrClosed
	default:
	}
	if l := p.w.lossPerK.Load(); l > 0 && rand.Int64N(1000) < l {
		return len(b), nil
	}
	select {
	case p.out <- append([]byte(nil), b...):
	default: // a full queue drops, as a socket's buffer does
	}
	return len(b), nil
}

func (p *packetEnd) Read(b []byte) (int, error) {
	select {
	case d := <-p.in:
		return copy(b, d), nil
	case <-p.done:
		return 0, net.ErrClosed
	}
}

func (p *packetEnd) Close() error { p.shut(); return nil }

func TestHelloKinds(t *testing.T) {
	var id SessionID
	id[0] = 7
	for _, k := range []memberKind{poolKind, {wire: testQuic, streams: true}, {wire: testUDP, packet: true}} {
		b := appendHelloFor(nil, id, Epoch{1}, k)
		if k.t1() != (string(b[1:5]) == magic) {
			t.Fatalf("%+v: hello %q", k, b[1:5])
		}
		f, err := readFrame(bufio.NewReader(bytes.NewReader(b)))
		if err != nil || f.typ != fHello || f.session != id || f.kind != k || f.epoch[0] != 1 {
			t.Fatalf("%+v: read back %+v, %v", k, f, err)
		}
	}
}

// TestStreamsFollowTheRoute: with bulk routed to the second wire, a
// stream's bytes go there both ways (the exit answers on the wire the entry
// used); routed back to the pool, they go on the pool.
func TestStreamsFollowTheRoute(t *testing.T) {
	h := newWireHarness(t, Config{}, 2, 2, 0)
	pool, quic := h.wires[PoolWire], h.wires[testQuic]
	h.entry.SetRoute(Route{Voice: AnyWire, Bulk: testQuic})
	c := h.carry()
	defer c.Close()
	p0, q0, pi0, qi0 := pool.out.Load(), quic.out.Load(), pool.in.Load(), quic.in.Load()
	roundTrip(t, c, 2<<20)
	if q, p := quic.out.Load()-q0, pool.out.Load()-p0; q < 2<<20 || p > 64<<10 {
		t.Fatalf("out: quic %d, pool %d bytes: the stream did not follow the route", q, p)
	}
	if q, p := quic.in.Load()-qi0, pool.in.Load()-pi0; q < 2<<20 || p > 64<<10 {
		t.Fatalf("in: quic %d, pool %d bytes: the exit did not answer on the entry's wire", q, p)
	}
	h.entry.SetRoute(Route{Voice: AnyWire, Bulk: PoolWire})
	p0, q0 = pool.out.Load(), quic.out.Load()
	roundTrip(t, c, 2<<20)
	if q, p := quic.out.Load()-q0, pool.out.Load()-p0; p < 2<<20 || q > 64<<10 {
		t.Fatalf("after the route went back: quic %d, pool %d bytes", q, p)
	}
}

// TestStreamMovesOffACutWire: the wire carrying a transfer is cut in the
// middle of it, its new dials failing too. The stream's chunks go again on
// the pool and the transfer completes: the client's connection never knew.
func TestStreamMovesOffACutWire(t *testing.T) {
	h := newWireHarness(t, Config{Stall: 100 * time.Millisecond, Quiet: 10 * time.Second}, 2, 2, 0)
	h.entry.SetRoute(Route{Voice: AnyWire, Bulk: testQuic})
	c := h.carry()
	defer c.Close()
	roundTrip(t, c, 1<<20)
	done := make(chan struct{})
	go func() {
		defer close(done)
		roundTrip(t, c, 16<<20)
	}()
	waitFor(t, func() bool { return h.wires[testQuic].out.Load() > 4<<20 })
	h.wires[testQuic].cut.Store(true)
	<-done
	st := h.entry.Session().Stats()
	if st.StreamsReset != 0 {
		t.Fatalf("the stream was reset: %+v", st)
	}
	if st.Resent == 0 {
		t.Fatalf("nothing was sent again: the cut did not hit the transfer: %+v", st)
	}
	if w := h.entry.Wires(); w[testQuic].Members != 0 {
		t.Fatalf("the cut wire still has %d member(s) up", w[testQuic].Members)
	}
}

// TestVoiceOnAPacketWire: a lossy packet wire carries the voice class; it
// keeps its members through lost datagrams, and the pool carries none of the
// call.
func TestVoiceOnAPacketWire(t *testing.T) {
	h := newWireHarness(t, Config{}, 2, 0, 2)
	udp, pool := h.wires[testUDP], h.wires[PoolWire]
	udp.lossPerK.Store(30)
	h.entry.SetRoute(Route{Voice: testUDP, Bulk: PoolWire})
	var got atomic.Int64
	f := h.entry.Session().OpenFlowWith(4000, FlowOptions{Copies: 1, Class: ClassVoice, Pin: AnyWire}, func([]byte) { got.Add(1) }, nil)
	defer f.Close()
	p0 := pool.out.Load()
	payload := bytes.Repeat([]byte{0xa5}, 160)
	for i := 0; i < 300; i++ {
		f.Send(payload)
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	// 3% lost each way: about 6% of the round trips.
	if n := got.Load(); n < 250 || n > 300 {
		t.Fatalf("%d of 300 came back", n)
	}
	if p := pool.out.Load() - p0; p > 300*20 {
		t.Fatalf("the pool carried %d bytes of the call", p)
	}
	if st := h.entry.Session().Stats(); st.MembersStall != 0 {
		t.Fatalf("lost datagrams buried packet members: %+v", st)
	}
	// Streams never go on a packet wire: routed there, bulk takes the pool.
	h.entry.SetRoute(Route{Voice: testUDP, Bulk: testUDP})
	c := h.carry()
	defer c.Close()
	roundTrip(t, c, 1<<20)
}

// TestPinnedCallHoldsToItsWire: the call of a wire is that wire's alone. Cut,
// its datagrams are lost, not carried by the pool: the call must hear the
// cut.
func TestPinnedCallHoldsToItsWire(t *testing.T) {
	h := newWireHarness(t, Config{Stall: 100 * time.Millisecond}, 2, 0, 1)
	var got atomic.Int64
	f := h.entry.Session().OpenFlowWith(EchoPort, FlowOptions{Copies: 1, Pin: testUDP}, func([]byte) { got.Add(1) }, nil)
	defer f.Close()
	send := func(n int) {
		for i := 0; i < n; i++ {
			f.Send(make([]byte, 64))
			time.Sleep(2 * time.Millisecond)
		}
		time.Sleep(100 * time.Millisecond)
	}
	send(50)
	if n := got.Load(); n != 50 {
		t.Fatalf("%d of 50 came back on a clean wire", n)
	}
	h.wires[testUDP].cut.Store(true)
	waitFor(t, func() bool { return h.entry.Wires()[testUDP].Members == 0 })
	before, p0 := got.Load(), h.wires[PoolWire].out.Load()
	send(50)
	if n := got.Load() - before; n != 0 {
		t.Fatalf("%d came back with the wire cut", n)
	}
	if p := h.wires[PoolWire].out.Load() - p0; p > 50*20 {
		t.Fatalf("the pool carried %d bytes of a pinned call", p)
	}
}
