package trunk

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Live datagrams on wires of two fates (fates.go, spec/trunk.md Datagrams):
// the night of 14.11 in memory. The packet wire loses datagrams to the exit
// by Gilbert's model as netem did on the bench
// (plans/research/2026-11-15-voice-night-lab.md: 14.7% to bad, 67% back,
// one copy lost 19%); the pool loses none. What counts is what a listener
// hears.

// listened is what a listener heard of a call: frames sent and the first copy
// of each back.
type listened struct {
	mu      sync.Mutex
	born    []time.Time
	arrived []time.Time
}

func newListened(frames int) *listened {
	return &listened{born: make([]time.Time, frames), arrived: make([]time.Time, frames)}
}

func (c *listened) deliver(p []byte) {
	if len(p) < 4 {
		return
	}
	seq := binary.BigEndian.Uint32(p)
	c.mu.Lock()
	defer c.mu.Unlock()
	if int(seq) < len(c.arrived) && c.arrived[seq].IsZero() {
		c.arrived[seq] = time.Now()
	}
}

// holes are frames not back by the play time: the best round trip of the
// call plus buffer. runs2 are holes of 2+ frames in a row, what PLC cannot
// hide.
func (c *listened) holes(buffer time.Duration) (holes, runs2 int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	best := time.Duration(1 << 62)
	for i, a := range c.arrived {
		if !a.IsZero() && a.Sub(c.born[i]) < best {
			best = a.Sub(c.born[i])
		}
	}
	run := 0
	for i, a := range c.arrived {
		if a.IsZero() || a.Sub(c.born[i]) > best+buffer {
			holes++
			run++
			continue
		}
		if run >= 2 {
			runs2++
		}
		run = 0
	}
	if run >= 2 {
		runs2++
	}
	return holes, runs2
}

// call sends frames 160 B datagrams on f, every gap, and waits for the last
// answers.
func (c *listened) call(f *Flow, gap time.Duration) {
	for seq := range c.born {
		p := make([]byte, 160)
		binary.BigEndian.PutUint32(p, uint32(seq))
		c.mu.Lock()
		c.born[seq] = time.Now()
		c.mu.Unlock()
		f.Send(p)
		time.Sleep(gap)
	}
	time.Sleep(300 * time.Millisecond)
}

// TestVoiceRidesTwoFates: the night's cut on the udp wire, voice routed
// there with one copy (a port whose client copies itself). The set carries
// it on the pool as well, and the listener hears under 1% holes and no run
// of two, where the udp wire alone gave 19%.
func TestVoiceRidesTwoFates(t *testing.T) {
	h := newWireHarness(t, Config{}, 2, 0, 3)
	udp := h.wires[testUDP]
	udp.gilbert.Lock()
	udp.gilbert.p, udp.gilbert.r = 0.147, 0.67
	udp.gilbert.Unlock()
	h.entry.SetRoute(Route{Voice: testUDP, Bulk: PoolWire})
	c := newListened(1500)
	f := h.entry.Session().OpenFlowWith(4000, FlowOptions{Copies: 1, Class: ClassVoice, Pin: AnyWire}, c.deliver, nil)
	defer f.Close()
	u0, p0 := udp.out.Load(), h.wires[PoolWire].out.Load()
	c.call(f, 2*time.Millisecond)
	holes, runs2 := c.holes(60 * time.Millisecond)
	t.Logf("holes %d of %d (%.2f%%), runs of 2+ %d", holes, len(c.born), 100*float64(holes)/float64(len(c.born)), runs2)
	if holes*100 >= len(c.born) || runs2 != 0 {
		t.Fatalf("holes %d of %d, runs of 2+ %d: want under 1%% and none", holes, len(c.born), runs2)
	}
	if u, p := udp.out.Load()-u0, h.wires[PoolWire].out.Load()-p0; u < 1500*160 || p < 1500*160 {
		t.Fatalf("the udp wire carried %d bytes, the pool %d: want a copy of each frame on both", u, p)
	}
}

// TestTCPNeverCarriesVoiceAlone: voice routed on the pool, by Voice or by a
// set of the pool alone, still goes on the udp wire while it is up; with the
// udp wire down the pool carries it alone, as before the sets.
func TestTCPNeverCarriesVoiceAlone(t *testing.T) {
	h := newWireHarness(t, Config{Stall: 100 * time.Millisecond}, 2, 0, 1)
	udp := h.wires[testUDP]
	var got atomic.Int64
	f := h.entry.Session().OpenFlowWith(4000, FlowOptions{Copies: 1, Class: ClassVoice, Pin: AnyWire}, func([]byte) { got.Add(1) }, nil)
	defer f.Close()
	send := func() (udpOut, poolOut int64) {
		u0, p0 := udp.out.Load(), h.wires[PoolWire].out.Load()
		for i := 0; i < 20; i++ {
			f.Send(make([]byte, 160))
			time.Sleep(2 * time.Millisecond)
		}
		time.Sleep(50 * time.Millisecond)
		return udp.out.Load() - u0, h.wires[PoolWire].out.Load() - p0
	}
	for _, r := range []Route{
		{Voice: PoolWire, Bulk: PoolWire},
		{Voice: PoolWire, VoiceSet: SetOf(Carry{Wire: PoolWire}), Bulk: PoolWire},
	} {
		h.entry.SetRoute(r)
		if u, p := send(); u < 20*160 || p < 20*160 {
			t.Fatalf("route %+v: the udp wire carried %d bytes, the pool %d: want a copy on each", r, u, p)
		}
	}
	udp.cut.Store(true)
	waitFor(t, func() bool { return h.entry.Wires()[testUDP].Members == 0 })
	before := got.Load()
	if _, p := send(); p < 20*160 {
		t.Fatalf("the udp wire down, the pool carried %d bytes", p)
	}
	if n := got.Load() - before; n != 20 {
		t.Fatalf("%d of 20 came back on the pool alone", n)
	}
}

// TestVideoGoesOnOneWire: video follows voice's main wire with no copy on
// the other fate, or its own wire when the route gives it one.
func TestVideoGoesOnOneWire(t *testing.T) {
	h := newWireHarness(t, Config{}, 2, 0, 1)
	udp, pool := h.wires[testUDP], h.wires[PoolWire]
	var got atomic.Int64
	f := h.entry.Session().OpenFlowWith(4000, FlowOptions{Copies: 1, Class: ClassVideo, Pin: AnyWire}, func([]byte) { got.Add(1) }, nil)
	defer f.Close()
	send := func() (udpOut, poolOut int64) {
		u0, p0 := udp.out.Load(), pool.out.Load()
		for i := 0; i < 50; i++ {
			f.Send(make([]byte, 1000))
			time.Sleep(time.Millisecond)
		}
		time.Sleep(50 * time.Millisecond)
		return udp.out.Load() - u0, pool.out.Load() - p0
	}
	h.entry.SetRoute(Route{Voice: testUDP, Bulk: PoolWire})
	if u, p := send(); u < 50*1000 || p > 50*100 {
		t.Fatalf("video after voice's wire: the udp wire carried %d bytes, the pool %d", u, p)
	}
	h.entry.SetRoute(Route{Voice: testUDP, Bulk: testUDP}.WithVideo(PoolWire))
	if u, p := send(); p < 50*1000 || u > 50*100 {
		t.Fatalf("video on the pool: the udp wire carried %d bytes, the pool %d", u, p)
	}
	if n := got.Load(); n != 100 {
		t.Fatalf("%d of 100 came back", n)
	}
}

// TestTheExitAnswersOnEveryWireOfTheSet: the exit answers a flow on every
// wire its datagrams came on in the last second, and stops on a wire a
// second after the last one came there.
func TestTheExitAnswersOnEveryWireOfTheSet(t *testing.T) {
	h := newWireHarness(t, Config{}, 2, 0, 2)
	udp, pool := h.wires[testUDP], h.wires[PoolWire]
	f := h.entry.Session().OpenFlowWith(4000, FlowOptions{Copies: 1, Class: ClassVideo, Pin: AnyWire}, func([]byte) {}, nil)
	defer f.Close()
	send := func(d time.Duration) (udpIn, poolIn int64) {
		u0, p0 := udp.in.Load(), pool.in.Load()
		for end := time.Now().Add(d); time.Now().Before(end); {
			f.Send(make([]byte, 1000))
			time.Sleep(5 * time.Millisecond)
		}
		time.Sleep(20 * time.Millisecond)
		return udp.in.Load() - u0, pool.in.Load() - p0
	}
	h.entry.SetRoute(Route{Voice: testUDP, Bulk: PoolWire}.WithVideo(testUDP))
	send(200 * time.Millisecond)
	h.entry.SetRoute(Route{Voice: testUDP, Bulk: PoolWire}.WithVideo(PoolWire))
	if u, p := send(300 * time.Millisecond); u < 20*1000 || p < 20*1000 {
		t.Fatalf("within a second of both: answers %d bytes on the udp wire, %d on the pool", u, p)
	}
	send(time.Second)
	if u, p := send(300 * time.Millisecond); u > 5*1000 || p < 20*1000 {
		t.Fatalf("a second after the udp wire's last: answers %d bytes on it, %d on the pool", u, p)
	}
}

// TestALaterCopyLeavesAfterItsDelay: a set's carry with After sends its copy
// that much later; the exit takes the first and drops the later one.
func TestALaterCopyLeavesAfterItsDelay(t *testing.T) {
	h := newWireHarness(t, Config{}, 2, 0, 2)
	h.entry.SetRoute(Route{Voice: testUDP, VoiceSet: SetOf(Carry{Wire: testUDP}, Carry{Wire: testUDP, After: 50 * time.Millisecond}), Bulk: PoolWire})
	var got atomic.Int64
	f := h.entry.Session().OpenFlowWith(4000, FlowOptions{Copies: 1, Class: ClassVoice, Pin: AnyWire}, func([]byte) { got.Add(1) }, nil)
	defer f.Close()
	copies := func() int64 { _, x := h.exit.Stats(); return x.DgramsCopy }
	f.Send(make([]byte, 160))
	time.Sleep(20 * time.Millisecond)
	if n, c := got.Load(), copies(); n != 1 || c != 0 {
		t.Fatalf("20 ms after: %d back, %d copies at the exit; want the first only", n, c)
	}
	waitFor(t, func() bool { return copies() == 1 })
	if n := got.Load(); n != 1 {
		t.Fatalf("%d answers to one datagram", n)
	}
}

// TestPoolMembersCarryDatagramsWithoutNagle: a 160 B frame every 20 ms on
// one member of the pool, on real TCP sockets dialled and accepted with
// Nagle on. Both ends turn it off, so no frame waits for the last one's
// ack: the write's delay does not grow (plan of 15.11, раздел 2).
func TestPoolMembersCarryDatagramsWithoutNagle(t *testing.T) {
	arrived := make(chan time.Duration, 200)
	sink, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := sink.ReadFrom(buf)
			if err != nil {
				return
			}
			if n >= 8 {
				arrived <- time.Since(time.Unix(0, int64(binary.BigEndian.Uint64(buf))))
			}
		}
	}()
	x := NewExit(Config{}, sinkLocal{sink.LocalAddr().String()})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go x.Run(ctx)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.(*net.TCPConn).SetNoDelay(false)
			go func() { _ = x.ServeMember(c) }()
		}
	}()
	ports, err := NewPortBook(30000, 31000, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	dial := func(ctx context.Context, _ int) (io.ReadWriteCloser, error) {
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", ln.Addr().String())
		if err == nil {
			_ = c.(*net.TCPConn).SetNoDelay(false)
		}
		return c, err
	}
	e, err := NewEntry(Config{}, 1, dial, ports, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	ran := make(chan struct{})
	go func() { e.Run(ctx); close(ran) }()
	defer func() { cancel(); <-ran }()
	waitFor(t, func() bool { return e.Wires()[PoolWire].Members == 1 })
	f := e.Session().OpenFlowWith(4000, FlowOptions{Copies: 1, Class: ClassVoice, Pin: AnyWire}, nil, nil)
	defer f.Close()
	var delays []time.Duration
	for i := 0; i < 100; i++ {
		p := make([]byte, 160)
		binary.BigEndian.PutUint64(p, uint64(time.Now().UnixNano()))
		f.Send(p)
		time.Sleep(20 * time.Millisecond)
		select {
		case d := <-arrived:
			delays = append(delays, d)
		case <-time.After(time.Second):
			t.Fatalf("frame %d did not arrive", i)
		}
	}
	slices.Sort(delays)
	p50, worst := delays[len(delays)/2], delays[len(delays)-1]
	t.Logf("one way: p50 %v, worst %v", p50, worst)
	if worst > p50+5*time.Millisecond {
		t.Fatalf("one way: p50 %v, worst %v: a frame waited on the socket", p50, worst)
	}
}

// sinkLocal is an exit's relay where every flow is one UDP socket to addr.
type sinkLocal struct{ addr string }

func (sinkLocal) DialStream(context.Context, uint16) (net.Conn, error) { return nil, net.ErrClosed }

func (l sinkLocal) DialFlow(ctx context.Context, _ uint16) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "udp", l.addr)
}
