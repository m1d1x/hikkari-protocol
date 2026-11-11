package trunk

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// loopLocal is the exit's relay in tests: TCP and UDP echo on loopback.
type loopLocal struct {
	tcp  net.Listener
	udp  net.PacketConn
	port uint16
}

func newLoopLocal(t *testing.T, serve func(net.Conn)) *loopLocal {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close(); pc.Close() })
	if serve == nil {
		serve = func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(c)
		}
	}()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], from)
		}
	}()
	return &loopLocal{tcp: ln, udp: pc}
}

func (l *loopLocal) DialStream(ctx context.Context, port uint16) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", l.tcp.Addr().String())
}

func (l *loopLocal) DialFlow(ctx context.Context, port uint16) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "udp", l.udp.LocalAddr().String())
}

// faulty is the entry's end of a member that the path may kill: past its
// budget it goes silent both ways, as a flow killed by source port does.
type faulty struct {
	net.Conn
	budget atomic.Int64
	dead   chan struct{}
	gone   chan struct{}
	once   sync.Once
	shut   sync.Once
}

func (f *faulty) Write(p []byte) (int, error) {
	if f.budget.Add(-int64(len(p))) < 0 {
		f.once.Do(func() { close(f.dead) })
		return len(p), nil // swallowed by the path
	}
	return f.Conn.Write(p)
}

func (f *faulty) Read(p []byte) (int, error) {
	n, err := f.Conn.Read(p)
	if oneWay.Load() {
		return n, err // only the way out died: the other end's frames still come
	}
	select {
	case <-f.dead:
		// The path dropped it; the reader sees nothing more until closed.
		<-f.gone
		return 0, net.ErrClosed
	default:
	}
	return n, err
}

// oneWay makes faulty members die one way only.
var oneWay atomic.Bool

type harness struct {
	exit  *Exit
	entry *Entry
	local *loopLocal
	kills atomic.Int64
	// budget, when set, is how many bytes each new member carries before it
	// goes silent; zero means members never die.
	budget func(n int64) int64
	dials  atomic.Int64
	cancel context.CancelFunc
	// dialDelay, when set, is how long a new member takes to reach the exit.
	dialDelay atomic.Int64

	logMu sync.Mutex
	logs  []string // the entry's lines
}

// journal is what the entry has logged so far.
func (h *harness) journal() string {
	h.logMu.Lock()
	defer h.logMu.Unlock()
	return strings.Join(h.logs, "\n")
}

func newHarness(t *testing.T, cfg Config, members int, budget func(int64) int64, serve func(net.Conn)) *harness {
	t.Helper()
	return newHarnessLocal(t, cfg, cfg, members, budget, newLoopLocal(t, serve))
}

// newHarnessLocal is newHarness with each end's own config and the exit's
// Local given.
func newHarnessLocal(t *testing.T, cfg, exitCfg Config, members int, budget func(int64) int64, local Local) *harness {
	t.Helper()
	h := &harness{budget: budget}
	if l, ok := local.(*loopLocal); ok {
		h.local = l
	}
	h.exit = NewExit(exitCfg, local)
	ports, err := NewPortBook(20000, 30000, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	replaceSpread = 20 * time.Millisecond
	dial := func(ctx context.Context, port int) (io.ReadWriteCloser, error) {
		n := h.dials.Add(1)
		if d := time.Duration(h.dialDelay.Load()); d > 0 {
			select {
			case <-time.After(d):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		a, b := net.Pipe()
		go func() { _ = h.exit.ServeMember(b) }()
		if h.budget == nil {
			return wire.wrap(a), nil
		}
		f := &faulty{Conn: a, dead: make(chan struct{}), gone: make(chan struct{})}
		f.budget.Store(h.budget(n))
		return &closer{f, a}, nil
	}
	logf := func(format string, a ...any) {
		h.logMu.Lock()
		h.logs = append(h.logs, fmt.Sprintf(format, a...))
		h.logMu.Unlock()
		t.Logf(format, a...)
	}
	h.entry, err = NewEntry(cfg, members, dial, ports, logf)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	exitCtx, exitCancel := context.WithCancel(context.Background())
	go h.exit.Run(exitCtx)
	ran := make(chan struct{})
	go func() { h.entry.Run(ctx); close(ran) }()
	// The entry's last line (what it cut) is logged before the test ends.
	t.Cleanup(func() { cancel(); <-ran; exitCancel() })
	waitFor(t, func() bool { return h.entry.Session().Stats().Members == members })
	return h
}

// closer closes the pipe under a faulty member, so the exit's end ends too.
type closer struct {
	*faulty
	pipe net.Conn
}

func (c *closer) Close() error {
	c.shut.Do(func() { close(c.gone) })
	return c.pipe.Close()
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// carry opens one client connection through the entry and returns the
// client's end.
func (h *harness) carry() net.Conn {
	client, edge := net.Pipe()
	go h.entry.Session().Carry(edge, 443)
	return client
}

var dump func()

func roundTrip(t *testing.T, c net.Conn, size int) {
	t.Helper()
	data := make([]byte, size)
	_, _ = rand.Read(data)
	errc := make(chan error, 1)
	go func() { _, err := c.Write(data); errc <- err }()
	got := make([]byte, size)
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil {
		if dump != nil {
			dump()
		}
		t.Fatalf("read back: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("write: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("echo differs")
	}
}

func TestEchoOverPool(t *testing.T) {
	h := newHarness(t, Config{}, 8, nil, nil)
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := h.carry()
			defer c.Close()
			roundTrip(t, c, 3<<20)
		}()
	}
	wg.Wait()
	st := h.entry.Session().Stats()
	if st.MembersStall != 0 || st.Resent != 0 {
		t.Fatalf("healthy pool resent: %+v", st)
	}
}

// TestKilledMembers: every member dies silently after 0.2–1 MiB. The bytes
// still all arrive, in order, and the killed ports are not used again.
func TestKilledMembers(t *testing.T) {
	budget := func(n int64) int64 { return 200<<10 + (n%5)*200<<10 }
	h := newHarness(t, Config{Stall: 100 * time.Millisecond}, 6, budget, nil)
	var once sync.Once
	dump = func() {
		once.Do(func() {
			dumpSession(t, "entry", h.entry.Session())
			h.exit.mu.Lock()
			for _, es := range h.exit.sessions {
				dumpSession(t, "exit", es.s)
			}
			h.exit.mu.Unlock()
		})
	}
	defer func() { dump = nil }()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := h.carry()
			defer c.Close()
			roundTrip(t, c, 4<<20)
		}()
	}
	wg.Wait()
	st := h.entry.Session().Stats()
	dead, kills := h.entry.Ports().Counts()
	if st.MembersStall == 0 || st.Resent == 0 || kills == 0 || dead == 0 {
		t.Fatalf("no member was killed and replaced: %+v dead=%d kills=%d", st, dead, kills)
	}
	t.Logf("stalls=%d resent=%d dials=%d", st.MembersStall, st.Resent, h.dials.Load())
}

// TestHalfClose: the client ends its request; the answer still comes back
// whole, and the stream closes on both sides.
func TestHalfClose(t *testing.T) {
	serve := func(c net.Conn) {
		defer c.Close()
		req, _ := io.ReadAll(c) // to the client's FIN
		_, _ = c.Write(append([]byte("got "), req...))
	}
	h := newHarness(t, Config{}, 3, nil, serve)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			h.entry.Session().Carry(c, 443)
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("hello"))
	_ = c.(*net.TCPConn).CloseWrite()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	answer, err := io.ReadAll(c)
	if err != nil || string(answer) != "got hello" {
		t.Fatalf("answer %q, %v", answer, err)
	}
	waitFor(t, func() bool { return h.entry.Session().Stats().Streams == 0 })
	_, x := h.exit.Stats()
	waitFor(t, func() bool { _, x = h.exit.Stats(); return x.Streams == 0 })
}

func TestDatagrams(t *testing.T) {
	h := newHarness(t, Config{}, 4, nil, nil)
	got := make(chan []byte, 100)
	f := h.entry.Session().OpenFlow(443, func(p []byte) { got <- append([]byte(nil), p...) }, nil)
	for i := 0; i < 50; i++ {
		if !f.Send([]byte{byte(i), 1, 2, 3}) {
			t.Fatal("flow ended")
		}
	}
	seen := map[byte]bool{}
	timeout := time.After(10 * time.Second)
	for len(seen) < 50 {
		select {
		case p := <-got:
			if seen[p[0]] {
				t.Fatalf("datagram %d delivered twice", p[0])
			}
			seen[p[0]] = true
		case <-timeout:
			t.Fatalf("%d of 50 datagrams came back", len(seen))
		}
	}
	_, x := h.exit.Stats()
	if st := h.entry.Session().Stats(); st.DgramsCopy == 0 || x.DgramsCopy == 0 {
		t.Fatalf("copies were not sent or not dropped: entry %+v exit %+v", st, x)
	}
}

// TestOneCopyDatagrams: a flow opened with one copy (its sender copies its
// datagrams itself, as Hikkari v1.02 does) travels once each way: the exit
// answers it as the entry sends it.
func TestOneCopyDatagrams(t *testing.T) {
	h := newHarness(t, Config{}, 4, nil, nil)
	got := make(chan []byte, 100)
	f := h.entry.Session().OpenFlowCopies(443, 1, func(p []byte) { got <- append([]byte(nil), p...) }, nil)
	for i := 0; i < 50; i++ {
		if !f.Send([]byte{byte(i), 1, 2, 3}) {
			t.Fatal("flow ended")
		}
		time.Sleep(2 * time.Millisecond)
	}
	seen := map[byte]bool{}
	timeout := time.After(10 * time.Second)
	for len(seen) < 50 {
		select {
		case p := <-got:
			seen[p[0]] = true
		case <-timeout:
			t.Fatalf("%d of 50 datagrams came back", len(seen))
		}
	}
	_, x := h.exit.Stats()
	if st := h.entry.Session().Stats(); st.DgramsCopy != 0 || x.DgramsCopy != 0 || x.DgramsIn != 50 || st.DgramsIn != 50 {
		t.Fatalf("one copy each way, want 50 in and none dropped: entry %+v exit %+v", st, x)
	}
}

// TestMemberRTTs: every member that answered a ping has a round trip.
func TestMemberRTTs(t *testing.T) {
	h := newHarness(t, Config{Keepalive: 50 * time.Millisecond}, 3, nil, nil)
	waitFor(t, func() bool { return len(h.entry.Session().MemberRTTs()) == 3 })
	rtts := h.entry.Session().MemberRTTs()
	for i, r := range rtts {
		if r <= 0 || (i > 0 && r < rtts[i-1]) {
			t.Fatalf("round trips %v, want positive and sorted", rtts)
		}
	}
}

// TestExitRestart: a new exit under the same entry (new epoch) resets the
// streams it lost instead of leaving them hanging.
func TestExitRestart(t *testing.T) {
	h := newHarness(t, Config{}, 2, nil, func(c net.Conn) { <-make(chan struct{}) })
	c := h.carry()
	defer c.Close()
	_, _ = c.Write([]byte("x"))
	waitFor(t, func() bool { _, x := h.exit.Stats(); return x.Streams == 1 })
	h.exit = NewExit(Config{}, h.local) // members redial into a fresh exit
	h.entry.Session().mu.Lock()
	for m := range h.entry.Session().members {
		h.entry.Session().dropMemberLocked(m, false)
	}
	h.entry.Session().mu.Unlock()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, err := c.Read(make([]byte, 1))
	var ne net.Error
	if err == nil || (errors.As(err, &ne) && ne.Timeout()) {
		t.Fatalf("stream survived the exit's restart: %v", err)
	}
}

func TestReplay(t *testing.T) {
	var r replay
	for _, s := range []uint32{1, 2, 5, 3} {
		if r.seen(s) {
			t.Fatalf("%d is new", s)
		}
	}
	for _, s := range []uint32{1, 5, 0} {
		if !r.seen(s) {
			t.Fatalf("%d is a copy", s)
		}
	}
	if r.seen(2000) || !r.seen(900) || r.seen(1999) {
		t.Fatal("window slide")
	}
}

func dumpSession(t *testing.T, name string, s *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t.Logf("%s: members=%d pending=%d early=%d", name, len(s.members), len(s.pending), len(s.early))
	for m := range s.members {
		t.Logf("  member segs=%d inflight=%d ping=%d progress=%s ago", len(m.segs), m.inflight, m.ping, time.Since(m.progress).Round(time.Millisecond))
	}
	for id, st := range s.streams {
		kinds := map[byte]int{}
		var noMember int
		for _, seg := range st.owed {
			kinds[seg.kind]++
			if seg.m == nil || seg.m.dead {
				noMember++
			}
		}
		t.Logf("  stream %d sent=%d credit=%d owed=%v orphan=%d received=%d written=%d ahead=%d queue=%d finAt=%d finSent=%v finDone=%v writeDone=%v ready=%v",
			id, st.sent, st.credit, kinds, noMember, st.received, st.written, len(st.ahead), len(st.queue), st.finAt, st.finSent, st.finDone, st.writeDone, st.local != nil)
	}
}

// TestOneWayDeath: members whose way out dies while the other end's frames
// keep arriving are still found dead, and the bytes still all arrive.
func TestOneWayDeath(t *testing.T) {
	oneWay.Store(true)
	defer oneWay.Store(false)
	budget := func(n int64) int64 { return 300<<10 + (n%3)*300<<10 }
	h := newHarness(t, Config{Stall: 100 * time.Millisecond}, 4, budget, nil)
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := h.carry()
			defer c.Close()
			roundTrip(t, c, 3<<20)
		}()
	}
	wg.Wait()
	if st := h.entry.Session().Stats(); st.MembersStall == 0 {
		t.Fatalf("no one-way death was found: %+v", st)
	}
}

// wireGate stands for the whole path and the entry's box at once: freeze
// stops every entry-side member read and write (the entry's box is not run),
// cut black-holes every member up now both ways (the path dropped them all).
type wireGate struct {
	mu     sync.Mutex
	cond   *sync.Cond
	frozen bool
	gen    int64 // members dialed now are of this generation
	cutGen int64 // members of a generation below this are cut
}

var wire = func() *wireGate { g := &wireGate{}; g.cond = sync.NewCond(&g.mu); return g }()

func (g *wireGate) freeze(on bool) {
	g.mu.Lock()
	g.frozen = on
	g.cond.Broadcast()
	g.mu.Unlock()
}

func (g *wireGate) cut() {
	g.mu.Lock()
	g.gen++
	g.cutGen = g.gen
	g.cond.Broadcast()
	g.mu.Unlock()
}

func (g *wireGate) reset() {
	g.mu.Lock()
	g.frozen, g.gen, g.cutGen = false, 0, 0
	g.cond.Broadcast()
	g.mu.Unlock()
}

func (g *wireGate) wrap(c net.Conn) io.ReadWriteCloser {
	g.mu.Lock()
	defer g.mu.Unlock()
	return &gated{Conn: c, g: g, gen: g.gen, closed: make(chan struct{})}
}

type gated struct {
	net.Conn
	g      *wireGate
	gen    int64
	closed chan struct{}
	once   sync.Once
}

// pass waits while the entry is frozen; false once the path cut this member.
func (c *gated) pass() bool {
	c.g.mu.Lock()
	defer c.g.mu.Unlock()
	for c.g.frozen && c.gen >= c.g.cutGen {
		c.g.cond.Wait()
	}
	return c.gen >= c.g.cutGen
}

func (c *gated) Write(p []byte) (int, error) {
	if !c.pass() {
		return len(p), nil // swallowed by the path
	}
	return c.Conn.Write(p)
}

func (c *gated) Read(p []byte) (int, error) {
	if !c.pass() {
		<-c.closed
		return 0, net.ErrClosed
	}
	n, err := c.Conn.Read(p)
	if err == nil && !c.pass() {
		<-c.closed // what came in as the path died is lost with it
		return 0, net.ErrClosed
	}
	return n, err
}

func (c *gated) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// TestOtherEndPaused: the entry's box is not run for 1.5 s in the middle of
// a transfer (its own clock stopped with it, which Quiet stands for here).
// The exit sees every member silent at once: that is the other end, not
// the members, and none is buried; the transfer goes on after the pause.
func TestOtherEndPaused(t *testing.T) {
	defer wire.reset()
	h := newHarness(t, Config{Stall: 100 * time.Millisecond, Quiet: 10 * time.Second}, 6, nil, nil)
	c := h.carry()
	defer c.Close()
	roundTrip(t, c, 1<<20)
	done := make(chan struct{})
	go func() {
		defer close(done)
		roundTrip(t, c, 8<<20)
	}()
	time.Sleep(50 * time.Millisecond)
	wire.freeze(true)
	time.Sleep(1500 * time.Millisecond)
	wire.freeze(false)
	<-done
	if st := h.entry.Session().Stats(); st.MembersStall != 0 || st.MembersBroken != 0 {
		t.Fatalf("the entry buried members: %+v", st)
	}
	if _, st := h.exit.Stats(); st.MembersStall != 0 {
		t.Fatalf("the exit buried members for the entry's pause: %+v", st)
	}
	if d := h.dials.Load(); d != 6 {
		t.Fatalf("%d dials for 6 members: some were replaced", d)
	}
}

// TestPathCut: the path drops every member at once. Nobody shows progress,
// so it is Quiet, not Stall, that ends them; the entry dials new ones and
// the transfer completes on them.
func TestPathCut(t *testing.T) {
	defer wire.reset()
	h := newHarness(t, Config{Stall: 100 * time.Millisecond, Quiet: 300 * time.Millisecond}, 4, nil, nil)
	c := h.carry()
	defer c.Close()
	roundTrip(t, c, 1<<20)
	wire.cut()
	roundTrip(t, c, 4<<20)
	// Idle members owe nothing until their next keepalive ping, so the last
	// of them end up to Keepalive + Quiet after the cut.
	waitFor(t, func() bool { return h.entry.Session().Stats().MembersStall >= 4 })
	waitFor(t, func() bool { return h.entry.Session().Stats().Members == 4 })
	if d := h.dials.Load(); d < 8 {
		t.Fatalf("%d dials: the cut members were not replaced", d)
	}
}

// TestOwnPause: a late tick is the session's own pause. Members that owe
// get a fresh start from it instead of being buried for the time the box
// did not run; one that stays silent after it ends by Quiet as usual.
func TestOwnPause(t *testing.T) {
	s := newSession(Config{Stall: 100 * time.Millisecond, Quiet: time.Second}, nil)
	defer s.Close()
	var told atomic.Int64
	s.onPause = func(d time.Duration) { told.Store(int64(d)) }
	a, b := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, b) }() // the other end reads, never answers
	go func() { _ = s.Serve(a) }()
	waitFor(t, func() bool { return s.Stats().Members == 1 })

	t0 := time.Now()
	s.mu.Lock()
	for m := range s.members {
		m.ping, m.pingSent = 1, t0 // a ping owed since t0
	}
	s.mu.Unlock()
	// run ticks the clock on time from one moment to another.
	run := func(from, to time.Duration) {
		for d := from; d <= to; d += tick {
			s.tick(t0.Add(d))
		}
	}
	run(0, 50*time.Millisecond)
	s.tick(t0.Add(2 * time.Second)) // the box was not run for 2 s
	if st := s.Stats(); st.Members != 1 || st.Pauses != 1 || st.Paused != 1950*time.Millisecond {
		t.Fatalf("after its own pause: %+v", st)
	}
	waitFor(t, func() bool { return told.Load() == int64(1950*time.Millisecond) })
	run(2*time.Second, 2*time.Second+900*time.Millisecond)
	if st := s.Stats(); st.Members != 1 {
		t.Fatalf("buried within Quiet of the pause: %+v", st)
	}
	run(2*time.Second+925*time.Millisecond, 2*time.Second+1100*time.Millisecond)
	if st := s.Stats(); st.Members != 0 || st.MembersStall != 1 {
		t.Fatalf("silent past Quiet and still up: %+v", st)
	}
}

// TestExitDrain: the exit's process is replaced without a cut. Its drain
// moves everything new to a new session that reaches the new process, the
// old session's stream goes on to its end, and then the old session closes,
// which lets the old process go.
func TestExitDrain(t *testing.T) {
	retireEvery = 20 * time.Millisecond
	defer func() { retireEvery = 5 * time.Second }()
	h := newHarness(t, Config{}, 4, nil, nil)
	c1 := h.carry()
	defer c1.Close()
	roundTrip(t, c1, 1<<20)

	old := h.exit
	next := NewExit(Config{}, h.local)
	exitCtx, exitCancel := context.WithCancel(context.Background())
	defer exitCancel()
	go next.Run(exitCtx)
	h.exit = next // new members reach the new process
	old.Drain()
	waitFor(t, func() bool { return h.entry.Retired() == 1 && h.entry.Session().Stats().Members == 4 })

	roundTrip(t, c1, 1<<20) // the old session's stream goes on
	c2 := h.carry()
	defer c2.Close()
	roundTrip(t, c2, 1<<20)
	if _, st := next.Stats(); st.Streams != 1 {
		t.Fatalf("new process carries %d streams, want the new one", st.Streams)
	}
	if _, st := old.Stats(); st.Streams != 1 || st.StreamsReset != 0 {
		t.Fatalf("old process: %+v", st)
	}

	c1.Close()
	waitFor(t, func() bool { return h.entry.Retired() == 0 })
	waitFor(t, func() bool { _, st := old.Stats(); return st.Members == 0 })
	roundTrip(t, c2, 1<<20)
}

// TestRetiredEntryIgnoresExitDrain: the entry's own process is being replaced
// (Retire), and while it still carries a stream the exit drains too. The old
// entry opens no new session and no new pool for it: it takes nothing new.
// Its stream goes on to its end on the exit's old process, and then the
// entry carries nothing and its session closes.
func TestRetiredEntryIgnoresExitDrain(t *testing.T) {
	retireEvery = 20 * time.Millisecond
	defer func() { retireEvery = 5 * time.Second }()
	h := newHarness(t, Config{}, 4, nil, nil)
	c1 := h.carry()
	defer c1.Close()
	roundTrip(t, c1, 1<<20)

	s := h.entry.Session()
	h.entry.Retire()
	if h.entry.Retired() != 1 || h.entry.Session() != s {
		t.Fatalf("retire: %d retired, same session %v", h.entry.Retired(), h.entry.Session() == s)
	}
	dials := h.dials.Load()

	old := h.exit
	next := NewExit(Config{}, h.local)
	exitCtx, exitCancel := context.WithCancel(context.Background())
	defer exitCancel()
	go next.Run(exitCtx)
	h.exit = next
	old.Drain()
	time.Sleep(300 * time.Millisecond)
	if strings.Contains(h.journal(), "exit drains") {
		t.Fatalf("a retired entry answered the exit's drain:\n%s", h.journal())
	}
	if h.entry.Session() != s || h.dials.Load() != dials {
		t.Fatalf("new session %v, dials %d after %d", h.entry.Session() != s, h.dials.Load(), dials)
	}
	if _, st := next.Stats(); st.Members != 0 {
		t.Fatalf("the exit's new process got %d members from a retired entry", st.Members)
	}

	roundTrip(t, c1, 1<<20) // what it carries goes on
	if streams, flows := h.entry.Carrying(); streams != 1 || flows != 0 {
		t.Fatalf("carrying %d stream(s) %d flow(s), want 1 and 0", streams, flows)
	}
	c1.Close()
	waitFor(t, func() bool { return h.entry.Retired() == 0 })
	if streams, _ := h.entry.Carrying(); streams != 0 {
		t.Fatalf("carrying %d stream(s) after the last one ended", streams)
	}
	waitFor(t, func() bool { _, st := old.Stats(); return st.Members == 0 })
}

// TestEntryCountsWhatItCuts: an entry that is stopped while it carries a
// stream on its current session and one on a retired one counts both, in
// Carrying and in the line it leaves on.
func TestEntryCountsWhatItCuts(t *testing.T) {
	h := newHarness(t, Config{}, 4, nil, nil)
	c1 := h.carry()
	defer c1.Close()
	roundTrip(t, c1, 1<<16)

	next := NewExit(Config{}, h.local)
	exitCtx, exitCancel := context.WithCancel(context.Background())
	defer exitCancel()
	go next.Run(exitCtx)
	old := h.exit
	h.exit = next
	old.Drain()
	waitFor(t, func() bool { return h.entry.Retired() == 1 && h.entry.Session().Stats().Members == 4 })
	c2 := h.carry()
	defer c2.Close()
	roundTrip(t, c2, 1<<16)

	if s := h.entry.Session().Stats().Streams; s != 1 {
		t.Fatalf("current session carries %d, want 1", s)
	}
	if streams, _ := h.entry.Carrying(); streams != 2 {
		t.Fatalf("carrying %d stream(s), want both", streams)
	}
	h.cancel()
	waitFor(t, func() bool { return strings.Contains(h.journal(), "trunk: closed with 2 stream(s) and 0 flow(s) cut") })
}

// TestExitDrainWaitsForThePool: the exit's new process is slow to take the
// new session's members. Until a quarter of the new pool is up, the old
// session goes on taking new streams (the exit's old process still serves
// them), so nothing new waits for a pool that is not there; then the new
// session takes over and the old one retires.
func TestExitDrainWaitsForThePool(t *testing.T) {
	retireEvery = 20 * time.Millisecond
	defer func() { retireEvery = 5 * time.Second }()
	h := newHarness(t, Config{}, 4, nil, nil)
	c1 := h.carry()
	defer c1.Close()
	roundTrip(t, c1, 1<<16)
	s := h.entry.Session()

	h.dialDelay.Store(int64(400 * time.Millisecond))
	old := h.exit
	next := NewExit(Config{}, h.local)
	exitCtx, exitCancel := context.WithCancel(context.Background())
	defer exitCancel()
	go next.Run(exitCtx)
	h.exit = next
	old.Drain()
	time.Sleep(100 * time.Millisecond)
	if h.entry.Session() != s || h.entry.Retired() != 0 {
		t.Fatalf("the new session took over with no member up")
	}
	c2 := h.carry() // during the wait: the old session, the old process
	defer c2.Close()
	roundTrip(t, c2, 1<<16)
	if _, st := old.Stats(); st.Streams != 2 {
		t.Fatalf("the exit's old process carries %d streams, want both", st.Streams)
	}

	waitFor(t, func() bool { return h.entry.Session() != s && h.entry.Retired() == 1 })
	if m := h.entry.Session().Stats().Members; m < 1 {
		t.Fatalf("the new session took over with %d members", m)
	}
	c3 := h.carry()
	defer c3.Close()
	roundTrip(t, c3, 1<<16)
	if _, st := next.Stats(); st.Streams != 1 {
		t.Fatalf("the exit's new process carries %d streams, want the one after the takeover", st.Streams)
	}
	if !strings.Contains(h.journal(), "exit drains: new session, the old one keeps 2 stream(s)") {
		t.Fatalf("no takeover line:\n%s", h.journal())
	}
	c1.Close()
	c2.Close()
	waitFor(t, func() bool { return h.entry.Retired() == 0 })
}
