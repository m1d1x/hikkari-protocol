package pipectl

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
	"github.com/m1d1x/hikkari-protocol/trunk/udpwire"
)

// The receivers (receivers_linux.go; the pipe's session.rs): the entry holds
// the trunk to two receivers, the same exit for a client at two addresses
// on the same ports, 127.0.0.1 and 127.0.0.2 here. Each receiver is a Go
// exit (trunk.Exit) behind a bare UDP wire and a pool's port; both hand the
// clients' traffic to the same echoes, as two relays of one group serve the
// same clients.

// receiver is one exit at ip: its wire and pool on ports shared with the
// other receiver, killable.
type receiver struct {
	x    *trunk.Exit
	ip   netip.Addr
	wire *udpwire.Listener
	pool net.Listener
	mu   sync.Mutex
	conn []net.Conn
}

func newReceiver(t *testing.T, ctx context.Context, ip netip.Addr, wirePort, poolPort uint16) (*receiver, error) {
	r := &receiver{x: trunk.NewExit(trunk.Config{}, local{}), ip: ip}
	go r.x.Run(ctx)
	w, err := udpwire.Listen(netip.AddrPortFrom(ip, wirePort).String(), []string{testKey}, func(c io.ReadWriteCloser) { _ = r.x.ServeMember(c) })
	if err != nil {
		return nil, err
	}
	pl, err := net.Listen("tcp", netip.AddrPortFrom(ip, poolPort).String())
	if err != nil {
		w.Close()
		return nil, err
	}
	r.wire, r.pool = w, pl
	t.Cleanup(r.kill)
	go func() {
		for {
			c, err := pl.Accept()
			if err != nil {
				return
			}
			r.mu.Lock()
			r.conn = append(r.conn, c)
			r.mu.Unlock()
			go func() { _ = r.x.ServeMember(c) }()
		}
	}()
	return r, nil
}

// kill takes the receiver off the net at once, as a machine gone: its wire
// and pool close, and every member of the pool with them.
func (r *receiver) kill() {
	r.wire.Close()
	r.pool.Close()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.conn {
		c.Close()
	}
	r.conn = nil
}

// killPool takes the receiver's pool off the net and leaves its wire: TCP
// to it cut, its datagrams heard (17.11 13:51, unl1).
func (r *receiver) killPool() {
	r.pool.Close()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.conn {
		c.Close()
	}
	r.conn = nil
}

// twoReceivers stands both receivers on one pair of free ports.
func twoReceivers(t *testing.T, ctx context.Context) (a, b *receiver, wirePort, poolPort uint16) {
	ipA, ipB := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")
	for try := 0; try < 20; try++ {
		wp, pp := freeUDPPort(t, ipA), freeTCPPort(t, ipA)
		ra, err := newReceiver(t, ctx, ipA, wp, pp)
		if err != nil {
			continue
		}
		rb, err := newReceiver(t, ctx, ipB, wp, pp)
		if err != nil {
			ra.kill()
			continue
		}
		return ra, rb, wp, pp
	}
	t.Fatal("no pair of ports free on both receivers")
	return nil, nil, 0, 0
}

func freeUDPPort(t *testing.T, ip netip.Addr) uint16 {
	c, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).AddrPort().Port()
}

func freeTCPPort(t *testing.T, ip netip.Addr) uint16 {
	l, err := net.Listen("tcp", netip.AddrPortFrom(ip, 0).String())
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	p, _ := strconv.Atoi(l.Addr().(*net.TCPAddr).AddrPort().String()[len(ip.String())+1:])
	return uint16(p)
}

// receiversPipe is a pipe under this brain to receiver a: a bare UDP wire
// of 4 members carrying voice, a pool of 4 carrying streams, a client port
// of each; b on standby with a pool of 2.
func receiversPipe(t *testing.T, a, b *receiver, wirePort, poolPort uint16) (p *Pipe, voice netip.AddrPort, streams string) {
	p, err := Start(Config{Bin: pipeBin(t), Args: []string{"--flow-idle-ms", "500"}, Stderr: os.Stderr, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	if err := p.SetWire(Wire{ID: dgramWire, Name: "udp", Exit: netip.AddrPortFrom(a.ip, wirePort), Key: testKey, Members: 4}); err != nil {
		t.Fatal(err)
	}
	if err := p.SetPool(Pool{ID: trunk.PoolWire, Members: 4, Exit: netip.AddrPortFrom(a.ip, poolPort)}); err != nil {
		t.Fatal(err)
	}
	p.SetRoute(trunk.Route{Voice: dgramWire, Bulk: trunk.PoolWire})
	waitFor(t, 10*time.Second, "the active receiver's members up", func() bool {
		return wireUp(p, dgramWire, 4) && wireUp(p, trunk.PoolWire, 4)
	})
	lc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lc.Close() })
	if err := p.Listen(0, lc, trunk.ClassVoice, udpEcho(t), 1); err != nil {
		t.Fatal(err)
	}
	tl, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.TCPListen(1, tl, tcpEcho(t)); err != nil {
		t.Fatal(err)
	}
	if err := p.SetReceiver(1, b.ip, 2); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "receiver 1 warm on standby", func() bool { return standbyUp(p, 1, 4, 2) })
	return p, lc.LocalAddr().(*net.UDPAddr).AddrPort(), tl.Addr().String()
}

// standbyUp: the pipe says receiver rx on standby with its wire's members
// all up (wire of them) and its pool's (pool of them).
func standbyUp(p *Pipe, rx byte, wire, pool int) bool {
	rs, _ := p.Receivers()
	for _, r := range rs.Standby {
		if r.Rx != rx {
			continue
		}
		var w, pl bool
		for _, x := range r.Wires {
			w = w || x.ID == dgramWire && x.Members == wire && x.Up == wire
			pl = pl || x.ID == trunk.PoolWire && x.Members == pool && x.Up == pool
		}
		return w && pl
	}
	return false
}

// TestAStandbyReceiverIsWarmAndCarriesNothing: receiver 1 on standby has
// its members up at its own address, and a call and a stream through the
// pipe reach receiver 0 alone.
func TestAStandbyReceiverIsWarmAndCarriesNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	a, b, wp, pp := twoReceivers(t, ctx)
	p, voice, streams := receiversPipe(t, a, b, wp, pp)
	k := newCaller(t, voice)
	k.call()
	c, err := net.Dial("tcp", streams)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := echoed(c, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	k.hangUp()
	checkCall(t, "the call on receiver 0", k, 0, 150*time.Millisecond)
	if st := stats(b.x); st.Flows != 0 || st.StreamsOpened != 0 || st.Members != 6 {
		t.Errorf("receiver 1 on standby: %d flows, %d streams, %d members; want 0, 0 and its 6", st.Flows, st.StreamsOpened, st.Members)
	}
	if st := stats(a.x); st.Flows != 1 || st.StreamsOpened != 1 {
		t.Errorf("receiver 0: %d flows, %d streams; want the call and the stream", st.Flows, st.StreamsOpened)
	}
	if rs, _ := p.Receivers(); rs.Active != 0 || len(rs.Standby) != 1 || rs.Standby[0].IP != b.ip {
		t.Errorf("the pipe's receivers %+v, want 0 active and 1 at %s on standby", rs, b.ip)
	}
}

// TestTheActiveReceiverDiesAndTheEntryMovesUnderACallAndAStream: receiver 0
// dies under a call and a stream; the brain makes receiver 1 the active one.
// The stream on 0 is cut at once (not left to its timeout) and a new one
// goes through 1 byte for byte; the call's next datagrams land on 1 and it
// comes back; receiver 0 is on standby, its members down as it is dead;
// the brain's new members of the bare UDP wire dial receiver 1.
func TestTheActiveReceiverDiesAndTheEntryMovesUnderACallAndAStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	a, b, wp, pp := twoReceivers(t, ctx)
	p, voice, streams := receiversPipe(t, a, b, wp, pp)
	k := newCaller(t, voice)
	k.call()
	old, err := net.Dial("tcp", streams)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	if err := echoOpen(old, 64<<10); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)

	a.kill()
	died := time.Now()
	time.Sleep(200 * time.Millisecond)
	if err := p.SetActive(1, b.ip); err != nil {
		t.Fatal(err)
	}
	cut := make(chan error, 1)
	go func() {
		_ = old.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, err := old.Read(make([]byte, 1))
		cut <- err
	}()
	select {
	case err := <-cut:
		var ne net.Error
		if err == nil || errors.As(err, &ne) && ne.Timeout() {
			t.Errorf("the stream on the dead receiver was not cut: %v", err)
		}
	case <-time.After(4 * time.Second):
		t.Error("the stream on the dead receiver hangs")
	}
	moved := time.Since(died)

	fresh, err := net.Dial("tcp", streams)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if err := echoed(fresh, 4<<20, nil); err != nil {
		t.Fatalf("a new stream after the move: %v", err)
	}
	time.Sleep(time.Second)
	k.hangUp()
	sent, back, gap := k.heard()
	t.Logf("the stream cut %v after the receiver died; the call: %d sent, %d back, longest pause %v", moved, sent, back, gap)
	if st := stats(b.x); st.Flows != 1 || st.StreamsOpened != 1 {
		t.Errorf("receiver 1 after the move: %d flows, %d streams; want the call and the new stream", st.Flows, st.StreamsOpened)
	}
	if gap > 1500*time.Millisecond {
		t.Errorf("the call paused %v across the move, want under 1.5 s (the 200 ms before it included)", gap)
	}
	rs, _ := p.Receivers()
	if rs.Active != 1 || len(rs.Standby) != 1 || rs.Standby[0].Rx != 0 || rs.Standby[0].IP != a.ip {
		t.Errorf("the pipe's receivers %+v, want 1 active and 0 at %s on standby", rs, a.ip)
	}
	// The brain renews a member of the wire on receiver 1, not on the dead 0.
	waitFor(t, 5*time.Second, "the wire's members on receiver 1", func() bool { return wireUp(p, dgramWire, 4) })
}

// TestAMoveByHandCutsWhatTheOldReceiverCarriesAtOnce: both receivers alive,
// the brain moves the entry to receiver 1 (by hand, or back from a
// standby). The stream on receiver 0 is cut by the move itself, not by any
// death, and the call goes on through receiver 1 with no answer lost for
// long; receiver 0 stays warm on standby.
func TestAMoveByHandCutsWhatTheOldReceiverCarriesAtOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	a, b, wp, pp := twoReceivers(t, ctx)
	p, voice, streams := receiversPipe(t, a, b, wp, pp)
	k := newCaller(t, voice)
	k.call()
	old, err := net.Dial("tcp", streams)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	if err := echoOpen(old, 64<<10); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	moved := time.Now()
	if err := p.SetActive(1, b.ip); err != nil {
		t.Fatal(err)
	}
	_ = old.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = old.Read(make([]byte, 1))
	var ne net.Error
	if err == nil || errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("the stream on receiver 0 was not cut by the move: %v", err)
	}
	t.Logf("the stream cut %v after the move", time.Since(moved))
	if d := time.Since(moved); d > 500*time.Millisecond {
		t.Errorf("the stream cut %v after the move, want at once", d)
	}
	fresh, err := net.Dial("tcp", streams)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if err := echoed(fresh, 1<<20, nil); err != nil {
		t.Fatalf("a new stream after the move: %v", err)
	}
	time.Sleep(time.Second)
	k.hangUp()
	sent, back, gap := k.heard()
	t.Logf("the call: %d sent, %d back, longest pause %v", sent, back, gap)
	if gap > 300*time.Millisecond {
		t.Errorf("the call paused %v across a move between live receivers", gap)
	}
	if st := stats(b.x); st.Flows != 1 || st.StreamsOpened != 1 {
		t.Errorf("receiver 1 after the move: %d flows, %d streams; want the call and the new stream", st.Flows, st.StreamsOpened)
	}
	waitFor(t, 10*time.Second, "receiver 0 warm on standby", func() bool { return standbyUp(p, 0, 4, 2) })
}

// TestTheActiveReceiverKeepsTheBrainsPoolAcrossMoves: the brain's pool has 4
// members, a receiver on standby keeps 2. After the entry moves to receiver
// 1 its pool grows to the brain's 4 and receiver 0 on standby keeps 2; after
// the move back, receiver 0's pool is 4 again. On 16.11 the people's entry
// moved twice under P6 and stayed on 8 members of its 32 until a reload.
func TestTheActiveReceiverKeepsTheBrainsPoolAcrossMoves(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	a, b, wp, pp := twoReceivers(t, ctx)
	p, _, streams := receiversPipe(t, a, b, wp, pp)
	if err := p.SetActive(1, b.ip); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "receiver 1's pool at the brain's 4, receiver 0 warm with 2", func() bool {
		return wireUp(p, trunk.PoolWire, 4) && standbyUp(p, 0, 4, 2)
	})
	c, err := net.Dial("tcp", streams)
	if err != nil {
		t.Fatal(err)
	}
	if err := echoed(c, 4<<20, nil); err != nil {
		t.Fatalf("a stream on receiver 1's grown pool: %v", err)
	}
	c.Close()
	waitFor(t, 10*time.Second, "receiver 1 heard", func() bool { return standbyUp(p, 0, 4, 2) })
	if err := p.SetActive(0, a.ip); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "receiver 0's pool at the brain's 4 again, receiver 1 warm with 2", func() bool {
		return wireUp(p, trunk.PoolWire, 4) && standbyUp(p, 1, 4, 2)
	})
}

// echoOpen sends size bytes on c and reads them back, leaving c open: a
// stream alive when the entry moves.
func echoOpen(c net.Conn, size int) error {
	b := make([]byte, size)
	if _, err := c.Write(b); err != nil {
		return err
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, err := io.ReadFull(c, b)
	return err
}

// TestTheBrainMovesOffADeadReceiverByItself: RunReceivers under a call and
// a stream; receiver 0 dies and nobody says anything. The entry is on
// receiver 1 within DeadAfter and a second or two of members' deaths and
// ticks, a new stream goes through it byte for byte, and the call comes
// back.
func TestTheBrainMovesOffADeadReceiverByItself(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	a, b, wp, pp := twoReceivers(t, ctx)
	p, voice, streams := receiversPipe(t, a, b, wp, pp)
	moves := make(chan Move, 4)
	go p.RunReceivers(ctx, map[byte]netip.Addr{0: a.ip, 1: b.ip}, func(m Move) { moves <- m })
	k := newCaller(t, voice)
	k.call()
	time.Sleep(2 * time.Second)
	select {
	case m := <-moves:
		t.Fatalf("moved with both receivers alive: %+v", m)
	default:
	}

	a.kill()
	died := time.Now()
	var m Move
	select {
	case m = <-moves:
	case <-time.After(DeadAfter + 4*time.Second):
		t.Fatal("no move off the dead receiver")
	}
	took := time.Since(died)
	if m.Err != nil || m.From != 0 || m.To != 1 || m.ToIP != b.ip {
		t.Fatalf("the move %+v, want 0 → 1 at %s", m, b.ip)
	}
	fresh, err := net.Dial("tcp", streams)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if err := echoed(fresh, 1<<20, nil); err != nil {
		t.Fatalf("a new stream after the move: %v", err)
	}
	time.Sleep(time.Second)
	k.hangUp()
	sent, back, gap := k.heard()
	t.Logf("moved %v after the receiver died (%s); the call: %d sent, %d back, longest pause %v", took, m.Why, sent, back, gap)
	// The members' Quiet (1 s) and a judge's step past DeadAfter.
	if took > DeadAfter+time.Second {
		t.Errorf("moved %v after the death, want within %v", took, DeadAfter+time.Second)
	}
	if gap > DeadAfter+1500*time.Millisecond {
		t.Errorf("the call paused %v", gap)
	}
	select {
	case m := <-moves:
		t.Errorf("a second move %+v", m)
	default:
	}
}

// TestTheBrainMovesOffAReceiverWhosePoolDied: the active receiver's pool
// cut and its wire heard, the brain moves by itself as for a dead receiver,
// and a new stream goes through the standby's pool.
func TestTheBrainMovesOffAReceiverWhosePoolDied(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	a, b, wp, pp := twoReceivers(t, ctx)
	p, voice, streams := receiversPipe(t, a, b, wp, pp)
	moves := make(chan Move, 4)
	go p.RunReceivers(ctx, map[byte]netip.Addr{0: a.ip, 1: b.ip}, func(m Move) { moves <- m })
	k := newCaller(t, voice)
	k.call()
	// The pool carries nothing here: the pipe keeps its proof by a ping every
	// 250 ms (keep_proof), and the judge sees it by the tick, once a second.
	var idle time.Duration
	for end := time.Now().Add(6 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		tick, at := p.Tick()
		if pool := poolOf(tick.Wires); pool != nil && pool[0].ProofAgo >= 0 {
			idle = max(idle, pool[0].ProofAgo+time.Since(at))
		}
	}
	t.Logf("the idle pool's proof at its oldest: %v (PoolDeadAfter %v)", idle.Round(time.Millisecond), PoolDeadAfter)
	select {
	case m := <-moves:
		t.Fatalf("moved with both receivers alive: %+v", m)
	default:
	}

	a.killPool()
	died := time.Now()
	var m Move
	select {
	case m = <-moves:
	case <-time.After(PoolDeadAfter + 4*time.Second):
		t.Fatal("no move off the receiver whose pool died")
	}
	took := time.Since(died)
	if m.Err != nil || m.From != 0 || m.To != 1 || m.ToIP != b.ip {
		t.Fatalf("the move %+v, want 0 → 1 at %s", m, b.ip)
	}
	if !strings.HasPrefix(m.Why, "the active receiver's pool unheard for ") {
		t.Fatalf("the move says %q, want the pool", m.Why)
	}
	fresh, err := net.Dial("tcp", streams)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if err := echoed(fresh, 1<<20, nil); err != nil {
		t.Fatalf("a new stream after the move: %v", err)
	}
	time.Sleep(time.Second)
	k.hangUp()
	sent, back, gap := k.heard()
	t.Logf("moved %v after the pool died (%s); the call: %d sent, %d back, longest pause %v", took, m.Why, sent, back, gap)
	if took > PoolDeadAfter+time.Second {
		t.Errorf("moved %v after the pool's death, want within %v", took, PoolDeadAfter+time.Second)
	}
	select {
	case m := <-moves:
		t.Errorf("a second move %+v", m)
	default:
	}
}
