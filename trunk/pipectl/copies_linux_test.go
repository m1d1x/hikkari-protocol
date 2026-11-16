package pipectl

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

// Copies on the pool (spec/trunk.md, "Copies on the pool"; hikkari-client
// plans/2026-11-15-pool-copy-coalescing.md, steps B and C): K members of the
// pool carry the copies of the voice set, a window at a time in one write,
// at both ends; a member of copies that dies gives its place with no hole.

// poolTap stands between the pipe's pool and the exit's pool port: each
// member's connection through it, its bytes and reads counted each way, so
// a test sees the writes of each end (each end writes with Nagle off, one
// segment a write) and can cut one member.
type poolTap struct {
	ln    *net.TCPListener
	to    netip.AddrPort
	mu    sync.Mutex
	conns []*tapped
}

type tapped struct {
	in, out    net.Conn
	upBytes    atomic.Int64
	upReads    atomic.Int64
	downReads  atomic.Int64
	downBytes  atomic.Int64
	cut        atomic.Bool
	lastUpRead atomic.Int64
}

func newPoolTap(t *testing.T, to netip.AddrPort) *poolTap {
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	p := &poolTap{ln: ln, to: to}
	t.Cleanup(func() {
		ln.Close()
		p.mu.Lock()
		defer p.mu.Unlock()
		for _, c := range p.conns {
			c.in.Close()
			c.out.Close()
		}
	})
	go p.run()
	return p
}

func (p *poolTap) addr() netip.AddrPort { return p.ln.Addr().(*net.TCPAddr).AddrPort() }

func (p *poolTap) run() {
	for {
		in, err := p.ln.AcceptTCP()
		if err != nil {
			return
		}
		out, err := net.DialTCP("tcp", nil, net.TCPAddrFromAddrPort(p.to))
		if err != nil {
			in.Close()
			continue
		}
		in.SetNoDelay(true)
		out.SetNoDelay(true)
		c := &tapped{in: in, out: out}
		p.mu.Lock()
		p.conns = append(p.conns, c)
		p.mu.Unlock()
		go pump(c, in, out, &c.upReads, &c.upBytes, &c.lastUpRead)
		go pump(c, out, in, &c.downReads, &c.downBytes, nil)
	}
}

func pump(c *tapped, from, to net.Conn, reads, bytes, last *atomic.Int64) {
	b := make([]byte, 256<<10)
	for {
		n, err := from.Read(b)
		if n > 0 {
			reads.Add(1)
			bytes.Add(int64(n))
			if last != nil {
				last.Store(time.Now().UnixNano())
			}
			if _, werr := to.Write(b[:n]); werr != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	c.in.Close()
	c.out.Close()
}

// live are the members' connections not cut, the busiest up first.
func (p *poolTap) live() []*tapped {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []*tapped
	for _, c := range p.conns {
		if !c.cut.Load() {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].upBytes.Load() > out[j].upBytes.Load() })
	return out
}

// kill cuts a member's connection both ways, as a path that resets it.
func (c *tapped) kill() {
	c.cut.Store(true)
	c.in.Close()
	c.out.Close()
}

// copiesStand is hk-pipe before hk-exit with the pool through a tap and the
// udp wire under the night's path (fates_linux_test.go), voice on the udp
// wire, the set's second fate on the pool.
type copiesStand struct {
	p      *Pipe
	tap    *poolTap
	client netip.AddrPort
}

func newCopiesStand(t *testing.T, members int, c Copies, loss bool) copiesStand {
	st := rustCopiesExit(t, c.Window)
	tap := newPoolTap(t, st.pool)
	wire := st.wire
	if loss {
		wire = newGilbert(t, st.wire, 0.147, 0.67).addr()
	}
	p, err := Start(Config{Bin: pipeBin(t), Stderr: os.Stderr, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	if err := p.SetCopies(c); err != nil {
		t.Fatal(err)
	}
	if err := p.SetPool(Pool{ID: trunk.PoolWire, Members: members, Exit: tap.addr()}); err != nil {
		t.Fatal(err)
	}
	if err := p.SetWire(Wire{ID: dgramWire, Name: "udp", Exit: wire, Key: testKey, Members: 2}); err != nil {
		t.Fatal(err)
	}
	p.SetRoute(trunk.Route{Voice: dgramWire, Bulk: trunk.PoolWire})
	waitFor(t, 20*time.Second, "the pool's and the wire's members up", func() bool {
		return wireUp(p, trunk.PoolWire, members) && wireUp(p, dgramWire, 2)
	})
	lc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Listen(0, lc, trunk.ClassVoice, st.echo, 1); err != nil {
		t.Fatal(err)
	}
	return copiesStand{p: p, tap: tap, client: lc.LocalAddr().(*net.UDPAddr).AddrPort()}
}

// rustCopiesExit is rustFatesExit's hk-exit holding its answers on members
// of copies for `window`.
func rustCopiesExit(t *testing.T, window time.Duration) fatesStand {
	x, err := StartExit(ExitConfig{Bin: exitBin(t), Stderr: os.Stderr, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { x.Close() })
	wc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if err := x.SetWire(ExitWire{ID: dgramWire, Conn: wc, Keys: []string{testKey}}); err != nil {
		t.Fatal(err)
	}
	pl, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if err := x.SetPool(pl, 0, 0); err != nil {
		t.Fatal(err)
	}
	echo := udpEcho(t)
	if err := x.SetPorts([]uint16{echo}); err != nil {
		t.Fatal(err)
	}
	if err := x.SetCopyWindow(window); err != nil {
		t.Fatal(err)
	}
	return fatesStand{wire: wc.LocalAddr().(*net.UDPAddr).AddrPort(), pool: netip.MustParseAddrPort(pl.Addr().String()), echo: echo}
}

// TestAKilledMemberOfCopiesLeavesNoHole: a call under the night's path on
// the udp wire both ways, its copies on 4 members of copies of 8, each
// window of 4 ms held at both ends. A third into the call the member that
// carries the copies is cut: the next window goes on another member at
// once, and a listener at 60 ms hears under 1% of holes and no run of two
// (step B of the plan).
func TestAKilledMemberOfCopiesLeavesNoHole(t *testing.T) {
	const frames = 1500 // 30 s
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	st := newCopiesStand(t, 8, Copies{Members: 4, Window: 4 * time.Millisecond}, true)
	go func() {
		time.Sleep(10 * time.Second)
		live := st.tap.live()
		if len(live) > 0 {
			t.Logf("cut the busiest member: %d B up", live[0].upBytes.Load())
			live[0].kill()
		}
	}()
	l := callThrough(t, ctx, st.client, frames)
	holes, runs2, lost := l.holes(60 * time.Millisecond)
	t.Logf("holes at 60 ms %.2f%% (%d), runs of 2+ %d, lost %d of %d", 100*float64(holes)/frames, holes, runs2, lost, frames)
	if holes*100 >= frames || runs2 > 0 {
		t.Errorf("holes %d of %d (want under 1%%), runs of 2+ %d (want 0)", holes, frames, runs2)
	}
	// The copies rode the members of copies alone: at most 4 members, and
	// so 5 with the one cut, carried more than their pings.
	busy := 0
	for _, c := range st.tap.live() {
		if c.upBytes.Load() > 64<<10 {
			busy++
		}
	}
	if busy > 4 {
		t.Errorf("%d members carried copies, want at most 4", busy)
	}
}

// floodThrough sends n datagrams of 160 B to the pipe's client port at
// `rate` a second and counts the answers.
func floodThrough(t *testing.T, to netip.AddrPort, n, rate int) int {
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(to))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var got atomic.Int64
	go func() {
		b := make([]byte, 2048)
		for {
			if _, err := c.Read(b); err != nil {
				return
			}
			got.Add(1)
		}
	}()
	p := make([]byte, 160)
	start := time.Now()
	for i := 0; i < n; i++ {
		binary.BigEndian.PutUint64(p, uint64(i))
		_, _ = c.Write(p)
		if d := time.Duration(i+1) * time.Second / time.Duration(rate); time.Since(start) < d {
			time.Sleep(d - time.Since(start))
		}
	}
	time.Sleep(time.Second)
	return int(got.Load())
}

// TestAWindowsCopiesGoInOneWrite: 5000 datagrams a second of voice through
// the pipe, every one copied on the pool. With 4 members of copies and a
// window of 4 ms the pool's writes at each end are 5 times fewer than the
// copies or less; with none they are about one a copy (step C of the plan).
// Every datagram comes back.
func TestAWindowsCopiesGoInOneWrite(t *testing.T) {
	const n, rate = 10000, 5000
	for _, x := range []struct {
		name string
		c    Copies
		want float64 // copies a write at least
	}{{"window", Copies{Members: 4, Window: 4 * time.Millisecond}, 5}, {"none", Copies{}, 0}} {
		t.Run(x.name, func(t *testing.T) {
			st := newCopiesStand(t, 8, x.c, false)
			time.Sleep(500 * time.Millisecond)
			var up0, down0 int64
			for _, c := range st.tap.live() {
				up0 += c.upReads.Load()
				down0 += c.downReads.Load()
			}
			got := floodThrough(t, st.client, n, rate)
			var up, down int64
			for _, c := range st.tap.live() {
				up += c.upReads.Load()
				down += c.downReads.Load()
			}
			up, down = up-up0, down-down0
			t.Logf("%s: %d copies, %d writes up (%.1f a write), %d down (%.1f a write); answers %d of %d",
				x.name, n, up, float64(n)/float64(up), down, float64(n)/float64(down), got, n)
			if got < n*99/100 {
				t.Errorf("answers %d of %d, want 99%%", got, n)
			}
			if x.want > 0 && (float64(n)/float64(up) < x.want || float64(n)/float64(down) < x.want) {
				t.Errorf("copies a write up %.1f, down %.1f; want %.0f or more", float64(n)/float64(up), float64(n)/float64(down), x.want)
			}
		})
	}
}
