package pipectl

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
	"github.com/m1d1x/hikkari-protocol/trunk/udpwire"
)

// The pipe is pipe-rs's hk-pipe, built for this box (pipe-rs/README.md):
// HK_PIPE=/path/to/hk-pipe go test ./pipectl. Without it the tests that run
// a pipe are skipped.
func pipeBin(t *testing.T) string {
	bin := os.Getenv("HK_PIPE")
	if bin == "" {
		t.Skip("HK_PIPE is not set: no pipe to run")
	}
	return bin
}

const testKey = "pipectl-test-trunk-key-0123456789"

type local struct{}

func (local) DialStream(ctx context.Context, port uint16) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
}

func (local) DialFlow(ctx context.Context, port uint16) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "udp", fmt.Sprintf("127.0.0.1:%d", port))
}

// cutter stands between a wire's members and the exit, one socket upstream
// per member as a path would map it, and drops everything both ways while
// cut: a wire cut on the path, the exit and the pipe both up.
type cutter struct {
	ln  *net.UDPConn
	to  *net.UDPAddr
	cut atomic.Bool
	mu  sync.Mutex
	up  map[netip.AddrPort]*net.UDPConn
}

func newCutter(t *testing.T, to netip.AddrPort) *cutter {
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	c := &cutter{ln: ln, to: net.UDPAddrFromAddrPort(to), up: map[netip.AddrPort]*net.UDPConn{}}
	t.Cleanup(func() {
		ln.Close()
		c.mu.Lock()
		for _, u := range c.up {
			u.Close()
		}
		c.mu.Unlock()
	})
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := ln.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if c.cut.Load() {
				continue
			}
			c.mu.Lock()
			u := c.up[from]
			if u == nil {
				u, err = net.DialUDP("udp", nil, c.to)
				if err != nil {
					c.mu.Unlock()
					continue
				}
				c.up[from] = u
				go func() {
					b := make([]byte, 65536)
					for {
						n, err := u.Read(b)
						if err != nil {
							return
						}
						if !c.cut.Load() {
							_, _ = ln.WriteToUDPAddrPort(b[:n], from)
						}
					}
				}()
			}
			c.mu.Unlock()
			_, _ = u.Write(buf[:n])
		}
	}()
	return c
}

// udpEcho is a relay's UDP port behind the exit that sends each datagram
// back; its port.
func udpEcho(t *testing.T) uint16 {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		b := make([]byte, 65536)
		for {
			n, from, err := c.ReadFromUDPAddrPort(b)
			if err != nil {
				return
			}
			_, _ = c.WriteToUDPAddrPort(b[:n], from)
		}
	}()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port)
}

func (c *cutter) addr() netip.AddrPort { return c.ln.LocalAddr().(*net.UDPAddr).AddrPort() }

// client sends a datagram every 20 ms to the pipe, as a call does, and
// notes when each answer came.
type client struct {
	c    *net.UDPConn
	mu   sync.Mutex
	got  []time.Time
	sent int
}

func runClient(ctx context.Context, t *testing.T, to netip.AddrPort) *client {
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(to))
	if err != nil {
		t.Fatal(err)
	}
	cl := &client{c: c}
	go func() {
		<-ctx.Done()
		c.Close()
	}()
	go func() {
		b := make([]byte, 2048)
		for {
			if _, err := c.Read(b); err != nil {
				return
			}
			cl.mu.Lock()
			cl.got = append(cl.got, time.Now())
			cl.mu.Unlock()
		}
	}()
	go func() {
		tk := time.NewTicker(20 * time.Millisecond)
		defer tk.Stop()
		p := make([]byte, 160)
		for seq := uint64(1); ; seq++ {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
			}
			binary.BigEndian.PutUint64(p, seq)
			_, _ = c.Write(p)
			cl.mu.Lock()
			cl.sent++
			cl.mu.Unlock()
		}
	}()
	return cl
}

// gapMax is the longest pause between answers in [from, to].
func (cl *client) gapMax(from, to time.Time) (time.Duration, int) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	var g time.Duration
	last := from
	n := 0
	for _, at := range cl.got {
		if at.Before(from) || at.After(to) {
			continue
		}
		n++
		g = max(g, at.Sub(last))
		last = at
	}
	return max(g, to.Sub(last)), n
}

func waitFor(t *testing.T, limit time.Duration, what string, ok func() bool) time.Duration {
	t.Helper()
	start := time.Now()
	for time.Since(start) < limit {
		if ok() {
			return time.Since(start)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("not in %v: %s", limit, what)
	return 0
}

func wireUp(p *Pipe, id trunk.WireID, n int) bool {
	tk, at := p.Tick()
	if time.Since(at) > 2*time.Second {
		return false
	}
	for _, w := range tk.Wires {
		if w.ID == id {
			return w.Up == n
		}
	}
	return false
}

// TestTheSelectorMovesVoiceOffACutWire is R2's ready (hikkari-client
// plans/2026-11-11-entry-hot-path-and-unit-economics.md, «Труба на Rust»):
// a Go exit, the pipe under this brain with two udp wires to it, the
// trunk's selector over the pipe's ticks and a call on each wire through the
// pipe, four clients calling through it. The wire voice is on is cut on the
// path: the selector moves voice to the other wire, and the clients' flows
// go on, none reset (the same flows at the pipe and at the exit). Healed, the
// cut wire's members come back on sockets the brain dials anew.
func TestTheSelectorMovesVoiceOffACutWire(t *testing.T) {
	bin := pipeBin(t)
	x := trunk.NewExit(trunk.Config{}, local{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go x.Run(ctx)
	l, err := udpwire.Listen("127.0.0.1:0", []string{testKey}, func(c io.ReadWriteCloser) { _ = x.ServeMember(c) })
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	cuts := map[trunk.WireID]*cutter{2: newCutter(t, l.Addr()), 3: newCutter(t, l.Addr())}

	p, err := Start(Config{Bin: bin, Stderr: os.Stderr, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	names := map[trunk.WireID]string{2: "udp-a", 3: "udp-b"}
	for _, id := range []trunk.WireID{2, 3} {
		if err := p.SetWire(Wire{ID: id, Name: names[id], Exit: cuts[id].addr(), Key: testKey, Members: 2}); err != nil {
			t.Fatal(err)
		}
	}
	lc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	// The clients' flows go to a relay behind the exit (a UDP echo on the
	// loopback), so the exit counts them as it counts a client's.
	relay := udpEcho(t)
	if err := p.Listen(0, lc, trunk.ClassVoice, relay, 1); err != nil {
		t.Fatal(err)
	}
	// Two shapes, so the warm pair is the two wires.
	sel := trunk.NewSelector(trunk.SelectorConfig{},
		trunk.Wire{ID: 2, Name: names[2], Shape: "random"}, trunk.Wire{ID: 3, Name: names[3], Shape: "browser"})
	go p.Run(ctx, sel, []trunk.WireID{2, 3}, nil, t.Logf)

	waitFor(t, 5*time.Second, "both wires up", func() bool { return wireUp(p, 2, 2) && wireUp(p, 3, 2) })
	waitFor(t, 5*time.Second, "a route for voice", func() bool { v := p.Route().Voice; return v == 2 || v == 3 })
	var clients []*client
	for i := 0; i < 4; i++ {
		clients = append(clients, runClient(ctx, t, lc.LocalAddr().(*net.UDPAddr).AddrPort()))
	}
	time.Sleep(3 * time.Second)

	on := p.Route().Voice
	other := trunk.WireID(5 - on)
	tk, _ := p.Tick()
	_, xs := x.Stats()
	flowsPipe, flowsExit := tk.Flows, xs.Flows
	t.Logf("voice on %s, flows: pipe %d, exit %d", names[on], flowsPipe, flowsExit)
	for _, cl := range clients {
		if g, n := cl.gapMax(time.Now().Add(-2*time.Second), time.Now()); n < 80 || g > 150*time.Millisecond {
			t.Fatalf("before the cut a client heard %d answers in 2 s, longest pause %v", n, g)
		}
	}

	cutAt := time.Now()
	cuts[on].cut.Store(true)
	moved := waitFor(t, 10*time.Second, "voice off the cut wire", func() bool { return p.Route().Voice == other })
	t.Logf("cut %s: voice on %s after %v", names[on], names[other], moved.Round(time.Millisecond))
	time.Sleep(3 * time.Second)
	end := time.Now()

	var gaps []time.Duration
	for i, cl := range clients {
		g, n := cl.gapMax(cutAt, end)
		gaps = append(gaps, g)
		after, m := cl.gapMax(cutAt.Add(moved).Add(time.Second), end)
		t.Logf("client %d: longest pause %v over the cut, %d answers; after the move %d answers, longest %v", i, g.Round(time.Millisecond), n, m, after.Round(time.Millisecond))
		if m < 50 || after > 150*time.Millisecond {
			t.Errorf("client %d does not go on after the move: %d answers, longest pause %v", i, m, after)
		}
	}
	sort.Slice(gaps, func(i, j int) bool { return gaps[i] < gaps[j] })
	t.Logf("pause over the cut, clients: %v", gaps)

	tk, _ = p.Tick()
	_, xs = x.Stats()
	if flowsExit != 4 {
		t.Errorf("the exit carries %d flows of the clients, want 4", flowsExit)
	}
	if tk.Flows != flowsPipe || xs.Flows != flowsExit {
		t.Errorf("flows reset by the move: pipe %d → %d, exit %d → %d", flowsPipe, tk.Flows, flowsExit, xs.Flows)
	}
	for _, w := range tk.Wires {
		t.Logf("wire %s: up %d/%d, owed %v, in %d, out %d, dgrams %d, dropped %d", names[w.ID], w.Up, w.Members, w.Owed, w.UpPkts, w.DownPkts, w.Dgrams, w.Dropped)
	}

	cuts[on].cut.Store(false)
	back := waitFor(t, 10*time.Second, "the cut wire's members back", func() bool { return wireUp(p, on, 2) })
	t.Logf("healed: %s up again after %v", names[on], back.Round(time.Millisecond))
}
