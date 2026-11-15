package pipectl

import (
	"context"
	"encoding/binary"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
	"github.com/m1d1x/hikkari-protocol/trunk/udpwire"
)

// Live datagrams on two fates through the pipe (step C of hikkari-client
// plans/2026-11-15-live-udp-two-fates.md; trunk fates_test.go
// TestVoiceRidesTwoFates is the Go reference): the night of 14.11 on the
// path of the udp wire, both ways, the pool clean. A call through hk-pipe
// before each exit is heard by what a listener hears: frames back by the
// best round trip plus a buffer of 60 ms.

// gilbert stands between the udp wire's members and the exit, one socket
// upstream per member, and loses datagrams by Gilbert's model in each way
// on its own: from good to bad with pBad, back with pGood, all lost while
// bad (netem's gemodel 14.7% 67% on the bench of 15.11).
type gilbert struct {
	ln          *net.UDPConn
	to          *net.UDPAddr
	pBad, pGood float64
	mu          sync.Mutex
	up          map[netip.AddrPort]*net.UDPConn
	rng         *rand.Rand
	bad         [2]bool // up, down
}

func newGilbert(t *testing.T, to netip.AddrPort, pBad, pGood float64) *gilbert {
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	g := &gilbert{ln: ln, to: net.UDPAddrFromAddrPort(to), pBad: pBad, pGood: pGood,
		up: map[netip.AddrPort]*net.UDPConn{}, rng: rand.New(rand.NewPCG(14, 11))}
	t.Cleanup(func() {
		ln.Close()
		g.mu.Lock()
		for _, u := range g.up {
			u.Close()
		}
		g.mu.Unlock()
	})
	go g.run()
	return g
}

// lost says whether the next datagram one way (0 up, 1 down) is lost.
func (g *gilbert) lost(way int) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.bad[way] {
		g.bad[way] = g.rng.Float64() >= g.pGood
	} else {
		g.bad[way] = g.rng.Float64() < g.pBad
	}
	return g.bad[way]
}

func (g *gilbert) run() {
	buf := make([]byte, 65536)
	for {
		n, from, err := g.ln.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		g.mu.Lock()
		u := g.up[from]
		if u == nil {
			if u, err = net.DialUDP("udp", nil, g.to); err != nil {
				g.mu.Unlock()
				continue
			}
			g.up[from] = u
			go g.back(u, from)
		}
		g.mu.Unlock()
		if !g.lost(0) {
			_, _ = u.Write(buf[:n])
		}
	}
}

func (g *gilbert) back(u *net.UDPConn, to netip.AddrPort) {
	b := make([]byte, 65536)
	for {
		n, err := u.Read(b)
		if err != nil {
			return
		}
		if !g.lost(1) {
			_, _ = g.ln.WriteToUDPAddrPort(b[:n], to)
		}
	}
}

func (g *gilbert) addr() netip.AddrPort { return g.ln.LocalAddr().(*net.UDPAddr).AddrPort() }

// listener is a call of frames numbered from 0, 160 B every 20 ms, and when
// the first copy of each came back.
type listener struct {
	born, back []time.Time
	mu         sync.Mutex
}

func callThrough(t *testing.T, ctx context.Context, to netip.AddrPort, frames int) *listener {
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(to))
	if err != nil {
		t.Fatal(err)
	}
	l := &listener{born: make([]time.Time, frames), back: make([]time.Time, frames)}
	go func() {
		b := make([]byte, 2048)
		for {
			n, err := c.Read(b)
			if err != nil {
				return
			}
			if n < 8 {
				continue
			}
			seq := binary.BigEndian.Uint64(b)
			l.mu.Lock()
			if seq < uint64(frames) && l.back[seq].IsZero() {
				l.back[seq] = time.Now()
			}
			l.mu.Unlock()
		}
	}()
	p := make([]byte, 160)
	tk := time.NewTicker(20 * time.Millisecond)
	defer tk.Stop()
	for i := 0; i < frames; i++ {
		select {
		case <-ctx.Done():
			t.Fatal("the call cut short")
		case <-tk.C:
		}
		binary.BigEndian.PutUint64(p, uint64(i))
		l.mu.Lock()
		l.born[i] = time.Now()
		l.mu.Unlock()
		_, _ = c.Write(p)
	}
	time.Sleep(time.Second)
	c.Close()
	return l
}

// holes are frames not back by the best round trip plus buffer, runs2 the
// holes of 2+ frames in a row (what PLC cannot hide), lost the frames never
// back.
func (l *listener) holes(buffer time.Duration) (holes, runs2, lost int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	best := time.Duration(1 << 62)
	for i, a := range l.back {
		if !a.IsZero() {
			best = min(best, a.Sub(l.born[i]))
		}
	}
	run := 0
	for i, a := range l.back {
		if a.IsZero() {
			lost++
		}
		if a.IsZero() || a.Sub(l.born[i]) > best+buffer {
			holes++
			run++
			if run == 2 {
				runs2++
			}
			continue
		}
		run = 0
	}
	return holes, runs2, lost
}

// fatesStand is an exit with a udp wire behind the night's path and a
// clean pool of plain TCP; its echo's port.
type fatesStand struct {
	wire netip.AddrPort
	pool netip.AddrPort
	echo uint16
}

func goFatesExit(t *testing.T, ctx context.Context) fatesStand {
	x := trunk.NewExit(trunk.Config{}, local{})
	go x.Run(ctx)
	l, err := udpwire.Listen("127.0.0.1:0", []string{testKey}, func(c io.ReadWriteCloser) { _ = x.ServeMember(c) })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	pl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pl.Close() })
	go func() {
		for {
			c, err := pl.Accept()
			if err != nil {
				return
			}
			go func() { _ = x.ServeMember(c) }()
		}
	}()
	return fatesStand{wire: l.Addr(), pool: netip.MustParseAddrPort(pl.Addr().String()), echo: udpEcho(t)}
}

func rustFatesExit(t *testing.T, ctx context.Context) fatesStand {
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
	return fatesStand{wire: wc.LocalAddr().(*net.UDPAddr).AddrPort(), pool: netip.MustParseAddrPort(pl.Addr().String()), echo: echo}
}

// TestVoiceRidesTwoFatesThroughThePipe: a call on a port of one copy (a
// Hikkari v1.02 client copies its call itself) through hk-pipe, the route's
// voice on the udp wire, its path the night of 14.11 both ways. One fate
// alone loses a frame in five each way, in runs; the set of the udp wire and
// the pool, answered by the exit on both, gives a listener at 60 ms under 1%
// of holes and no run of two. Before the Go exit and before hk-exit.
func TestVoiceRidesTwoFatesThroughThePipe(t *testing.T) {
	const frames = 1500 // 30 s
	for _, x := range []struct {
		name string
		mk   func(*testing.T, context.Context) fatesStand
	}{{"goexit", goFatesExit}, {"rustexit", rustFatesExit}} {
		t.Run(x.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			st := x.mk(t, ctx)
			night := newGilbert(t, st.wire, 0.147, 0.67)
			p, err := Start(Config{Bin: pipeBin(t), Stderr: os.Stderr, Logf: t.Logf})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { p.Close() })
			if err := p.SetPool(Pool{ID: trunk.PoolWire, Members: 4, Exit: st.pool}); err != nil {
				t.Fatal(err)
			}
			// The night's path loses hellos too: the members come up as
			// the path lets them.
			if err := p.SetWire(Wire{ID: dgramWire, Name: "udp", Exit: night.addr(), Key: testKey, Members: 2}); err != nil {
				t.Fatal(err)
			}
			p.SetRoute(trunk.Route{Voice: dgramWire, Bulk: trunk.PoolWire})
			waitFor(t, 20*time.Second, "the pool's and the wire's members up", func() bool {
				return wireUp(p, trunk.PoolWire, 4) && wireUp(p, dgramWire, 2)
			})
			lc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Listen(0, lc, trunk.ClassVoice, st.echo, 1); err != nil {
				t.Fatal(err)
			}
			l := callThrough(t, ctx, lc.LocalAddr().(*net.UDPAddr).AddrPort(), frames)
			holes, runs2, lost := l.holes(60 * time.Millisecond)
			h40, _, _ := l.holes(40 * time.Millisecond)
			t.Logf("%s: holes at 60 ms %.2f%% (%d), at 40 ms %.2f%%, runs of 2+ %d, lost %d of %d",
				x.name, 100*float64(holes)/frames, holes, 100*float64(h40)/frames, runs2, lost, frames)
			if holes*100 >= frames || runs2 > 0 {
				t.Errorf("holes %d of %d (want under 1%%), runs of 2+ %d (want 0)", holes, frames, runs2)
			}
		})
	}
}
