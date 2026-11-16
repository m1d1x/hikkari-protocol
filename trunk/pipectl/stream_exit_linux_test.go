package pipectl

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

// The exit's streams (R1.7, hikkari-client
// plans/2026-11-11-entry-hot-path-and-unit-economics.md, «Труба на Rust»):
// stream members on the pool's port, each over plain TCP, carrying streams
// to the loopback services, on the Go exit (trunk.Exit, the reference) and
// on the Rust exit under this brain (SetPool) alike. The entry is the Go
// one (trunk.Entry's pool, Session().Carry, as production) or the Rust one
// (hk-pipe's stream members, alone on its flags: the brain does not steer
// its streams yet). What the exit does with each frame is spec/trunk.md,
// "Streams".

// streamExit is an exit with a pool's port of plain TCP stream members.
type streamExit struct {
	pool string
	// stats: streams opened, reset (either way), chunks sent again, as of
	// now (trunk Stats.StreamsOpened, StreamsReset, Resent).
	stats func() (opened, reset, resent int64)
	rust  *rustExit
}

// streamExits are both exits under test, the reference first.
var streamExits = []struct {
	name string
	mk   func(t *testing.T, ctx context.Context, ports ...uint16) *streamExit
}{{"goexit", newGoStreamExit}, {"rustexit", newRustStreamExit}}

func onEachStreamExit(t *testing.T, f func(t *testing.T, mk func(*testing.T, context.Context, ...uint16) *streamExit)) {
	for _, x := range streamExits {
		t.Run(x.name, func(t *testing.T) { f(t, x.mk) })
	}
}

func newGoStreamExit(t *testing.T, ctx context.Context, _ ...uint16) *streamExit {
	x := trunk.NewExit(trunk.Config{}, local{})
	go x.Run(ctx)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { _ = x.ServeMember(c) }()
		}
	}()
	return &streamExit{pool: l.Addr().String(), stats: func() (int64, int64, int64) {
		_, st := x.Stats()
		return st.StreamsOpened, st.StreamsReset, st.Resent
	}}
}

// newRustStreamExit: hk-exit under this brain, its udp wire (as
// newRustExit) and the pool's listening socket, bound by the brain.
func newRustStreamExit(t *testing.T, ctx context.Context, ports ...uint16) *streamExit {
	r := newRustExit(t, ctx, ports...).(*rustExit)
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.x.SetPool(l, 0, 0); err != nil {
		t.Fatal(err)
	}
	return &streamExit{pool: l.Addr().String(), rust: r, stats: func() (int64, int64, int64) {
		tk := r.fresh()
		return int64(tk.StreamsOpened), int64(tk.ResetPeer + tk.ResetLocal), int64(tk.Resent)
	}}
}

// tcpEcho is a loopback service echoing every connection, its end after
// the client's.
func tcpEcho(t *testing.T) uint16 {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
				_ = c.(*net.TCPConn).CloseWrite()
			}()
		}
	}()
	return uint16(l.Addr().(*net.TCPAddr).Port)
}

// memberCutter stands between stream members and the exit's pool, one
// connection upstream per member, and cuts the member that carried most
// since it was asked: rst closes both sides at once (the member's socket
// fails at each end), freeze stops carrying it either way (it goes silent
// and dies by its stall).
type memberCutter struct {
	l     net.Listener
	mu    sync.Mutex
	pairs map[*cutPair]struct{}
	cuts  atomic.Int32
}

type cutPair struct {
	in, out *net.TCPConn
	moved   atomic.Int64
	frozen  atomic.Bool
}

func newMemberCutter(t *testing.T, to string) *memberCutter {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &memberCutter{l: l, pairs: map[*cutPair]struct{}{}}
	t.Cleanup(func() {
		l.Close()
		c.mu.Lock()
		for p := range c.pairs {
			p.in.Close()
			p.out.Close()
		}
		c.mu.Unlock()
	})
	go func() {
		for {
			in, err := l.Accept()
			if err != nil {
				return
			}
			out, err := net.Dial("tcp", to)
			if err != nil {
				in.Close()
				continue
			}
			p := &cutPair{in: in.(*net.TCPConn), out: out.(*net.TCPConn)}
			c.mu.Lock()
			c.pairs[p] = struct{}{}
			c.mu.Unlock()
			carry := func(dst, src *net.TCPConn) {
				buf := make([]byte, 64<<10)
				for {
					n, err := src.Read(buf)
					if n > 0 && !p.frozen.Load() {
						if _, err := dst.Write(buf[:n]); err != nil {
							return
						}
						p.moved.Add(int64(n))
					}
					if err != nil {
						return
					}
				}
			}
			go carry(p.out, p.in)
			go carry(p.in, p.out)
		}
	}()
	return c
}

func (c *memberCutter) addr() string { return c.l.Addr().String() }

// cutBusiest cuts the member that carried most so far; false when none
// carried anything.
func (c *memberCutter) cutBusiest(freeze bool) bool {
	c.mu.Lock()
	var best *cutPair
	for p := range c.pairs {
		if !p.frozen.Load() && (best == nil || p.moved.Load() > best.moved.Load()) {
			best = p
		}
	}
	if best == nil || best.moved.Load() == 0 {
		c.mu.Unlock()
		return false
	}
	delete(c.pairs, best)
	c.mu.Unlock()
	if freeze {
		best.frozen.Store(true)
		time.AfterFunc(time.Minute, func() { best.in.Close(); best.out.Close() })
	} else {
		best.in.SetLinger(0)
		best.out.SetLinger(0)
		best.in.Close()
		best.out.Close()
	}
	c.cuts.Add(1)
	return true
}

// streamEntry is an entry whose clients' TCP connections go as streams to
// an exit's loopback port: dial opens one.
type streamEntry struct {
	name string
	dial func(t *testing.T) net.Conn
	// resent is the entry's chunks sent again; -1 when it does not say.
	resent func() int64
}

// goStreamEntry: trunk.Entry with a pool of n plain TCP members to pool,
// both classes on it; each client connection is Session().Carry to port.
func goStreamEntry(t *testing.T, ctx context.Context, pool string, n int, port uint16) *streamEntry {
	ports, err := trunk.NewPortBook(20000, 30000, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	dial := func(ctx context.Context, _ int) (io.ReadWriteCloser, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", pool)
	}
	e, err := trunk.NewEntry(trunk.Config{}, n, dial, ports, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	e.SetRoute(trunk.Route{Voice: trunk.PoolWire, Bulk: trunk.PoolWire})
	go e.Run(ctx)
	waitFor(t, 5*time.Second, "the Go entry's pool up", func() bool { return e.Session().Stats().Members == n })
	return &streamEntry{name: "goentry", resent: func() int64 { return e.Session().Stats().Resent },
		dial: func(t *testing.T) net.Conn {
			client, edge := net.Pipe()
			go e.Session().Carry(edge, port)
			return client
		}}
}

// rustStreamEntry: hk-pipe alone (bench flags) with n stream members to
// pool, its client port of streams to port.
func rustStreamEntry(t *testing.T, ctx context.Context, pool string, n int, port uint16) *streamEntry {
	bin := pipeBin(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	at := l.Addr().String()
	l.Close()
	cmd := exec.CommandContext(ctx, bin, "--tcp-wire", pool, "--tcp-listen", at, "--tcp-to", fmt.Sprint(port),
		"--tcp-members", fmt.Sprint(n), "--listen", "127.0.0.1:0", "--wire", "127.0.0.1:9")
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	// Its port comes up shortly after the start; a connection made only to
	// see it would be a stream too, so the first dial waits instead.
	return &streamEntry{name: "rustentry", resent: func() int64 { return -1 },
		dial: func(t *testing.T) net.Conn {
			var c net.Conn
			waitFor(t, 5*time.Second, "hk-pipe's client port", func() bool {
				var err error
				c, err = net.Dial("tcp", at)
				return err == nil
			})
			return c
		}}
}

// echoed sends size random bytes on c, half-closes it and reads them back,
// every byte compared, then the end; during counts the bytes read so far.
func echoed(c net.Conn, size int, during *atomic.Int64) error {
	data := make([]byte, size)
	_, _ = rand.Read(data)
	errc := make(chan error, 1)
	go func() {
		_, err := c.Write(data)
		if err == nil {
			if cw, ok := c.(interface{ CloseWrite() error }); ok {
				err = cw.CloseWrite()
			}
		}
		errc <- err
	}()
	_ = c.SetReadDeadline(time.Now().Add(60 * time.Second))
	got := make([]byte, 0, size)
	buf := make([]byte, 64<<10)
	for len(got) < size {
		n, err := c.Read(buf)
		got = append(got, buf[:n]...)
		if during != nil {
			during.Add(int64(n))
		}
		if err != nil {
			return fmt.Errorf("read at %d of %d: %w", len(got), size, err)
		}
	}
	if !bytes.Equal(got, data) {
		return fmt.Errorf("echo differs")
	}
	if err := <-errc; err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// entriesFor are the entries a stream test runs through: the Go one, and
// the Rust one when HK_PIPE names it.
func entriesFor(t *testing.T, ctx context.Context, pool string, n int, port uint16) []func() *streamEntry {
	return []func() *streamEntry{
		func() *streamEntry { return goStreamEntry(t, ctx, pool, n, port) },
		func() *streamEntry { return rustStreamEntry(t, ctx, pool, n, port) },
	}
}

// TestStreamsCrossTheExitByteForByte: 4 streams of 8 MiB at once through
// each entry, echoed by a loopback service behind the exit; every byte
// comes back, every stream ends by its FINs, none is reset.
func TestStreamsCrossTheExitByteForByte(t *testing.T) {
	onEachStreamExit(t, func(t *testing.T, mk func(*testing.T, context.Context, ...uint16) *streamExit) {
		for i, name := range []string{"goentry", "rustentry"} {
			t.Run(name, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				echo := tcpEcho(t)
				x := mk(t, ctx, echo)
				e := entriesFor(t, ctx, x.pool, 4, echo)[i]()
				var wg sync.WaitGroup
				errs := make([]error, 4)
				for k := range errs {
					wg.Add(1)
					go func() {
						defer wg.Done()
						c := e.dial(t)
						defer c.Close()
						errs[k] = echoed(c, 8<<20, nil)
					}()
				}
				wg.Wait()
				for k, err := range errs {
					if err != nil {
						t.Errorf("stream %d: %v", k, err)
					}
				}
				time.Sleep(200 * time.Millisecond)
				opened, reset, _ := x.stats()
				if x.rust != nil {
					tk := x.rust.fresh()
					t.Logf("rust exit: links %d, streams open %d, opened %d, fin %d, up %d, down %d",
						tk.Links, tk.Streams, tk.StreamsOpened, tk.StreamsFin, tk.Up, tk.Down)
					if tk.StreamsFin != 4 || tk.Up != 4*8<<20 || tk.Down != 4*8<<20 || tk.Streams != 0 {
						t.Errorf("rust exit: fin %d, up %d, down %d, open %d; want 4, 32 MiB each way, 0",
							tk.StreamsFin, tk.Up, tk.Down, tk.Streams)
					}
				}
				if opened != 4 || reset != 0 {
					t.Errorf("exit opened %d streams, reset %d; want 4, 0", opened, reset)
				}
			})
		}
	})
}

// TestAStreamOutlivesItsMembersDeath: a stream of 32 MiB through each
// entry while the member that carried most dies under it, twice: its socket
// fails at both ends (rst), or it goes silent and dies by its stall
// (freeze). What it carried unconfirmed goes again on the others, both
// ways; every byte comes back in order, nothing is reset.
func TestAStreamOutlivesItsMembersDeath(t *testing.T) {
	onEachStreamExit(t, func(t *testing.T, mk func(*testing.T, context.Context, ...uint16) *streamExit) {
		for _, how := range []string{"rst", "freeze"} {
			for i, name := range []string{"goentry", "rustentry"} {
				t.Run(how+"/"+name, func(t *testing.T) {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					echo := tcpEcho(t)
					x := mk(t, ctx, echo)
					cut := newMemberCutter(t, x.pool)
					e := entriesFor(t, ctx, cut.addr(), 4, echo)[i]()
					var read atomic.Int64
					const size = 32 << 20
					go func() {
						for _, at := range []int64{4 << 20, 16 << 20} {
							for read.Load() < at && ctx.Err() == nil {
								time.Sleep(time.Millisecond)
							}
							cut.cutBusiest(how == "freeze")
						}
					}()
					c := e.dial(t)
					defer c.Close()
					if err := echoed(c, size, &read); err != nil {
						t.Fatalf("after %d cuts: %v", cut.cuts.Load(), err)
					}
					time.Sleep(200 * time.Millisecond)
					opened, reset, resent := x.stats()
					t.Logf("%d cuts; exit opened %d, reset %d, resent %d; entry resent %d", cut.cuts.Load(), opened, reset, resent, e.resent())
					if cut.cuts.Load() != 2 {
						t.Errorf("%d cuts, want 2", cut.cuts.Load())
					}
					if reset != 0 {
						t.Errorf("exit reset %d streams", reset)
					}
				})
			}
		}
	})
}
