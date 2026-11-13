package pipectl

import (
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

// Streams under the brain (R4.2, hikkari-client
// plans/2026-11-11-entry-hot-path-and-unit-economics.md, «Труба на Rust»;
// rust/pipe/src/pipe/pool.rs): the brain gives the pipe a client port of
// streams and a pool, and a reload hands the port to the next pipe. The
// exit is the Go one (trunk.Exit, its pool's port over plain TCP); the
// reference of the reload is the Go entry's generations (hikkari-control
// trunkentry handoff.go: a stream stays with the process that accepted it).

// tcpPipe is a pipe under this brain with a pool of 4 plain TCP members to
// pool, up, and no client port yet.
func tcpPipe(t *testing.T, pool string) *Pipe {
	return poolPipe(t, Pool{ID: trunk.PoolWire, Members: 4, Exit: netip.MustParseAddrPort(pool)})
}

// poolPipe is a pipe under this brain with pool w, its members up.
func poolPipe(t *testing.T, w Pool) *Pipe {
	p, err := Start(Config{Bin: pipeBin(t), Stderr: os.Stderr, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	if err := p.SetPool(w); err != nil {
		t.Fatal(err)
	}
	p.SetRoute(trunk.Route{Voice: trunk.PoolWire, Bulk: trunk.PoolWire})
	waitFor(t, 10*time.Second, "the pool's members up", func() bool { return wireUp(p, w.ID, w.Members) })
	return p
}

// TestAReloadUnderLiveStreamsCutsNone: a stream of 1 GiB runs through pipe
// a when the brain reloads a into b on the same client port of streams.
// The stream stays with a and ends byte for byte, not reset; a accepts no
// connection after the reload, b takes every new one; once the stream ends,
// a says it drained.
func TestAReloadUnderLiveStreamsCutsNone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	x := newGoStreamExit(t, ctx)
	reloadUnderStreams(t, x, Pool{ID: trunk.PoolWire, Members: 4, Exit: netip.MustParseAddrPort(x.pool)}, 1<<30)
}

// reloadUnderStreams runs a stream of size through pipe a on pool w, reloads
// a into b on the same client port of streams, and checks what the test
// above says.
func reloadUnderStreams(t *testing.T, x *streamExit, w Pool, size int) {
	echo := tcpEcho(t)
	a := poolPipe(t, w)
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.TCPListen(1, l, echo); err != nil {
		t.Fatal(err)
	}
	at := l.Addr().String()
	// The next pipe, its pool up first, as the brain brings it up.
	b := poolPipe(t, w)

	c1, err := net.Dial("tcp", at)
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	var moved atomic.Int64
	errc := make(chan error, 1)
	go func() { errc <- echoed(c1, size, &moved) }()
	waitFor(t, 30*time.Second, "the stream under way", func() bool { return moved.Load() > 64<<20 })

	if err := a.Handoff(b); err != nil {
		t.Fatal(err)
	}
	// The stream is a's and a new one b's: one held open on each.
	held, err := net.Dial("tcp", at)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	waitFor(t, 3*time.Second, "b's stream open", func() bool { return freshTick(b).Streams == 1 })
	at1 := moved.Load()
	if s := freshTick(a).Streams; s != 1 && moved.Load() < int64(size) {
		t.Errorf("a carries %d streams after the reload, want its one", s)
	}
	held.Close()
	for i := 0; i < 4; i++ {
		c, err := net.Dial("tcp", at)
		if err != nil {
			t.Fatal(err)
		}
		if err := echoed(c, 4<<20, nil); err != nil {
			t.Errorf("a stream after the reload: %v", err)
		}
		c.Close()
	}
	if s := freshTick(a).Streams; s > 1 {
		t.Errorf("a carries %d streams: it took one after the reload", s)
	}
	if err := <-errc; err != nil {
		t.Fatalf("the stream through the reload: %v", err)
	}
	t.Logf("the stream through the reload: %d MiB byte for byte, %d MiB of it after the reload", size>>20, (int64(size)-at1)>>20)
	if x.stats != nil {
		if opened, reset, _ := x.stats(); opened != 6 || reset != 0 {
			t.Errorf("the exit opened %d streams and reset %d; want 6 and 0", opened, reset)
		}
	}
	c1.Close()
	select {
	case <-a.Drained():
	case <-time.After(3 * time.Second):
		t.Fatal("a did not drain in 3 s after its last stream ended")
	}
}

// The pool's form: Chromium's CONNECT to the Go exit's relay channel
// (bench/go goexit -naive, its certificate's PEM written for the entry),
// from a pipe built for glibc with libcronet (rust/README.md, «Chromium
// members»): HK_PIPE that build, HK_GOEXIT the bench's goexit, HK_CRONET
// libcronet.so. Without HK_GOEXIT or HK_CRONET the test is skipped.

// naiveExit starts goexit with its relay channel on a port of its own and
// gives the pool's form to it.
func naiveExit(t *testing.T, ctx context.Context) (*streamExit, Pool) {
	bin, cronet := os.Getenv("HK_GOEXIT"), os.Getenv("HK_CRONET")
	if bin == "" || cronet == "" {
		t.Skip("HK_GOEXIT or HK_CRONET is not set: no relay channel for Chromium members")
	}
	free := func(network string) string {
		if network == "udp" {
			c, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			return c.LocalAddr().String()
		}
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.Addr().String()
	}
	naive, roots := free("tcp"), filepath.Join(t.TempDir(), "roots.pem")
	cmd := exec.CommandContext(ctx, bin, "-naive", naive, "-naive-roots", roots, "-wire", free("udp"), "-pool", free("tcp"))
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	var pem []byte
	waitFor(t, 5*time.Second, "goexit's certificate", func() bool {
		b, err := os.ReadFile(roots)
		pem = b
		return err == nil && len(b) > 0
	})
	w := Pool{ID: trunk.PoolWire, Members: 4, Exit: netip.MustParseAddrPort(naive),
		Chromium: &ChromiumForm{SNI: "hk.example", Key: "bench-trunk-key-0123456789abcdef", Cronet: cronet, Roots: string(pem)}}
	// The exit is another process: what it counts the test does not see.
	return &streamExit{pool: naive, stats: nil}, w
}

// TestAChromiumPoolUnderTheBrainCarriesStreamsThroughAReload: the same
// reload as above with the pool in its form, Chromium's CONNECT: the brain
// gives the form (domain, key, libcronet, roots), the pipe dials its
// members on one engine, and a stream of 1 GiB goes through the reload
// byte for byte.
func TestAChromiumPoolUnderTheBrainCarriesStreamsThroughAReload(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	x, w := naiveExit(t, ctx)
	reloadUnderStreams(t, x, w, 1<<30)
}
