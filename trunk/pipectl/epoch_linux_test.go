package pipectl

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
	"github.com/m1d1x/hikkari-protocol/trunk/udpwire"
)

// The exit restarted under the pipe's session (trunk TestExitRestart, entry.go:
// "exit epoch %x after %x: streams reset"): a new process on the same
// address, with a new epoch in its hellos and nothing of what the old one
// held. The pipe's members go silent to it and come back with new hellos;
// the new epoch must end the session's clients' flows, or the new process's
// answers, numbered anew, are copies to the old flow's window and a call
// never hears again.

// syncBuffer is the pipe's stderr.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// restartingExit is a Go exit on a udp wire address whose process can be
// replaced by a fresh one on the same address.
type restartingExit struct {
	t    *testing.T
	ctx  context.Context
	addr string
	l    io.Closer
}

func (r *restartingExit) start() {
	x := trunk.NewExit(trunk.Config{}, local{})
	go x.Run(r.ctx)
	l, err := udpwire.Listen(r.addr, []string{testKey}, func(c io.ReadWriteCloser) { _ = x.ServeMember(c) })
	if err != nil {
		r.t.Fatal(err)
	}
	r.l = l
	r.addr = l.Addr().String()
}

func TestAnExitRestartedUnderTheSessionEndsItsFlowsAndACallComesBack(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	echo := udpEcho(t)
	x := &restartingExit{t: t, ctx: ctx, addr: "127.0.0.1:0"}
	x.start()
	t.Cleanup(func() { x.l.Close() })
	logs := &syncBuffer{}
	p, err := Start(Config{Bin: pipeBin(t), Stderr: io.MultiWriter(os.Stderr, logs), Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	wire, _ := net.ResolveUDPAddr("udp", x.addr)
	if err := p.SetWire(Wire{ID: dgramWire, Name: "udp", Exit: wire.AddrPort(), Key: testKey, Members: 4}); err != nil {
		t.Fatal(err)
	}
	p.SetRoute(trunk.Route{Voice: dgramWire, Bulk: dgramWire})
	waitFor(t, 5*time.Second, "the pipe's members up", func() bool { return wireUp(p, dgramWire, 4) })
	lc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lc.Close() })
	if err := p.Listen(0, lc, trunk.ClassVoice, echo, 1); err != nil {
		t.Fatal(err)
	}
	k := newCaller(t, lc.LocalAddr().(*net.UDPAddr).AddrPort())
	k.call()
	heard := func(after time.Time) func() bool {
		return func() bool {
			k.mu.Lock()
			defer k.mu.Unlock()
			return k.last.After(after)
		}
	}
	waitFor(t, 5*time.Second, "the call heard", heard(time.Now()))
	// The exit's process is replaced: the old socket closes, a fresh exit
	// binds the same address.
	x.l.Close()
	restarted := time.Now()
	x.start()
	took := waitFor(t, 10*time.Second, "the call heard again after the exit's restart", heard(restarted))
	t.Logf("the call came back %s after the restart", took.Round(time.Millisecond))
	if !strings.Contains(logs.String(), "hk-pipe: trunk: exit epoch ") || !strings.Contains(logs.String(), "streams reset") {
		t.Errorf("the pipe did not say the exit's epochs and the reset:\n%s", logs.String())
	}
}

// restartingPool is a Go exit's pool port whose process can be replaced:
// the old one's members' connections close with it, a fresh exit takes the
// members that dial again.
type restartingPool struct {
	mu    sync.Mutex
	exit  *trunk.Exit
	conns []net.Conn
	addr  string
}

func newRestartingPool(t *testing.T, ctx context.Context) *restartingPool {
	r := &restartingPool{}
	r.replace(ctx)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	r.addr = l.Addr().String()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			r.mu.Lock()
			x := r.exit
			r.conns = append(r.conns, c)
			r.mu.Unlock()
			go func() { _ = x.ServeMember(c) }()
		}
	}()
	return r
}

// replace starts a fresh exit and closes every member of the old one.
func (r *restartingPool) replace(ctx context.Context) {
	x := trunk.NewExit(trunk.Config{}, local{})
	go x.Run(ctx)
	r.mu.Lock()
	old := r.conns
	r.exit, r.conns = x, nil
	r.mu.Unlock()
	for _, c := range old {
		c.Close()
	}
}

func (r *restartingPool) streams() int {
	r.mu.Lock()
	x := r.exit
	r.mu.Unlock()
	_, st := x.Stats()
	return st.Streams
}

// TestAStreamEndsWhenTheExitRestartsUnderIt (trunk TestExitRestart on the
// pipe): a client's stream on the pool waits for the relay's answer when the
// exit's process is replaced; its members redial into a fresh exit with a new
// epoch, and the stream it lost ends at the client instead of hanging.
func TestAStreamEndsWhenTheExitRestartsUnderIt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	x := newRestartingPool(t, ctx)
	silent := tcpEcho(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	at := l.Addr().String()
	l.Close()
	logs := &syncBuffer{}
	cmd := exec.CommandContext(ctx, pipeBin(t), "--tcp-wire", x.addr, "--tcp-listen", at, "--tcp-to", fmt.Sprint(silent),
		"--tcp-members", "2", "--members", "0", "--listen", "127.0.0.1:0", "--wire", "127.0.0.1:9")
	cmd.Stderr = io.MultiWriter(os.Stderr, logs)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	var c net.Conn
	waitFor(t, 5*time.Second, "hk-pipe's client port", func() bool {
		c, err = net.Dial("tcp", at)
		return err == nil
	})
	defer c.Close()
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
		t.Fatalf("the stream's echo before the restart: %v", err)
	}
	waitFor(t, 5*time.Second, "the stream at the exit", func() bool { return x.streams() == 1 })
	x.replace(ctx)
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, err = c.Read(make([]byte, 1))
	var ne net.Error
	if err == nil || (errors.As(err, &ne) && ne.Timeout()) {
		t.Fatalf("the stream survived the exit's restart (read: %v):\n%s", err, logs.String())
	}
	if !strings.Contains(logs.String(), "streams reset") {
		t.Errorf("the pipe did not say the exit's new epoch reset the session:\n%s", logs.String())
	}
}
