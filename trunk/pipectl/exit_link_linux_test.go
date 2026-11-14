package pipectl

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Members the brain accepts itself (R6.4.3, hikkari-client
// plans/2026-11-11-entry-hot-path-and-unit-economics.md, «Труба на Rust»): the
// relay takes a pool member's CONNECT on its own TLS and hands hk-exit one end
// of a socket pair (Exit.Link), copying the member's bytes to the other end
// (edge trunk_pipe.go). Here plain TCP stands for the relay's TLS.

// linker is the brain's side of the pool: it accepts the pipe's stream
// members and links each to the exit to, copying both ways.
type linker struct {
	l  net.Listener
	mu sync.Mutex
	to *Exit
	n  atomic.Int64
}

func startLinker(t *testing.T, to *Exit) *linker {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	k := &linker{l: l, to: to}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			k.mu.Lock()
			x := k.to
			k.mu.Unlock()
			if err := k.link(x, c); err != nil {
				t.Logf("link: %v", err)
				c.Close()
				continue
			}
			k.n.Add(1)
		}
	}()
	return k
}

// link is edge trunkPipe.serveMember with c for the relay's tunnel.
func (k *linker) link(x *Exit, c net.Conn) error {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	exitSide, relaySide := os.NewFile(uintptr(fds[0]), "member-exit"), os.NewFile(uintptr(fds[1]), "member-relay")
	defer exitSide.Close()
	defer relaySide.Close()
	if err := x.Link(exitSide); err != nil {
		return err
	}
	r, err := net.FileConn(relaySide)
	if err != nil {
		return err
	}
	go func() {
		defer c.Close()
		defer r.Close()
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(r, c); done <- struct{}{} }()
		go func() { _, _ = io.Copy(c, r); done <- struct{}{} }()
		<-done
	}()
	return nil
}

// moveTo links the members that come from now on to x.
func (k *linker) moveTo(x *Exit) {
	k.mu.Lock()
	k.to = x
	k.mu.Unlock()
}

// TestAMemberLinkedByTheBrainCarriesAStreamThroughAReload: the exit listens
// on no pool port; the brain accepts the pipe's 4 stream members and links
// each. A stream of 64 MiB goes byte for byte while the exit reloads: the old
// exit keeps the members it was given, the new session's members are linked
// to the new one, and a stream after the takeover is its own. A member before
// SetPool is refused by the brain's side.
func TestAMemberLinkedByTheBrainCarriesAStreamThroughAReload(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	tcp := tcpEcho(t)
	old := startRustExit(t, 0)
	if err := old.Link(os.Stdin); err == nil {
		t.Fatal("a member before the pool was taken")
	}
	if err := old.SetPool(nil, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := old.SetPorts([]uint16{tcp}); err != nil {
		t.Fatal(err)
	}
	k := startLinker(t, old)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	at := l.Addr().String()
	l.Close()
	cmd := exec.CommandContext(ctx, pipeBin(t), "--tcp-wire", k.l.Addr().String(), "--tcp-listen", at, "--tcp-to", fmt.Sprint(tcp),
		"--tcp-members", "4", "--members", "0", "--listen", "127.0.0.1:0", "--wire", "127.0.0.1:9")
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	waitFor(t, 5*time.Second, "the pipe's stream members linked to the exit", func() bool { return freshExit(old).Links == 4 })
	var c1 net.Conn
	waitFor(t, 5*time.Second, "hk-pipe's client port", func() bool {
		c1, err = net.Dial("tcp", at)
		return err == nil
	})
	defer c1.Close()
	var moved atomic.Int64
	errc := make(chan error, 1)
	go func() { errc <- echoed(c1, 64<<20, &moved) }()
	waitFor(t, 10*time.Second, "the stream under way", func() bool { return moved.Load() > 4<<20 })

	next := startRustExit(t, 1)
	k.moveTo(next)
	if err := old.Handoff(next, 1); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "the new session's members linked to the new exit", func() bool { return freshExit(next).Links == 4 })
	time.Sleep(200 * time.Millisecond)
	c2, err := net.Dial("tcp", at)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if err := echoed(c2, 1<<20, nil); err != nil {
		t.Errorf("the stream after the takeover: %v", err)
	}
	if err := <-errc; err != nil {
		t.Errorf("the stream through the reload: %v", err)
	}
	o, n := freshExit(old), freshExit(next)
	if o.StreamsOpened != 1 || n.StreamsOpened != 1 || o.ResetPeer+o.ResetLocal+n.ResetPeer+n.ResetLocal != 0 {
		t.Errorf("streams opened: old exit %d, new %d, reset %d; want 1, 1, 0", o.StreamsOpened, n.StreamsOpened,
			o.ResetPeer+o.ResetLocal+n.ResetPeer+n.ResetLocal)
	}
	if got := k.n.Load(); got != 8 {
		t.Errorf("the brain linked %d members, want the two sessions' 8", got)
	}
	c1.Close()
	select {
	case <-old.Drained():
	case <-time.After(5 * time.Second):
		t.Fatalf("the old exit did not drain after its stream ended: %+v", freshExit(old))
	}
}

// TestACallRidesThePoolLinkedByTheBrain: a pipe with no packet wire carries
// a client's call on the pool's members (R2.3, the pool as UDP's fallback),
// which the brain linked to hk-exit: the exit takes the datagrams off its
// stream members and answers on them, as the Go exit does. The call hears
// all its answers and no pause over 150 ms.
func TestACallRidesThePoolLinkedByTheBrain(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	udp, tcp := udpEcho(t), tcpEcho(t)
	x := startRustExit(t, 0)
	if err := x.SetPool(nil, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := x.SetPorts([]uint16{udp, tcp}); err != nil {
		t.Fatal(err)
	}
	k := startLinker(t, x)
	lc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	client := lc.LocalAddr().(*net.UDPAddr).AddrPort()
	lc.Close()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	at := l.Addr().String()
	l.Close()
	cmd := exec.CommandContext(ctx, pipeBin(t), "--tcp-wire", k.l.Addr().String(), "--tcp-listen", at, "--tcp-to", fmt.Sprint(tcp), "--tcp-members", "4",
		"--members", "0", "--listen", client.String(), "--to", fmt.Sprint(udp), "--wire", "127.0.0.1:9")
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	waitFor(t, 5*time.Second, "the pipe's stream members linked to the exit", func() bool { return freshExit(x).Links == 4 })
	c := newCaller(t, client)
	c.call()
	time.Sleep(3 * time.Second)
	c.hangUp()
	checkCall(t, "the call on the pool", c, 0, 150*time.Millisecond)
	// The flow itself ends idle once the call hangs up: its datagrams stay
	// counted.
	if tk := freshExit(x); tk.DgramsIn < 140 || tk.DgramsOut < 140 {
		t.Errorf("the exit: datagrams in %d, out %d; want the call's", tk.DgramsIn, tk.DgramsOut)
	}
}
