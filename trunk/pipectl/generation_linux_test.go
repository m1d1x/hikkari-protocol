package pipectl

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

// Generations of the pipe (R4, hikkari-client
// plans/2026-11-11-entry-hot-path-and-unit-economics.md, «Труба на Rust»;
// spec/trunk.md, "An entry's own process replaced"): a reload under a live
// call, against each exit. The Go reference is the Go entry's generations
// (hikkari-control trunkentry handoff.go, TestHandoffKeepsWhatTheEntryCarries
// there); its live numbers, a pause of 66-100 ms in the trunk's call at a
// reload: hikkari-client plans/research/2026-11-11-entry-hitless-rollout.md.

// callEvery is a call's pace, as a voice client's (and the trunk's call).
const callEvery = 20 * time.Millisecond

// caller is a client calling through the entry: a numbered datagram every
// 20 ms to the client port, answered by the relay's echo, and the longest
// pause between answers it hears.
type caller struct {
	c    *net.UDPConn
	mu   sync.Mutex
	sent uint64
	got  map[uint64]bool
	last time.Time
	gap  time.Duration
	stop chan struct{}
	done chan struct{}
}

func newCaller(t *testing.T, to netip.AddrPort) *caller {
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(to))
	if err != nil {
		t.Fatal(err)
	}
	k := &caller{c: c, got: map[uint64]bool{}}
	t.Cleanup(func() {
		k.hangUp()
		c.Close()
	})
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
			now := time.Now()
			k.mu.Lock()
			if s := binary.BigEndian.Uint64(b); !k.got[s] {
				k.got[s] = true
				if !k.last.IsZero() && now.Sub(k.last) > k.gap {
					k.gap = now.Sub(k.last)
				}
				k.last = now
			}
			k.mu.Unlock()
		}
	}()
	return k
}

// call starts calling; the pause is heard from its first answer on.
func (k *caller) call() {
	k.mu.Lock()
	k.last, k.gap = time.Time{}, 0
	k.stop, k.done = make(chan struct{}), make(chan struct{})
	stop, done := k.stop, k.done
	k.mu.Unlock()
	go func() {
		defer close(done)
		p := make([]byte, 160)
		tk := time.NewTicker(callEvery)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
			}
			k.mu.Lock()
			k.sent++
			binary.BigEndian.PutUint64(p, k.sent)
			k.mu.Unlock()
			_, _ = k.c.Write(p)
		}
	}()
}

// hangUp stops calling and lets the last answers come.
func (k *caller) hangUp() {
	k.mu.Lock()
	stop, done := k.stop, k.done
	k.stop = nil
	k.mu.Unlock()
	if stop == nil {
		return
	}
	close(stop)
	<-done
	time.Sleep(300 * time.Millisecond)
}

// heard is what the caller sent and had answered so far, and the longest
// pause between answers since it last started calling.
func (k *caller) heard() (sent, answered int, gap time.Duration) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return int(k.sent), len(k.got), k.gap
}

// genPipe is a pipe under this brain with one udp wire of 2 members to the
// exit at wire, up; flows unused for idle end (the trunk's 2 minutes for 0).
func genPipe(t *testing.T, wire netip.AddrPort, idle time.Duration) *Pipe {
	var args []string
	if idle > 0 {
		args = []string{"--flow-idle-ms", strconv.Itoa(int(idle / time.Millisecond))}
	}
	p, err := Start(Config{Bin: pipeBin(t), Args: args, Stderr: os.Stderr, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	if err := p.SetWire(Wire{ID: dgramWire, Name: "udp", Exit: wire, Key: testKey, Members: 2}); err != nil {
		t.Fatal(err)
	}
	p.SetRoute(trunk.Route{Voice: dgramWire, Bulk: dgramWire})
	waitFor(t, 5*time.Second, "the pipe's members up", func() bool { return wireUp(p, dgramWire, 2) })
	return p
}

// flowsOn is the clients' flows a pipe carries, as its next tick says.
func flowsOn(p *Pipe) int {
	asked := time.Now()
	for {
		tk, at := p.Tick()
		if at.After(asked) {
			return tk.Flows
		}
		select {
		case <-p.Done():
			return tk.Flows
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// genStand is pipe a with a client port in front of it, the exit behind.
func genStand(t *testing.T, ctx context.Context, mk exitMaker, idle time.Duration) (a *Pipe, client, wire netip.AddrPort) {
	_, wire, echo := newDgramExit(t, ctx, mk)
	a = genPipe(t, wire, idle)
	lc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lc.Close() })
	if err := a.Listen(0, lc, trunk.ClassVoice, echo, 1); err != nil {
		t.Fatal(err)
	}
	return a, lc.LocalAddr().(*net.UDPAddr).AddrPort(), wire
}

// checkCall fails t if the caller lost more than lost datagrams besides the
// 2 still in flight, or heard a pause over max.
func checkCall(t *testing.T, who string, k *caller, lost int, max time.Duration) {
	t.Helper()
	sent, answered, gap := k.heard()
	t.Logf("%s: sent %d, answered %d, longest pause %v", who, sent, answered, gap)
	if answered < sent-2-lost {
		t.Errorf("%s: %d of %d answered", who, answered, sent)
	}
	if gap > max {
		t.Errorf("%s: a pause of %v, over %v", who, gap, max)
	}
}

// TestAReloadUnderACallPausesItNoMoreThan150ms: a client calls through pipe
// a; the brain reloads it into pipe b (its wires up first) on the same
// client port. The call hears no pause over 150 ms and loses nothing: its
// flow stays with a, its datagrams read by b and handed over. A client that
// calls after the reload is b's, a takes none. Once the first client hangs
// up, a's flow ends unused, a says it drained, and the client's next call
// is b's.
func TestAReloadUnderACallPausesItNoMoreThan150ms(t *testing.T) {
	onEachExit(t, func(t *testing.T, mk exitMaker) {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		a, client, wire := genStand(t, ctx, mk, 500*time.Millisecond)
		first := newCaller(t, client)
		first.call()
		time.Sleep(time.Second)
		b := genPipe(t, wire, 500*time.Millisecond)
		if err := a.Handoff(b); err != nil {
			t.Fatal(err)
		}
		time.Sleep(300 * time.Millisecond)
		second := newCaller(t, client)
		second.call()
		time.Sleep(2 * time.Second)
		checkCall(t, "the call through the reload", first, 0, 150*time.Millisecond)
		checkCall(t, "a call after it", second, 0, 150*time.Millisecond)
		if fa, fb := flowsOn(a), flowsOn(b); fa != 1 || fb != 1 {
			t.Errorf("flows: a %d, b %d; want 1 each (the first call a's, the second b's)", fa, fb)
		}
		select {
		case <-a.Drained():
			t.Fatal("a drained while it carried a call")
		default:
		}

		first.hangUp()
		select {
		case <-a.Drained():
		case <-time.After(3 * time.Second):
			t.Fatal("a did not drain in 3 s after its last flow went unused")
		}
		first.call()
		time.Sleep(time.Second)
		checkCall(t, "the first client's next call", first, 0, 150*time.Millisecond)
		if fa, fb := flowsOn(a), flowsOn(b); fa != 0 || fb != 2 {
			t.Errorf("flows after a drained: a %d, b %d; want 0 and 2", fa, fb)
		}
	})
}

// TestAnOldPipeGoneGivesItsAddressesToTheNewOne: a pipe draining is killed
// under the call it carries; the new pipe takes the call's address at once,
// and the call goes on through it after a pause well under the trunk's 2
// minutes of a flow left to itself.
func TestAnOldPipeGoneGivesItsAddressesToTheNewOne(t *testing.T) {
	onEachExit(t, func(t *testing.T, mk exitMaker) {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		a, client, wire := genStand(t, ctx, mk, 0)
		k := newCaller(t, client)
		k.call()
		time.Sleep(500 * time.Millisecond)
		b := genPipe(t, wire, 0)
		if err := a.Handoff(b); err != nil {
			t.Fatal(err)
		}
		time.Sleep(500 * time.Millisecond)
		if fb := flowsOn(b); fb != 0 {
			t.Fatalf("b carries %d flows before a is gone, want 0", fb)
		}
		a.Close()
		time.Sleep(time.Second)
		// What a held when it was killed is lost: its socket's datagrams.
		checkCall(t, "the call through a's end", k, 10, 300*time.Millisecond)
		if fb := flowsOn(b); fb != 1 {
			t.Errorf("b carries %d flows after a is gone, want 1", fb)
		}
	})
}
