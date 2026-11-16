package pipectl

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

// TestAPoolCallLivesThroughAChainOfReloadsAndTheOldestsEnd: unl1, 16.11, as
// it went: the exit reloads twice (A to B, B to C) while a client's call
// still rides A, the pipe's pool and its udp wire under the brain's calls.
// B carries nothing of its own; A ends at its relay's drain limit. Through
// all of it the brain's call on the pool must keep being heard: on 16.11
// the stand's and the people's pool calls went to 0 of 3000 a minute, the
// pool's members up, until the brain was reloaded.
func TestAPoolCallLivesThroughAChainOfReloadsAndTheOldestsEnd(t *testing.T) {
	r := newRustReload(t)
	p, lc := reloadPipe(t, r)
	if err := p.SetPool(Pool{ID: trunk.PoolWire, Members: 4, Exit: netip.MustParseAddrPort(r.pool.Addr().String())}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "the pool up", func() bool { return wireUp(p, trunk.PoolWire, 4) })
	first := newCaller(t, lc.LocalAddr().(*net.UDPAddr).AddrPort())
	first.call()
	call := startBrainCall(p, trunk.PoolWire)
	defer call.hangUp()
	time.Sleep(time.Second)
	a := r.old

	r.reload()
	b := r.next
	waitFor(t, 5*time.Second, "the takeover by B's session", func() bool { tk := freshTick(p); return !tk.Coming })
	time.Sleep(2 * time.Second)
	c := startRustExit(t, 2)
	if err := b.Handoff(c, 2); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "the takeover by C's session", func() bool { return freshExit(c).Links >= 4 && !freshTick(p).Coming })
	time.Sleep(3 * time.Second)

	// B's relay ends it once it says it drained, A's once it does or at its
	// limit (here: now).
	select {
	case <-b.Drained():
		b.Close()
		t.Log("B drained and ended while A drained through it")
	case <-time.After(3 * time.Second):
	}
	time.Sleep(3 * time.Second)
	a.Close()
	select {
	case <-b.Drained():
	case <-time.After(5 * time.Second):
	}
	b.Close()
	gone := time.Now()

	deadline := gone.Add(15 * time.Second)
	for {
		before := call.got.Load()
		time.Sleep(3 * time.Second)
		heard := call.got.Load() - before
		if heard >= int64(3*time.Second/callEvery)*9/10 {
			t.Logf("the pool call hears %d answers in 3 s, %v after A and B ended", heard, time.Since(gone).Round(100*time.Millisecond))
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the pool call heard %d answers in the last 3 s, %v after A and B ended: %+v", heard, time.Since(gone).Round(100*time.Millisecond), freshTick(p))
		}
	}
}
