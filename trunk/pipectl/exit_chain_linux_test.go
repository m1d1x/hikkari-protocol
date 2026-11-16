package pipectl

import (
	"net"
	"testing"
	"time"
)

// TestAChainOfReloadsLeavesTheWiresToTheNewestExit: the exit reloads twice
// while a client's call still rides the first generation (A drains to B, B
// to C), as two reloads of a relay within its drain do (the hub's canary,
// then a reconfigure: unl1, 16.11). B carries nothing of its own, but A
// drains through it: B must not say it drained while A is there, or its
// relay ends it, A's end of the handoff socket closes, A takes the wires
// back beside C (spec/trunk.md, "An exit's own process replaced") and every
// datagram of the wires goes to whichever of the two the kernel picks. So:
// B says nothing until A is gone; the client's call on A and the brain's
// call on C lose nothing through both reloads and A's end; once A ends, B
// drains, and once B ends, C alone reads the wires.
func TestAChainOfReloadsLeavesTheWiresToTheNewestExit(t *testing.T) {
	r := newRustReload(t)
	p, lc := reloadPipe(t, r)
	client := lc.LocalAddr().(*net.UDPAddr).AddrPort()
	first := newCaller(t, client)
	first.call()
	time.Sleep(time.Second)
	a := r.old

	// A → B: the brain's flows and what is new go to B.
	r.reload()
	b := r.next
	waitFor(t, 5*time.Second, "the takeover by B's session", func() bool { tk := freshTick(p); return !tk.Coming && tk.Retired == 1 })
	call := startBrainCall(p, dgramWire)
	time.Sleep(time.Second)

	// B → C, A still carrying the first client's call.
	c := startRustExit(t, 2)
	if err := b.Handoff(c, 2); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "C's session at C", func() bool { return freshExit(c).Members == 4 })
	// B's session carries nothing once the brain's call moves on: it may
	// close at once, A's stays retired with the first client's call.
	waitFor(t, 5*time.Second, "the takeover by C's session", func() bool { tk := freshTick(p); return !tk.Coming && tk.Retired >= 1 })

	// B carries nothing of its own now, but A drains through it.
	select {
	case <-b.Drained():
		t.Fatalf("B said it drained while A drains through it: %+v", freshExit(b))
	case <-time.After(3 * time.Second):
	}
	checkCall(t, "the first client's call on A through both reloads", first, 0, 150*time.Millisecond)

	// A ends with its call: its relay closes it; then B carries nothing.
	first.hangUp()
	select {
	case <-a.Drained():
	case <-time.After(5 * time.Second):
		t.Fatalf("A did not drain: %+v", freshExit(a))
	}
	a.Close()
	select {
	case <-b.Drained():
	case <-time.After(5 * time.Second):
		t.Fatalf("B did not drain once A was gone: %+v", freshExit(b))
	}
	b.Close()

	// C alone reads the wires: a new call and the brain's lose nothing.
	time.Sleep(500 * time.Millisecond)
	second := newCaller(t, client)
	second.call()
	time.Sleep(1500 * time.Millisecond)
	checkCall(t, "a call after A and B ended", second, 0, 150*time.Millisecond)
	gap := call.hangUp()
	t.Logf("the brain's call: %d answers, longest pause %v", call.got.Load(), gap.Round(time.Millisecond))
	if gap > 150*time.Millisecond {
		t.Errorf("the brain's call paused %v through the chain", gap)
	}
	if f := freshExit(c).Flows; f < 1 {
		t.Errorf("C carries %d flows, want the second client's", f)
	}
}
