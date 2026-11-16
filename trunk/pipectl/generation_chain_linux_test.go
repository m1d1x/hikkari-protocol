package pipectl

import (
	"context"
	"testing"
	"time"
)

// TestAChainOfPipeReloadsLeavesTheClientsToTheNewestPipe: the entry's pipe
// reloads twice while a client's call still rides the first generation (A
// drains to B, B to C), as two reloads of nekko-trunk-entry within A's
// drain do. B carries nothing of its own, but A drains through it: B must
// not say it drained while A is there, or its brain ends it, A's end of the
// handoff socket closes, A reads the clients' sockets again beside C, and a
// client's datagrams go to whichever of the two the kernel picks (the
// exit's same fault, unl1 16.11). So: B says nothing until A is gone; A's
// call loses nothing through both reloads (C hands A's datagrams to B, B on
// to A); once A ends B drains, and the first client's next call is C's.
func TestAChainOfPipeReloadsLeavesTheClientsToTheNewestPipe(t *testing.T) {
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
		time.Sleep(500 * time.Millisecond)
		second := newCaller(t, client)
		second.call()
		time.Sleep(time.Second)
		second.hangUp()

		c := genPipe(t, wire, 500*time.Millisecond)
		if err := b.Handoff(c); err != nil {
			t.Fatal(err)
		}
		select {
		case <-b.Drained():
			t.Fatal("B said it drained while A drains through it")
		case <-time.After(3 * time.Second):
		}
		third := newCaller(t, client)
		third.call()
		time.Sleep(time.Second)
		checkCall(t, "the first call, on A, through both reloads", first, 0, 150*time.Millisecond)
		checkCall(t, "a call after the second reload", third, 0, 150*time.Millisecond)
		if fa, fc := flowsOn(a), flowsOn(c); fa != 1 || fc != 1 {
			t.Errorf("flows: A %d, C %d; want 1 each (the first call A's, the third C's)", fa, fc)
		}

		first.hangUp()
		select {
		case <-a.Drained():
		case <-time.After(3 * time.Second):
			t.Fatal("A did not drain after its call went unused")
		}
		a.Close()
		select {
		case <-b.Drained():
		case <-time.After(3 * time.Second):
			t.Fatal("B did not drain once A was gone")
		}
		b.Close()
		time.Sleep(300 * time.Millisecond)
		first.call()
		time.Sleep(time.Second)
		checkCall(t, "the first client's next call", first, 0, 150*time.Millisecond)
		if fc := flowsOn(c); fc != 2 {
			t.Errorf("C carries %d flows, want the first and the third clients'", fc)
		}
	})
}
