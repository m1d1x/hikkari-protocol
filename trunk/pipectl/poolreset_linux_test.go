package pipectl

// The pool reset at once under streams (17.11 13:51:25 UTC: every member of
// the pool aezamsk1 → unl1 reset in the same tenth of a second, and the
// pool took 65 s to come back while udp proved unl1 alive; hikkari-client
// plans/research/2026-11-17-pool-reset-unl1-1351.md).

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

// resetPool resets every member of the receiver's pool (RST) and keeps its
// port open: TCP to it cut once, the path whole after.
func (r *receiver) resetPool() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.conn {
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		c.Close()
	}
	r.conn = nil
}

// TestThePoolComesBackAfterEveryMemberIsReset: every member of the active
// receiver's pool reset at once under four streams of 16 MiB and a call on
// the udp wire; the path whole after. The pool is up again within a couple
// of seconds, every stream comes back byte for byte, the call goes on. A
// pool that takes a minute is the path (or the receiver), not the pipe.
func TestThePoolComesBackAfterEveryMemberIsReset(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	a, b, wp, pp := twoReceivers(t, ctx)
	p, voice, streams := receiversPipe(t, a, b, wp, pp)
	k := newCaller(t, voice)
	k.call()
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.Dial("tcp", streams)
			if err != nil {
				errs <- err
				return
			}
			defer c.Close()
			errs <- echoed(c, 16<<20, nil)
		}()
	}
	time.Sleep(700 * time.Millisecond)
	a.resetPool()
	reset := time.Now()
	waitFor(t, 2*time.Second, "a pool member down after the reset", func() bool { return !wireUp(p, trunk.PoolWire, 4) })
	waitFor(t, 30*time.Second, "the pool up again", func() bool { return wireUp(p, trunk.PoolWire, 4) })
	back := time.Since(reset)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("a stream through the reset: %v", err)
		}
	}
	done := time.Since(reset)
	k.hangUp()
	sent, got, gap := k.heard()
	t.Logf("the pool up %v after the reset, every stream done %v after it; the call %d/%d, longest pause %v",
		back.Round(time.Millisecond), done.Round(time.Millisecond), got, sent, gap)
	if limit := 3 * time.Second; back > limit {
		t.Errorf("the pool came back %v after the reset, want within %v", back, limit)
	}
	if gap > 500*time.Millisecond {
		t.Errorf("the call over udp paused %v under a reset of the pool", gap)
	}
}
