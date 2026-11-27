package pipectl

import (
	"context"
	"net"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

// TestTheBrainTakesALatePointOffThePath (spec/trunk.md, "Border points by
// quality"; plans/2026-11-28-border-points-by-quality.md): three points to
// the core, the third freezing 400 ms in every 1.2 s, as edislv1 (Riga) was
// late a quarter of the time on 27.11. Under a call of two copies and a
// stream, the judge takes the third off the path within 2 min 30 s; the
// pipe carries on the first two alone, and nothing is cut.
func TestTheBrainTakesALatePointOffThePath(t *testing.T) {
	if testing.Short() {
		t.Skip("takes two minutes")
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	core, a, b, wp, pp := coreAndPoints(t, ctx)
	c, err := newPoint(t, netip.MustParseAddr("127.0.0.4"), core.ip, wp, pp)
	if err != nil {
		t.Skipf("no third point: %v", err)
	}
	p, err := Start(Config{Bin: pipeBin(t), Args: []string{"--flow-idle-ms", "2000"}, Stderr: os.Stderr, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	if err := p.SetPoints([]netip.Addr{a.ip, b.ip, c.ip}); err != nil {
		t.Fatal(err)
	}
	wires(t, p, wp, pp)
	waitFor(t, 10*time.Second, "every member up through the three points", func() bool {
		return wireUp(p, dgramWire, 4) && wireUp(p, trunk.PoolWire, 4)
	})
	changes := make(chan PointChange, 4)
	go p.RunPoints(ctx, func(ch PointChange) { changes <- ch })
	go func() {
		for ctx.Err() == nil {
			c.freeze(400 * time.Millisecond)
			time.Sleep(1200 * time.Millisecond)
		}
	}()
	k := newCaller(t, voice0(t, p, 2))
	k.call()
	s, err := net.Dial("tcp", streams0(t, p))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := echoOpen(s, 64<<10); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	var ch PointChange
	select {
	case ch = <-changes:
	case <-time.After(150 * time.Second):
		t.Fatal("the late point stayed on the path for 2 min 30 s")
	}
	t.Logf("after %v: %s", time.Since(start).Round(time.Second), ch.Why)
	if ch.Err != nil || !slices.Equal(ch.Left, []netip.Addr{c.ip}) || !slices.Equal(ch.Path, []netip.Addr{a.ip, b.ip}) {
		t.Fatalf("change %+v, want %s off and %s, %s left", ch, c.ip, a.ip, b.ip)
	}
	waitFor(t, 5*time.Second, "the pipe's points the two left", func() bool {
		ps, _ := p.Points()
		return len(ps) == 2 && ps[0].IP == a.ip && ps[1].IP == b.ip && ps[0].RTT >= 0
	})
	if err := echoOpen(s, 4<<20); err != nil {
		t.Fatalf("the stream after the point left: %v", err)
	}
	k.hangUp()
	sent, back, gap := k.heard()
	t.Logf("the call across the point leaving: %d sent, %d back, longest pause %v", sent, back, gap)
	if back < sent*99/100 {
		t.Errorf("the call: %d of %d back", back, sent)
	}
	n, st := core.x.Stats()
	if st.StreamsOpened != 1 || st.StreamsReset != 0 || n != 1 {
		t.Errorf("the core: %d streams opened, %d reset, %d sessions; want 1, 0, 1: nothing cut", st.StreamsOpened, st.StreamsReset, n)
	}
}
