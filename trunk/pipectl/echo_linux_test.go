package pipectl

import (
	"context"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
	"github.com/m1d1x/hikkari-protocol/trunk/udpwire"
)

// TestTheExitStampsTheCallSoTheEntryHearsBothWays: the trunk's call over a
// wire to each exit (trunk TestCallsTickWithOneFrameNumberAndHearBothWays):
// the exit's echo writes its stamp and map (trunk echo.go, hikkari_trunk
// echo.rs), so every frame is heard up and down, in time, by the call and by
// its set.
func TestTheExitStampsTheCallSoTheEntryHearsBothWays(t *testing.T) {
	onEachExit(t, func(t *testing.T, mk func(*testing.T, context.Context, ...uint16) testExit) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		x := mk(t, ctx)
		e := newGoEntry(t, 0)
		if err := e.AddWire(trunk.Wire{ID: healthWire, Name: "udp", Shape: "random", Members: 2, Packet: true,
			Dial: udpwire.Dialer{Exit: x.addr(), Key: testKey}.Dial}); err != nil {
			t.Fatal(err)
		}
		go e.Run(ctx)
		waitFor(t, 5*time.Second, "the Go entry's members up", func() bool { return e.Wires()[healthWire].Members == 2 })
		legs := make(chan trunk.CallWindow, 64)
		sets := make(chan trunk.CallSetWindow, 64)
		cfg := trunk.CallConfig{Copies: 1, Every: 10 * time.Millisecond, Window: 500 * time.Millisecond, Grace: 200 * time.Millisecond,
			OnWire: true, Wire: healthWire}
		go trunk.RunCalls(ctx, func() trunk.CallCarrier { return e.Session() }, []trunk.CallConfig{cfg},
			[]trunk.CallSet{{Name: "voice", Wires: func() []trunk.WireID { return []trunk.WireID{healthWire} }}},
			trunk.CallReports{Leg: func(_ int, w trunk.CallWindow) { legs <- w }, Set: func(w trunk.CallSetWindow) { sets <- w }})
		<-legs // the first window starts mid-way
		<-sets
		w, s := <-legs, <-sets
		t.Logf("call: sent %d, up %+v, down %+v; set %+v", w.Sent, w.Up, w.Down, s)
		if w.Sent < 40 || w.Up.Frames != w.Sent || w.Down.Frames != w.Sent || w.Up.Holes != [3]int{} || w.Down.Holes != [3]int{} {
			t.Fatalf("call %+v: want every frame heard in time both ways", w)
		}
		if s.Up.Frames != w.Sent || s.Up.Holes != [3]int{} || s.Down.Holes != [3]int{} || len(s.Wires) != 1 {
			t.Fatalf("set %+v: want the wire's frames, all in time", s)
		}
	})
}
