package trunk

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"sync"
	"testing"
	"time"
)

// echoGolden is the exit's map after each frame, the same in rust/trunk
// echo.rs (echo_map_follows_go): frames in order, one skipped, one late,
// one too old, one far ahead.
var echoGolden = []struct {
	n    uint64
	want uint64
}{
	{1, 0x1}, {2, 0x3}, {3, 0x7}, {5, 0x1d}, {4, 0xf}, {70, 0x1}, {6, 0x1}, {71, 0x3}, {200, 0x1},
}

// TestTheEchoMapSaysTheFramesTheExitHad: bit i of the map an answer carries
// is frame n-i, as the exit had them so far.
func TestTheEchoMapSaysTheFramesTheExitHad(t *testing.T) {
	var m echoMap
	for _, g := range echoGolden {
		if got := m.note(g.n); got != g.want {
			t.Fatalf("frame %d: map %#x, want %#x", g.n, got, g.want)
		}
	}
	p := make([]byte, callStamped)
	binary.BigEndian.PutUint64(p, 201)
	m.stamp(p, time.Unix(0, 0x0102030405060708))
	if got := hex.EncodeToString(p); got != "00000000000000c9"+"0102030405060708"+"0000000000000003" {
		t.Fatalf("stamped %s", got)
	}
	short := []byte{0, 0, 0, 0, 0, 0, 0, 9}
	m.stamp(short, time.Now())
	if hex.EncodeToString(short) != "0000000000000009" {
		t.Fatal("a datagram too short for the stamp was changed")
	}
	m.stamp(p, time.Now())
	if got := hex.EncodeToString(p); got != "00000000000000c9"+"0102030405060708"+"0000000000000003" {
		t.Fatalf("a datagram stamped already was stamped again: %s", got)
	}
}

// lab is frames sent every 20 ms from at, heard on one or more calls.
type lab struct {
	at     time.Time
	frames []heardFrame
}

// frame adds frame i on calls with one-way delays up and down (negative:
// lost that way); the exit's clock runs off ahead of the entry's.
func (l *lab) frame(i int, off time.Duration, legs ...[2]time.Duration) {
	at := l.at.Add(time.Duration(i) * 20 * time.Millisecond)
	f := heardFrame{at: at, lead: 0}
	for _, d := range legs {
		r := &callSent{at: at}
		if d[0] >= 0 {
			r.had = true
			if d[1] >= 0 {
				r.exit = at.Add(d[0] + off).UnixNano()
				r.back = at.Add(d[0] + d[1]).UnixNano()
			}
		}
		f.legs = append(f.legs, r)
	}
	l.frames = append(l.frames, f)
}

var ms = time.Millisecond

// TestAListenerHearsEachDirectionByItsBuffer: the exit's clock 7 s ahead
// is taken off by the window's best delay; a frame 50 ms late up is a hole at
// 40 ms and not at 60; two lost in a row are a run; a second with 3 holes is
// bad; an answer lost on the way down is a hole down and on time up.
func TestAListenerHearsEachDirectionByItsBuffer(t *testing.T) {
	l := &lab{at: time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)}
	off := 7 * time.Second
	for i := 0; i < 100; i++ {
		up, down := 20*ms, 21*ms
		switch i {
		case 10:
			up = 70 * ms // 50 ms over the best: late at 40, in time at 60
		case 20, 21:
			up = -1 // lost on the way up, two in a row
		case 30:
			down = -1 // the exit had it (its map says so), the answer was lost
		case 60:
			down = 140 * ms // 119 ms over the best down: late at every buffer
		}
		l.frame(i, off, [2]time.Duration{up, down})
	}
	h := hear(l.frames)
	if h.up.Frames != 100 || h.up.Seconds != 2 {
		t.Fatalf("up judged %d frames in %d seconds, want 100 in 2", h.up.Frames, h.up.Seconds)
	}
	if h.up.Holes != [3]int{3, 2, 2} || h.up.Runs2 != [3]int{1, 1, 1} || h.up.BadS != [3]int{1, 0, 0} {
		t.Fatalf("up %+v: want holes 3/2/2, a run, one bad second at 40 ms", h.up)
	}
	if h.down.Frames != 98 || h.down.Holes != [3]int{2, 2, 2} || h.down.Runs2 != [3]int{} || h.down.BadS != [3]int{} {
		t.Fatalf("down %+v: want 98 frames judged, the lost answer and the late one", h.down)
	}
	if got := h.up.HolesPct(1); got != 2 {
		t.Fatalf("holes at 60 ms %.2f%%, want 2", got)
	}
	// An exit that stamps nothing hears nothing.
	old := &lab{at: l.at}
	old.frames = append(old.frames, heardFrame{at: l.at, legs: []*callSent{{at: l.at, answered: true}}, lead: -1})
	if h := hear(old.frames); h.up.Frames != 0 || h.down.Frames != 0 {
		t.Fatalf("an exit without a stamp heard %+v", h)
	}
}

// TestASetHearsAFrameIfOneOfItsWiresBroughtItInTime: the datagrams' wire
// loses some frames, the pool's copy comes 30 ms later and loses others; the
// set's holes are the frames both lost, and the pool's lag is 30 ms.
func TestASetHearsAFrameIfOneOfItsWiresBroughtItInTime(t *testing.T) {
	l := &lab{at: time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)}
	for i := 0; i < 50; i++ {
		udp, pool := [2]time.Duration{20 * ms, 20 * ms}, [2]time.Duration{50 * ms, 20 * ms}
		if i%5 == 0 {
			udp[0] = -1
		}
		if i == 10 || i == 31 {
			pool[0] = -1
		}
		l.frame(i, 0, udp, pool)
	}
	h := hear(l.frames)
	if h.up.Holes != [3]int{1, 1, 1} || h.up.Runs2 != [3]int{} {
		t.Fatalf("set up %+v: want the one frame both lost", h.up)
	}
	if h.down.Frames != 49 || h.down.Holes != [3]int{} {
		t.Fatalf("set down %+v: want 49 frames judged, none a hole", h.down)
	}
	if h.lagUp.N != 39 || h.lagUp.P50 != 30*ms || h.lagUp.Max != 30*ms || h.lagDown.P95 != 0 {
		t.Fatalf("lag up %+v down %+v: want the pool 30 ms behind up, even down", h.lagUp, h.lagDown)
	}
}

// TestCallsTickWithOneFrameNumberAndHearBothWays: two calls held to the pool
// side by side, a set of both, over the Go exit's echo: every frame heard in
// time both ways, by each call and by the set.
func TestCallsTickWithOneFrameNumberAndHearBothWays(t *testing.T) {
	h := newHarness(t, Config{}, 4, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	legs := map[int][]CallWindow{}
	var sets []CallSetWindow
	done := make(chan struct{})
	cfg := CallConfig{Copies: 1, Every: 10 * time.Millisecond, Window: 500 * time.Millisecond, Grace: 200 * time.Millisecond, OnWire: true, Wire: PoolWire}
	two := cfg
	two.Copies = 2
	go func() {
		defer close(done)
		RunCalls(ctx, func() CallCarrier { return h.entry.Session() }, []CallConfig{cfg, two},
			[]CallSet{{Name: "voice", Wires: func() []WireID { return []WireID{PoolWire} }}},
			CallReports{
				Leg: func(i int, w CallWindow) { mu.Lock(); legs[i] = append(legs[i], w); mu.Unlock() },
				Set: func(w CallSetWindow) { mu.Lock(); sets = append(sets, w); mu.Unlock() },
			})
	}()
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(sets) >= 3 })
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	for i := 0; i < 2; i++ {
		for _, w := range legs[i][1:] {
			if w.Wire != PoolWire || w.Up.Frames != w.Sent || w.Down.Frames != w.Sent || w.Up.Holes[0] != 0 || w.Down.Holes[0] != 0 {
				t.Fatalf("call %d window %+v: want every frame heard in time both ways", i, w)
			}
		}
	}
	if legs[0][1].Sent != legs[1][1].Sent {
		t.Fatalf("the calls sent %d and %d in one window: not one ticker", legs[0][1].Sent, legs[1][1].Sent)
	}
	for _, w := range sets[1:] {
		if w.Name != "voice" || len(w.Wires) != 1 || w.Up.Frames == 0 || w.Up.Holes[0] != 0 || w.Down.Holes[0] != 0 || w.LagUp.N == 0 {
			t.Fatalf("set window %+v: want the pool heard in time both ways, its two calls' lag", w)
		}
	}
}
