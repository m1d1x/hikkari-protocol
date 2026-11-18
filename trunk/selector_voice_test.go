package trunk

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// heardAs is a minute of a call that a listener heard with bad seconds,
// runs of 2 holes and holes at the 60 ms buffer, up only, of 3000 frames.
func heardAs(to time.Time, rtt time.Duration, badS, runs2, holes int) CallWindow {
	w := calm(to, rtt)
	w.RTTP50 = rtt
	w.Up = CallHearing{Frames: 3000, Seconds: 60}
	w.Down = CallHearing{Frames: 3000, Seconds: 60}
	w.Up.BadS[voiceBuffer], w.Up.Runs2[voiceBuffer], w.Up.Holes[voiceBuffer] = badS, runs2, holes
	return w
}

// TestSelectorRanksVoiceByWhatAListenerHeard: two wires of fate udp. Bad
// seconds come first, then runs, then holes; round trips within 50 ms are
// one. A wire better than voice's main takes it after Hold, not before, and
// the pool stays in the set as the other fate all along.
func TestSelectorRanksVoiceByWhatAListenerHeard(t *testing.T) {
	for _, tc := range []struct {
		name      string
		udp, quic CallWindow
		want      WireID
	}{
		{"fewer bad seconds", heardAs(time.Time{}, 40*ms, 2, 0, 10), heardAs(time.Time{}, 90*ms, 0, 5, 90), testQuic},
		{"then fewer runs", heardAs(time.Time{}, 40*ms, 0, 3, 10), heardAs(time.Time{}, 40*ms, 0, 1, 90), testQuic},
		{"then fewer holes", heardAs(time.Time{}, 40*ms, 0, 0, 30), heardAs(time.Time{}, 40*ms, 0, 0, 3), testQuic},
		// Ties go by id: quic (1) before udp (2).
		{"rtt within 50 ms is one", heardAs(time.Time{}, 30*ms, 0, 0, 0), heardAs(time.Time{}, 70*ms, 0, 0, 0), testQuic},
		{"rtt beyond 50 ms is not", heardAs(time.Time{}, 30*ms, 0, 0, 0), heardAs(time.Time{}, 90*ms, 0, 0, 0), testUDP},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now()
			sel := NewSelector(SelectorConfig{}, selPool, selUDP, selQuic)
			tc.udp.To, tc.quic.To = now, now
			sel.Call(testUDP, tc.udp)
			sel.Call(testQuic, tc.quic)
			sel.Call(PoolWire, heardAs(now, 40*ms, 0, 0, 0))
			c := sel.Choose(now, liveAll(now, PoolWire, testUDP, testQuic))
			if c.Route.Voice != tc.want || c.Route.VoiceSet != SetOf(Carry{Wire: tc.want}, Carry{Wire: PoolWire, Copies: 1}) {
				t.Fatalf("voice %+v, want main %d and the pool", c.Route, tc.want)
			}
		})
	}

	now := time.Now()
	sel := NewSelector(SelectorConfig{}, selPool, selUDP, selQuic)
	sel.Call(testUDP, heardAs(now, 40*ms, 0, 0, 0))
	sel.Call(testQuic, heardAs(now, 40*ms, 0, 0, 30))
	if c := sel.Choose(now, liveAll(now, PoolWire, testUDP, testQuic)); c.Route.Voice != testUDP {
		t.Fatalf("first choice %+v", c.Route)
	}
	// udp turns bad; quic is better from now on.
	for at := now.Add(time.Minute); !at.After(now.Add(time.Minute + DefaultHold)); at = at.Add(time.Minute) {
		sel.Call(testUDP, heardAs(at, 40*ms, 4, 3, 60))
		sel.Call(testQuic, heardAs(at, 40*ms, 0, 0, 1))
		c := sel.Choose(at, liveAll(at, PoolWire, testUDP, testQuic))
		switch held := at.Sub(now.Add(time.Minute)); {
		case held < DefaultHold && c.Route.Voice != testUDP:
			t.Fatalf("voice moved after %s, before Hold: %+v", held, c)
		case held >= DefaultHold && (c.Route.Voice != testQuic || !strings.HasPrefix(c.Why, "voice: quic better than udp for 5m0s")):
			t.Fatalf("voice not on the better wire after Hold: %+v", c)
		}
		if !c.Route.VoiceSet.has(PoolWire) {
			t.Fatalf("the pool left the set: %+v", c.Route)
		}
	}
}

// TestSelectorGivesVoiceAThirdCopyAtOnce: 2 bad seconds of the set's last 5
// give voice one more copy on its main wire 10 ms after the first, in the
// same Choose; one bad second does not. It goes after Hold with no bad
// second, not before.
func TestSelectorGivesVoiceAThirdCopyAtOnce(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	sel := NewSelector(SelectorConfig{}, selPool, selUDP)
	two := SetOf(Carry{Wire: testUDP}, Carry{Wire: PoolWire, Copies: 1})
	three := SetOf(Carry{Wire: testUDP}, Carry{Wire: PoolWire, Copies: 1}, Carry{Wire: testUDP, Copies: 1, After: thirdCopyAfter})
	second := func(at time.Time, bad bool) {
		sel.Second(CallSecond{At: at, Set: VoiceSetName, Wire: AnyWire, Frames: 50, Bad: bad})
	}
	if c := sel.Choose(now, liveAll(now, PoolWire, testUDP)); c.Route.VoiceSet != two {
		t.Fatalf("first choice %+v", c.Route)
	}
	second(now.Add(-4*time.Second), true)
	for i := 3; i > 0; i-- {
		second(now.Add(-time.Duration(i)*time.Second), false)
	}
	if c := sel.Choose(now, liveAll(now, PoolWire, testUDP)); c.Route.VoiceSet != two {
		t.Fatalf("one bad second of 5 gave a third copy: %+v", c.Route)
	}
	t1 := now.Add(time.Second)
	second(now, true)
	c := sel.Choose(t1, liveAll(t1, PoolWire, testUDP))
	if c.Route.VoiceSet != three || c.Why != "voice: third copy on udp (2 bad seconds of 5)" {
		t.Fatalf("2 bad seconds of 5: %+v", c)
	}
	// Seconds clean from here: the copy stays for Hold after the last bad.
	for at := t1; at.Before(t1.Add(DefaultHold)); at = at.Add(30 * time.Second) {
		second(at, false)
		if c := sel.Choose(at, liveAll(at, PoolWire, testUDP)); c.Route.VoiceSet != three {
			t.Fatalf("the third copy went %s after the last bad second: %+v", at.Sub(t1), c)
		}
	}
	end := t1.Add(DefaultHold)
	second(end.Add(-time.Second), false)
	if c := sel.Choose(end, liveAll(end, PoolWire, testUDP)); c.Route.VoiceSet != two || c.Why != "voice: third copy off (no bad second for 5m0s)" {
		t.Fatalf("the third copy did not go after Hold: %+v", c)
	}
}

// TestVideoLeavesADatagramWireOnlyForAnotherOne: video has no copy, so the
// pool, TCP, is never its carrier while a wire of fate udp is up (owner's
// decisions of 15.11 and 18.11; 17.11 18:01 video went to the pool as
// "better" and stayed 64 minutes). Bad seconds move it at once to another
// datagram wire, not to the pool; with no other one it stays where it is.
// Only once every datagram wire is red does it go to the pool, and it comes
// back as soon as one is not.
func TestVideoLeavesADatagramWireOnlyForAnotherOne(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	badUDP := func(sel *Selector, wires ...WireID) {
		for i := 5; i > 0; i-- {
			at := now.Add(-time.Duration(i) * time.Second)
			sel.Second(CallSecond{At: at, Wire: testUDP, Frames: 50, Bad: i <= 3})
			for _, w := range wires {
				sel.Second(CallSecond{At: at, Wire: w, Frames: 50})
			}
		}
	}

	sel := NewSelector(SelectorConfig{}, selPool, selUDP)
	if c := sel.Choose(now, liveAll(now, PoolWire, testUDP)); c.Route.Video() != testUDP {
		t.Fatalf("video starts on %d", c.Route.Video())
	}
	badUDP(sel, PoolWire)
	if c := sel.Choose(now, liveAll(now, PoolWire, testUDP)); c.Route.Video() != testUDP || strings.Contains(c.Why, "video") {
		t.Fatalf("bad seconds of the only datagram wire put video on the pool: %+v", c)
	}
	later := now.Add(DefaultHold + time.Second)
	if c := sel.Choose(later, liveAll(later, PoolWire, testUDP)); c.Route.Video() != testUDP {
		t.Fatalf("the pool took video as better after Hold: %+v", c)
	}

	sel = NewSelector(SelectorConfig{}, selPool, selUDP, selQuic)
	sel.Choose(now, liveAll(now, PoolWire, testUDP, testQuic))
	sel.video = testUDP
	badUDP(sel, PoolWire, testQuic)
	c := sel.Choose(now, liveAll(now, PoolWire, testUDP, testQuic))
	if c.Route.Video() != testQuic || c.Why != "video: udp had 3 bad seconds of 5, to quic" {
		t.Fatalf("video did not move to the other datagram wire: %+v", c)
	}

	sel = NewSelector(SelectorConfig{}, selPool, selUDP)
	sel.Choose(now, liveAll(now, PoolWire, testUDP))
	t1 := now.Add(time.Second)
	live := liveAll(t1, PoolWire, testUDP)
	live[testUDP] = WireState{ID: testUDP, Members: 2, Proof: now, Owed: 600 * time.Millisecond}
	if c := sel.Choose(t1, live); c.Route.Video() != PoolWire {
		t.Fatalf("every datagram wire red and video not on the pool: %+v", c)
	}
	t2 := t1.Add(time.Second)
	if c := sel.Choose(t2, liveAll(t2, PoolWire, testUDP)); c.Route.Video() != testUDP {
		t.Fatalf("video stayed on the pool after udp came back: %+v", c)
	}
}

// TestASecondIsJudgedAgainstTheKeptFrames: frames of one second against the
// best delays of all the frames kept. 3 of a second's 50 frames 100 ms late
// is a bad second at 60 ms and not at 200; 2 is not bad at all; an exit that
// stamps nothing is not heard.
func TestASecondIsJudgedAgainstTheKeptFrames(t *testing.T) {
	l := &lab{at: time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)}
	for i := 0; i < 150; i++ {
		up := 20 * ms
		if i == 60 || i == 70 || i == 80 || i == 110 || i == 120 {
			up = 120 * ms
		}
		l.frame(i, 3*time.Second, [2]time.Duration{up, 20 * ms})
	}
	s1 := l.at.Add(time.Second)
	if n, bad := judgeSecond(l.frames, s1, secondVoiceBuffer); n != 50 || !bad {
		t.Fatalf("3 late of 50 at 60 ms: %d judged, bad %v", n, bad)
	}
	if _, bad := judgeSecond(l.frames, s1, secondVideoBuffer); bad {
		t.Fatal("100 ms late is bad at 200 ms")
	}
	if _, bad := judgeSecond(l.frames, s1.Add(time.Second), secondVoiceBuffer); bad {
		t.Fatal("2 late of 50 is a bad second")
	}
	old := []heardFrame{{at: l.at, legs: []*callSent{{at: l.at, answered: true}}, lead: -1}}
	if n, _ := judgeSecond(old, l.at, secondVoiceBuffer); n != 0 {
		t.Fatalf("an exit without a stamp was heard: %d", n)
	}
}

// TestCallsReportEachSecond: over the Go exit's echo, RunCalls reports each
// second of the voice set and of the call pinned to the pool, none of them
// bad, one report per second and kind.
func TestCallsReportEachSecond(t *testing.T) {
	h := newHarness(t, Config{}, 4, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	seen := map[[2]any]int{}
	var secs []CallSecond
	done := make(chan struct{})
	cfg := CallConfig{Copies: 1, Every: 20 * time.Millisecond, Window: 2 * time.Second, Grace: 500 * time.Millisecond, OnWire: true, Wire: PoolWire}
	go func() {
		defer close(done)
		RunCalls(ctx, func() CallCarrier { return h.entry.Session() }, []CallConfig{cfg},
			[]CallSet{VoiceCallSet(func() Route { return Route{Voice: PoolWire, Bulk: PoolWire} })},
			CallReports{Second: func(s CallSecond) {
				mu.Lock()
				defer mu.Unlock()
				secs = append(secs, s)
				seen[[2]any{s.At, s.Set}]++
			}})
	}()
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(secs) >= 8 })
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	sets, wires := 0, 0
	for _, s := range secs[2:] { // the first seconds start mid-way
		if s.Bad || s.Frames < 40 {
			t.Fatalf("second %+v: want about 50 frames heard in time", s)
		}
		if s.Set == VoiceSetName && s.Wire == AnyWire {
			sets++
		} else if s.Set == "" && s.Wire == PoolWire {
			wires++
		}
	}
	if sets == 0 || wires == 0 {
		t.Fatalf("seconds %+v: want the set's and the pool call's", secs)
	}
	for k, n := range seen {
		if n != 1 {
			t.Fatalf("second %v reported %d times", k, n)
		}
	}
}
