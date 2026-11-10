package trunk

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestEchoFlow: the exit sends a flow to EchoPort straight back, without a
// socket, and neither end counts it among its clients' flows and datagrams.
func TestEchoFlow(t *testing.T) {
	h := newHarness(t, Config{}, 4, nil, nil)
	got := make(chan []byte, 100)
	f := h.entry.Session().OpenFlowCopies(EchoPort, 2, func(p []byte) { got <- append([]byte(nil), p...) }, nil)
	for i := 0; i < 20; i++ {
		if !f.Send([]byte{byte(i), 9}) {
			t.Fatal("flow ended")
		}
	}
	seen := map[byte]bool{}
	timeout := time.After(10 * time.Second)
	for len(seen) < 20 {
		select {
		case p := <-got:
			if seen[p[0]] {
				t.Fatalf("answer %d delivered twice", p[0])
			}
			seen[p[0]] = true
		case <-timeout:
			t.Fatalf("%d of 20 answers came back", len(seen))
		}
	}
	_, x := h.exit.Stats()
	st := h.entry.Session().Stats()
	if st.DgramsOut != 0 || st.DgramsIn != 0 || st.DgramsCopy != 0 || st.Flows != 0 ||
		x.DgramsOut != 0 || x.DgramsIn != 0 || x.DgramsCopy != 0 || x.Flows != 0 {
		t.Fatalf("the echo counted as a client's: entry %+v exit %+v", st, x)
	}
	if h.entry.Session().Busy() {
		t.Fatal("the echo keeps the session busy: a retired session would never close")
	}
	f.Close()
	if f.Send([]byte{1}) {
		t.Fatal("a closed flow still sends")
	}
}

// TestCallOverTrunk: a call over a healthy pool gets every datagram back in
// every window, with no pause a call would hear.
func TestCallOverTrunk(t *testing.T) {
	h := newHarness(t, Config{}, 4, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var windows []CallWindow
	done := make(chan struct{})
	go func() {
		defer close(done)
		RunCall(ctx, h.entry.Session, CallConfig{Copies: 1, Every: 10 * time.Millisecond, Window: 500 * time.Millisecond, Grace: 200 * time.Millisecond},
			func(w CallWindow) { mu.Lock(); windows = append(windows, w); mu.Unlock() })
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		mu.Lock()
		n := len(windows)
		mu.Unlock()
		if n >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d windows reported in 10 s", n)
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	// The first window starts mid-way; the full ones after it are judged.
	for _, w := range windows[1:] {
		if w.Copies != 1 || w.Sent < 40 || w.Lost() != 0 || w.Sessions != 1 {
			t.Fatalf("window %+v: want ~50 sent, none lost, one session", w)
		}
		if w.RTTP50 <= 0 || w.RTTMax < w.RTTP99 || w.RTTP99 < w.RTTP50 {
			t.Fatalf("window %+v: round trips out of order", w)
		}
		if w.Gaps150 != 0 || w.GapMax > 150*time.Millisecond {
			t.Fatalf("window %+v: a pause on a healthy loopback pool", w)
		}
	}
}

// TestCallWindowPauses: the pauses between answers, the window's start and
// end counting as answers.
func TestCallWindowPauses(t *testing.T) {
	cfg := CallConfig{Copies: 1}.withDefaults()
	from := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	ms := func(n int) time.Time { return from.Add(time.Duration(n) * time.Millisecond) }
	b := &callBucket{from: from, to: from.Add(time.Second), sent: 50, got: 3,
		rtts:     []time.Duration{50 * time.Millisecond, 40 * time.Millisecond, 70 * time.Millisecond},
		arrivals: []time.Time{ms(20), ms(40), ms(540), ms(600), ms(620)}, sessions: map[*Session]bool{nil: true}}
	// Pauses: 20, 20, 500, 60, 20, then 380 to the window's end.
	w := cfg.window(b, from)
	if w.Gaps60 != 2 || w.Gaps150 != 2 || w.GapMax != 500*time.Millisecond {
		t.Fatalf("pauses %+v: want two over 60 ms and over 150 ms, the longest 500 ms", w)
	}
	if w.Silent != 480*time.Millisecond+360*time.Millisecond {
		t.Fatalf("silent %s, want 840ms", w.Silent)
	}
	if len(w.Worst) != 2 || !w.Worst[0].At.Equal(ms(40)) || w.Worst[1].Len != 380*time.Millisecond {
		t.Fatalf("worst %+v", w.Worst)
	}
	if w.RTTP50 != 50*time.Millisecond || w.RTTMax != 70*time.Millisecond || w.Lost() != 47 {
		t.Fatalf("round trips or loss %+v", w)
	}
	// Nothing came back at all: the whole window is one pause.
	w = cfg.window(&callBucket{from: from, to: from.Add(time.Second), sent: 50, sessions: map[*Session]bool{}}, from)
	if w.Gaps150 != 1 || w.GapMax != time.Second || w.Got != 0 || w.RTTP50 != 0 {
		t.Fatalf("a silent window %+v", w)
	}
}

// TestCallFollowsDrain: when the exit drains (its process is replaced), the
// call moves to the entry's new session, whose members reach the new
// process, and leaves the old one free to close.
func TestCallFollowsDrain(t *testing.T) {
	retireEvery = 20 * time.Millisecond
	defer func() { retireEvery = 5 * time.Second }()
	h := newHarness(t, Config{}, 4, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan CallWindow, 100)
	go RunCall(ctx, h.entry.Session, CallConfig{Copies: 2, Every: 10 * time.Millisecond, Window: 300 * time.Millisecond, Grace: 200 * time.Millisecond},
		func(w CallWindow) { ch <- w })
	first := h.entry.Session()
	<-ch

	old := h.exit
	next := NewExit(Config{}, h.local)
	exitCtx, exitCancel := context.WithCancel(context.Background())
	defer exitCancel()
	go next.Run(exitCtx)
	h.exit = next
	old.Drain()
	waitFor(t, func() bool { return h.entry.Session() != first && h.entry.Session().Stats().Members == 4 })
	// The old session carries nothing of a client's: retired and closed.
	waitFor(t, func() bool { return h.entry.Retired() == 0 })

	deadline := time.After(10 * time.Second)
	for {
		select {
		case w := <-ch:
			if w.From.Before(time.Now().Add(-time.Second)) || w.Sessions != 1 || w.Got == 0 {
				continue // windows from before the move
			}
			if w.Lost() > 0 {
				t.Fatalf("after the drain %+v: lost", w)
			}
			if _, st := next.Stats(); st.Members == 0 {
				t.Fatal("the new process has no members")
			}
			return
		case <-deadline:
			t.Fatal("the call did not go on after the drain")
		}
	}
}
