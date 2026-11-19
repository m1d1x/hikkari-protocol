package pipectl

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

// rxHeard keeps each receiver's call windows as RunReceiverCalls gives them.
type rxHeard struct {
	mu sync.Mutex
	ws map[byte][]trunk.CallWindow
}

func (h *rxHeard) add(rx byte, w trunk.CallWindow) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.ws == nil {
		h.ws = map[byte][]trunk.CallWindow{}
	}
	h.ws[rx] = append(h.ws[rx], w)
}

// after is rx's windows that began at or after t.
func (h *rxHeard) after(rx byte, t time.Time) []trunk.CallWindow {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []trunk.CallWindow
	for _, w := range h.ws[rx] {
		if !w.From.Before(t) {
			out = append(out, w)
		}
	}
	return out
}

// TestACallHeldToEachReceiverHearsItThroughAMove (better.go): the brain's
// call held to each receiver hears that receiver, active or on standby; a
// move of the entry leaves each call on its own receiver (the old active
// one's on its new standby session), and a receiver dead after the move
// silences its own call alone.
func TestACallHeldToEachReceiverHearsItThroughAMove(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	a, b, wp, pp := twoReceivers(t, ctx)
	p, _, _ := receiversPipe(t, a, b, wp, pp)
	var h rxHeard
	go p.RunReceiverCalls(ctx, []byte{0, 1}, trunk.CallConfig{Copies: 1, Window: time.Second, Grace: 500 * time.Millisecond}, h.add)

	full := func(ws []trunk.CallWindow) bool {
		for _, w := range ws {
			if w.Sent < 40 || w.Got < w.Sent-1 {
				return false
			}
		}
		return len(ws) >= 2
	}
	start := time.Now().Add(time.Second)
	waitFor(t, 8*time.Second, "both receivers' calls answered", func() bool { return full(h.after(0, start)) && full(h.after(1, start)) })

	// By hand to receiver 1: each call stays on its own receiver.
	if err := p.SetActive(1, b.ip); err != nil {
		t.Fatal(err)
	}
	moved := time.Now().Add(1500 * time.Millisecond) // the old one's standby session up again
	waitFor(t, 10*time.Second, "both calls answered after the move", func() bool { return full(h.after(0, moved)) && full(h.after(1, moved)) })

	// Receiver 0, on standby now, dies: its call goes silent, receiver 1's
	// (the active one's) does not.
	a.kill()
	dead := time.Now().Add(time.Second)
	waitFor(t, 8*time.Second, "receiver 0's call silent", func() bool {
		ws := h.after(0, dead)
		return len(ws) >= 2 && ws[len(ws)-1].Got == 0 && ws[len(ws)-2].Got == 0
	})
	if ws := h.after(1, dead); !full(ws) {
		t.Fatalf("the active receiver's call after the standby died: %+v", ws)
	}
	t.Logf("receiver 0: %d windows, receiver 1: %d", len(h.after(0, start)), len(h.after(1, start)))
}
