package pipectl

// better.go: the entry moves to a better live receiver, not only off a dead
// one (judge.go). The brain calls each receiver through the pipe, active or
// on standby, one flow held to it (AtReceiver, rust/pipe session.rs
// rehome_held), a datagram every 20 ms as the trunk's call; the judge hears
// each minute of each call (Hear) and compares the receivers by the same
// measure on the same minutes.
//
// A move cuts every client's streams and flows, so it is paid once and must
// win for long: the active receiver is worse BetterMinutes minutes in a row
// after the latest move (each with WorsePauses pauses over 150 ms or loss
// past WorseLoss), a heard standby clean in each of the same minutes (no
// pause over 150 ms, loss under CleanLoss), and no move to a better one in
// BetterHold. The spike's threshold is one pause over 150 ms an hour of a
// call; 19.11 on ams3 the people's call had 1–8 a minute, 39 minutes of 39.
// A death is not waited for: the move off a dead receiver (judge.go) comes
// in DeadAfter as before, and it clears BetterHold, since the receiver it
// lands on is the one that woke first, not the best.

import (
	"fmt"
	"sort"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

const (
	// BetterMinutes minutes in a row the active receiver is worse and a
	// standby clean before the entry moves: three minutes of a red call
	// against one cut of every client.
	BetterMinutes = 3
	// WorsePauses pauses over 150 ms in a minute, or WorseLoss of the call
	// lost, make a minute worse; a clean minute has none and under
	// CleanLoss lost. A minute with one pause is neither: it moves no one.
	WorsePauses = 2
	WorseLoss   = 0.02
	CleanLoss   = 0.01
	// BetterHold is how long after a move to a better receiver the next
	// waits: two receivers worse by turns cut the clients at most three
	// times an hour.
	BetterHold = 20 * time.Minute
	// rxCallKept is how many minutes of each receiver's call the judge keeps.
	rxCallKept = BetterMinutes + 2
)

// RxWindow is a minute of the call held to receiver Rx.
type RxWindow struct {
	Rx      byte
	From    time.Time
	Sent    int
	Got     int
	Gaps150 int
}

// RxWindowOf is the call's window w as the judge reads it.
func RxWindowOf(rx byte, w trunk.CallWindow) RxWindow {
	return RxWindow{Rx: rx, From: w.From, Sent: w.Sent, Got: w.Got, Gaps150: w.Gaps150}
}

func (w RxWindow) loss() float64 {
	if w.Sent <= 0 {
		return 1
	}
	return float64(w.Sent-w.Got) / float64(w.Sent)
}

func (w RxWindow) worse() bool { return w.Gaps150 >= WorsePauses || w.loss() > WorseLoss }
func (w RxWindow) clean() bool { return w.Sent > 0 && w.Gaps150 == 0 && w.loss() < CleanLoss }

// Hear takes a minute of the call held to a receiver.
func (j *Judge) Hear(w RxWindow) {
	if j.calls == nil {
		j.calls = map[byte][]RxWindow{}
	}
	ws := append(j.calls[w.Rx], w)
	sort.Slice(ws, func(a, b int) bool { return ws[a].From.Before(ws[b].From) })
	if len(ws) > rxCallKept {
		ws = ws[len(ws)-rxCallKept:]
	}
	j.calls[w.Rx] = ws
}

// lastMinutes is rx's latest BetterMinutes minutes in a row, all after
// since; nil when there are not as many.
func (j *Judge) lastMinutes(rx byte, since time.Time) []RxWindow {
	ws := j.calls[rx]
	if len(ws) < BetterMinutes {
		return nil
	}
	ws = ws[len(ws)-BetterMinutes:]
	if ws[0].From.Before(since) {
		return nil
	}
	for i := 1; i < len(ws); i++ {
		if d := ws[i].From.Sub(ws[i-1].From); d < 30*time.Second || d > 90*time.Second {
			return nil
		}
	}
	return ws
}

// minuteOf is rx's minute that began at from, or false.
func (j *Judge) minuteOf(rx byte, from time.Time) (RxWindow, bool) {
	for _, w := range j.calls[rx] {
		if d := w.From.Sub(from); d > -time.Second && d < time.Second {
			return w, true
		}
	}
	return RxWindow{}, false
}

// better is the move to a better receiver, or a hold, while the active
// receiver is heard.
func (j *Judge) better(now time.Time, rs Receivers) Verdict {
	held := Verdict{Why: "the active receiver is heard"}
	if len(rs.Standby) == 0 {
		return held
	}
	if !j.movedAt.IsZero() && now.Sub(j.movedAt) < Settle || !j.betterAt.IsZero() && now.Sub(j.betterAt) < BetterHold {
		return held
	}
	act := j.lastMinutes(rs.Active, j.movedAt)
	if act == nil {
		return held
	}
	pauses := 0
	for _, w := range act {
		if !w.worse() {
			return held
		}
		pauses += w.Gaps150
	}
	best, bestUp := -1, 0
	for i, r := range rs.Standby {
		if !heardWithin(r.Wires, DeadAfter) {
			continue
		}
		clean := true
		for _, a := range act {
			w, ok := j.minuteOf(r.Rx, a.From)
			if !ok || !w.clean() {
				clean = false
				break
			}
		}
		if clean {
			if up := membersUp(r.Wires); best < 0 || up > bestUp {
				best, bestUp = i, up
			}
		}
	}
	if best < 0 {
		return Verdict{Why: "the active receiver is worse, no standby is clean beside it"}
	}
	to := rs.Standby[best].Rx
	j.movedAt, j.betterAt = now, now
	return Verdict{Move: true, To: to, Why: fmt.Sprintf("the active receiver worse for %d min (%d pauses over 150 ms, %s lost), receiver %d clean the same minutes",
		BetterMinutes, pauses, lossOf(act), to)}
}

// lossOf is the minutes' loss as a percent.
func lossOf(ws []RxWindow) string {
	sent, got := 0, 0
	for _, w := range ws {
		sent, got = sent+w.Sent, got+w.Got
	}
	if sent == 0 {
		return "all"
	}
	return fmt.Sprintf("%.1f%%", 100*float64(sent-got)/float64(sent))
}
