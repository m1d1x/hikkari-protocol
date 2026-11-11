package datagram

import (
	"testing"
	"time"

	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/monotime"
)

// guardRun drives a guard for secs seconds: pps packets of 1200 B a second,
// lossShare of them lost, the rest acked a round trip later.
func guardRun(g *guardSender, start monotime.Time, secs, pps int, lossShare float64, rtt time.Duration) monotime.Time {
	now := start
	step := time.Second / time.Duration(pps)
	var pn congestion.PacketNumber
	lostEvery := 0
	if lossShare > 0 {
		lostEvery = int(1 / lossShare)
	}
	for i := 0; i < secs*pps; i++ {
		now = now.Add(step)
		pn++
		g.OnPacketSent(now, 0, pn, 1200, true)
		if lostEvery > 0 && i%lostEvery == 0 {
			g.OnCongestionEventEx(0, now.Add(rtt), nil, []congestion.LostPacketInfo{{PacketNumber: pn, BytesLost: 1200}})
		} else {
			g.OnCongestionEventEx(0, now.Add(rtt), []congestion.AckedPacketInfo{{PacketNumber: pn, BytesAcked: 1200}}, nil)
		}
	}
	return now
}

// Without loss the guard holds nothing back, whatever the round trip: a
// download's 2 s of queue on the user's line is not a reason to stop.
func TestTheGuardNeverLimitsWithoutLoss(t *testing.T) {
	g := newGuardSender(1252)
	now := guardRun(g, monotime.Now(), 5, 2000, 0, 2*time.Second)
	if !g.CanSend(32<<20) || !g.HasPacingBudget(now) || g.TimeUntilSend(0) != 0 || g.limited {
		t.Fatalf("the guard held a clean connection back: limited %v", g.limited)
	}
	if g.Limited() != 0 {
		t.Fatalf("limited for %v", g.Limited())
	}
}

// Losing more than a tenth turns a limit on at guardShare of what was
// delivered.
func TestTheGuardLimitsOnLoss(t *testing.T) {
	g := newGuardSender(1200)
	now := guardRun(g, monotime.Now(), 3, 2000, 0.25, 20*time.Millisecond)
	if !g.limited {
		t.Fatal("a quarter lost and no limit")
	}
	// 2000 packets a second, a quarter lost: 1500 delivered, guardShare of it.
	want := guardShare * 1500 * 1200
	if g.rate < want*0.8 || g.rate > want*1.2 {
		t.Fatalf("limit %.0f B/s, want about %.0f", g.rate, want)
	}
	// The limit paces: a burst beyond it waits.
	for g.HasPacingBudget(now) {
		g.OnPacketSent(now, 0, 0, 1200, true)
	}
	if g.TimeUntilSend(0) == 0 {
		t.Fatal("no wait over the limit")
	}
	if g.since.IsZero() {
		t.Fatal("the limit's start not kept for guard_s")
	}
}

// Small loss never turns the limit on: the applications back off by
// themselves before a tenth.
func TestTheGuardIgnoresSmallLoss(t *testing.T) {
	g := newGuardSender(1200)
	guardRun(g, monotime.Now(), 3, 2000, 0.05, 20*time.Millisecond)
	if g.limited {
		t.Fatal("5% loss turned the limit on")
	}
}

// Clean seconds raise the limit until it is twice what is sent; then it goes.
func TestTheGuardLiftsTheLimit(t *testing.T) {
	g := newGuardSender(1200)
	now := guardRun(g, monotime.Now(), 2, 2000, 0.25, 20*time.Millisecond)
	if !g.limited {
		t.Fatal("no limit to lift")
	}
	// The sender backed off: 300 packets a second, clean.
	guardRun(g, now, 30, 300, 0, 20*time.Millisecond)
	if g.limited {
		t.Fatalf("the limit stayed: %.0f B/s for 360000 B/s sent", g.rate)
	}
	if g.limitedFor <= 0 || !g.since.IsZero() {
		t.Fatalf("limited time %v not counted on lifting", g.limitedFor)
	}
}
