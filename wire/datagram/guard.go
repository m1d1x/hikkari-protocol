package datagram

import (
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/m1d1x/hikkari-protocol/observe"
	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/monotime"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
)

// Sender names a datagram connection's congestion controller.
const (
	// SenderGuard is the default (v1.05): no limit while the path loses
	// nothing, a rate limit only on real loss (guardSender).
	SenderGuard = "guard"
	// SenderBBR is BBR as before v1.05, the rollback.
	SenderBBR = "bbr"
)

// ParseSender checks a Sender option; empty is SenderGuard.
func ParseSender(s string) (string, error) {
	switch s {
	case "", SenderGuard:
		return SenderGuard, nil
	case SenderBBR:
		return SenderBBR, nil
	}
	return "", fmt.Errorf("datagram sender %q is not %s or %s", s, SenderGuard, SenderBBR)
}

// The guard's thresholds (v1.05), starting values the loopback test settled
// (TestLiveTrafficOnABloatedLine: a deaf bulk over the line's rate beside a
// call, a game and a screen share). guardJudge of the connection's sending is
// judged at a time.
const (
	// guardWindow bounds the bytes in flight, from memory, not from the path.
	guardWindow congestion.ByteCount = 64 << 20
	// guardOnLoss turns the limit on: this share of a stretch's bytes lost,
	// out of at least guardOnPackets packets.
	guardOnLoss    = 0.10
	guardOnPackets = 100
	// guardShare of the rate the path delivered in that stretch is the
	// limit: deep enough that the line's queue the excess left drains within
	// a few seconds (at 0.85 it took about six, and a call beside it lost a
	// tenth of its packets on the queue's every peak).
	guardShare = 0.70
	// guardClean is a stretch clean enough for the limit to grow by
	// guardGrow, after guardHold such stretches in a row (slowly: every probe
	// over the line's rate costs everyone on the line a burst of loss); the
	// limit goes once it is guardOff times what is sent.
	guardClean = 0.02
	guardGrow  = 1.03
	guardHold  = 3
	// guardProbeRTT: the limit grows only while the round trip is within
	// this of the least seen since the limit came on, the line's queue all
	// but empty. A probe over the line's rate into a full queue costs every
	// sender on the line a burst of loss (a call beside a deaf bulk got 81
	// to 95 % of its packets with growth on a full queue).
	guardProbeRTT = 50 * time.Millisecond
	guardOff      = 2.0
	// guardFloor is the least the limit falls to, bytes a second (1 Mbit/s):
	// a connection sending less floods no line a call can live on, and the
	// limit never cuts a call that loses by another sender's flood on the
	// same line.
	guardFloor = 125_000
	// guardBurst is how much of the limit may go at once.
	guardBurst = 10 * time.Millisecond
	// guardJudge is the stretch of sending judged at a time.
	guardJudge = 500 * time.Millisecond
)

// guardSender is the datagram connection's sender (v1.05, "the datagram
// channel is a pipe"). The connection carries only DATAGRAM frames, which
// QUIC never sends again, and the applications behind them (WebRTC, games,
// QUIC inside the tunnel) run congestion control of their own. Holding a
// frame back for a long round trip only delays it, and hides the path's loss
// from the application's own controller. So while nothing is lost the guard
// lets everything go at once, whatever the round trip: no window but memory's,
// no pacing. Real loss (more than guardOnLoss of a stretch's bytes) turns a
// rate limit on, at guardShare of what the path delivered then, for a
// sender that never backs off by itself (a flood): the frames over it age in
// the connection's scheduler and are counted stale there. After guardHold
// clean stretches in a row each clean one raises the limit by guardGrow; it
// goes once it is guardOff times what is sent.
type guardSender struct {
	maxDatagramSize congestion.ByteCount

	// the stretch being judged
	start                 monotime.Time
	sent, lost, delivered congestion.ByteCount
	packets               int

	limited bool
	rate    float64 // bytes a second while limited
	clean   int     // clean stretches in a row while limited
	// rtt is the connection's; leastRTT the least round trip seen since the
	// limit came on.
	rtt      congestion.RTTStatsProvider
	leastRTT time.Duration
	// pace is rate for the connection's scheduler, 0 while not limited
	// (math.Float64bits; read from the scheduler's goroutine).
	pace   atomic.Uint64
	budget float64 // pacing bytes while limited
	refill monotime.Time

	// limitedFor is the time spent limited, for observe (read from another
	// goroutine).
	mu         sync.Mutex
	limitedFor time.Duration
	since      monotime.Time
}

func newGuardSender(initialPacketSize congestion.ByteCount) *guardSender {
	return &guardSender{maxDatagramSize: initialPacketSize}
}

func (g *guardSender) SetRTTStatsProvider(p congestion.RTTStatsProvider) { g.rtt = p }

// lineEmpty reports whether the round trip is back near the least seen while
// limited: the queue the excess left on the line has drained.
func (g *guardSender) lineEmpty() bool {
	if g.rtt == nil {
		return true
	}
	latest := g.rtt.LatestRTT()
	if latest <= 0 {
		return true
	}
	if g.leastRTT == 0 || latest < g.leastRTT {
		g.leastRTT = latest
	}
	return latest <= g.leastRTT+guardProbeRTT
}

func (g *guardSender) TimeUntilSend(congestion.ByteCount) monotime.Time {
	if !g.limited || g.budget >= float64(g.maxDatagramSize) {
		return 0
	}
	wait := (float64(g.maxDatagramSize) - g.budget) / g.rate
	return g.refill.Add(time.Duration(wait * float64(time.Second)))
}

func (g *guardSender) HasPacingBudget(now monotime.Time) bool {
	if !g.limited {
		return true
	}
	g.fill(now)
	return g.budget >= float64(g.maxDatagramSize)
}

func (g *guardSender) fill(now monotime.Time) {
	if !now.After(g.refill) {
		return
	}
	burst := max(g.rate*guardBurst.Seconds(), 2*float64(g.maxDatagramSize))
	g.budget = min(burst, g.budget+g.rate*now.Sub(g.refill).Seconds())
	g.refill = now
}

func (g *guardSender) OnPacketSent(sentTime monotime.Time, _ congestion.ByteCount, _ congestion.PacketNumber, bytes congestion.ByteCount, _ bool) {
	g.judge(sentTime)
	g.sent += bytes
	g.packets++
	if g.limited {
		g.fill(sentTime)
		g.budget -= float64(bytes)
	}
}

func (g *guardSender) CanSend(bytesInFlight congestion.ByteCount) bool {
	return bytesInFlight < guardWindow
}

func (g *guardSender) MaybeExitSlowStart() {}

func (g *guardSender) OnPacketAcked(congestion.PacketNumber, congestion.ByteCount, congestion.ByteCount, monotime.Time) {
}

func (g *guardSender) OnCongestionEvent(congestion.PacketNumber, congestion.ByteCount, congestion.ByteCount) {
}

func (g *guardSender) OnCongestionEventEx(_ congestion.ByteCount, eventTime monotime.Time, acked []congestion.AckedPacketInfo, lost []congestion.LostPacketInfo) {
	g.judge(eventTime)
	for _, a := range acked {
		g.delivered += a.BytesAcked
	}
	for _, l := range lost {
		g.lost += l.BytesLost
	}
}

// judge closes the stretch when it is over: the limit goes on, follows the
// path, or goes.
func (g *guardSender) judge(now monotime.Time) {
	if g.start.IsZero() {
		g.start = now
		return
	}
	elapsed := now.Sub(g.start)
	if elapsed < guardJudge {
		return
	}
	secs := elapsed.Seconds()
	var loss float64
	if g.sent > 0 {
		loss = float64(g.lost) / float64(g.sent)
	}
	lossy := g.packets >= guardOnPackets && loss > guardOnLoss
	delivered := max(guardFloor, guardShare*float64(g.delivered)/secs)
	switch {
	case !g.limited && lossy:
		g.limited, g.rate, g.budget, g.refill = true, delivered, 0, now
		g.clean, g.leastRTT = 0, 0
		g.mu.Lock()
		g.since = now
		g.mu.Unlock()
	case g.limited && lossy:
		g.rate = min(g.rate, delivered)
		g.clean = 0
	case g.limited && loss >= guardClean:
		g.clean = 0
	case g.limited:
		g.clean++
		if empty := g.lineEmpty(); g.clean > guardHold && empty {
			g.rate *= guardGrow
		}
		if g.rate > guardOff*float64(g.sent)/secs {
			g.limited = false
			g.mu.Lock()
			g.limitedFor += now.Sub(g.since)
			g.since = 0
			g.mu.Unlock()
		}
	}
	if g.limited && g.rtt != nil {
		g.lineEmpty() // keeps leastRTT up to date in every stretch
	}
	if g.limited {
		g.pace.Store(math.Float64bits(g.rate))
	} else {
		g.pace.Store(0)
	}
	g.start, g.sent, g.lost, g.delivered, g.packets = now, 0, 0, 0, 0
}

// Pace is the limit in bytes a second, 0 while there is none: the
// connection's scheduler holds its frames to it, so they wait (and age) in
// the scheduler and not in QUIC's own queue.
func (g *guardSender) Pace() float64 { return math.Float64frombits(g.pace.Load()) }

// Limited is the time the guard held the connection to a rate.
func (g *guardSender) Limited() time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	d := g.limitedFor
	if !g.since.IsZero() {
		d += max(0, monotime.Since(g.since))
	}
	return d
}

func (g *guardSender) OnRetransmissionTimeout(bool) {}

func (g *guardSender) SetMaxDatagramSize(size congestion.ByteCount) { g.maxDatagramSize = size }

func (g *guardSender) InSlowStart() bool { return false }

func (g *guardSender) InRecovery() bool { return false }

func (g *guardSender) GetCongestionWindow() congestion.ByteCount { return guardWindow }

func (g *guardSender) OnPacketNeutered(congestion.PacketNumber) {}

func (g *guardSender) OnPacketsLost(congestion.PacketNumber) {}

func (g *guardSender) OnAppLimited(congestion.ByteCount) {}

// setSender gives conn its sender: the guard, which observe reads as the
// connection's guard_s and q keeps pace with, or BBR with profile.
func setSender(conn *quic.Conn, q *sendQueue, sender string, profile congestion_meta2.Profile) {
	if sender == SenderBBR {
		conn.SetCongestionControl(congestion_meta2.NewBbrSenderWithProfile(conn.InitialPacketSize(), profile))
		return
	}
	g := newGuardSender(conn.InitialPacketSize())
	conn.SetCongestionControl(g)
	observe.Guard(conn, g.Limited)
	q.paceBy(g.Pace)
}
