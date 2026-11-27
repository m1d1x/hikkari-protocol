package client

// How good an entry's path is (v1.08, spec/v1.md "How an entry is judged"):
// the pings of the last minute on one carrier, scored by their median round
// trip and the share of them that came late.

import (
	"sort"
	"time"
)

const (
	// judgeWindow is how far back the pings an entry is judged by go. Late
	// pings are rare on a sound path, a few a minute: two minutes of them
	// tell two sound entries apart from a slow one, one minute does not.
	judgeWindow = 2 * time.Minute
	// judgeInFlight is the newest part of the window left out: its pings
	// may still come back. A ping not back after it is late.
	judgeInFlight = time.Second
	// lateOver is how much later than the window's median a ping may come
	// back before it counts late, by fate. A datagram 50 ms late is a pause
	// a call hears (26.11: 31 pauses over 60 ms a minute on aezamsk1 at a
	// tail of 75 ms over the median). The stream rides the trunk's TCP pool,
	// whose answers spread wide on a sound path too (p95 25-110 ms over the
	// median on 26.11 on both entries): only a stall a page or a game feels
	// counts there.
	lateOverDatagram = 50 * time.Millisecond
	lateOverStream   = 150 * time.Millisecond
	// latePenalty is what the whole window late would add to the median:
	// 1% of pings late weighs as 20 ms, one ping in a full window as 4 ms.
	latePenalty = 2 * time.Second
	// judgeMinPings is how many pings a fate is scored from: a minute of
	// them.
	judgeMinPings = 240
)

// pingLog holds one probe carrier's pings of the last judgeWindow in the
// order they were sent.
type pingLog struct {
	pings  []ping
	sorted []float64 // scratch for the median
}

type ping struct {
	seq  uint64
	sent time.Time
	rtt  time.Duration // 0 until it came back
	back bool
	// settled: the ping left the in-flight part and was counted.
	settled bool
}

// sent records a ping going out and forgets those older than the window.
func (l *pingLog) sent(seq uint64, now time.Time) {
	cut := 0
	for cut < len(l.pings) && now.Sub(l.pings[cut].sent) > judgeWindow {
		cut++
	}
	l.pings = append(l.pings[:0], l.pings[cut:]...)
	l.pings = append(l.pings, ping{seq: seq, sent: now})
}

// answered records the answer to ping seq; it reports the round trip, and
// false for a ping the log no longer holds or already heard.
func (l *pingLog) answered(seq uint64, now time.Time) (time.Duration, bool) {
	for i := len(l.pings) - 1; i >= 0; i-- {
		p := &l.pings[i]
		if p.seq != seq {
			continue
		}
		if p.back {
			return 0, false
		}
		p.back, p.rtt = true, now.Sub(p.sent)
		return p.rtt, true
	}
	return 0, false
}

// fateScore is a fate judged at one moment.
type fateScore struct {
	score time.Duration
	ok    bool // judged by judgeMinPings or more
	// Pings that left the in-flight part since the last judgement, and how
	// many of them were late: the period's counts.
	settled, late int64
}

// judge scores the fate at now (spec/v1.md "How an entry is judged"); a
// ping is late lateOver after the median.
func (l *pingLog) judge(now time.Time, lateOver time.Duration) fateScore {
	l.sorted = l.sorted[:0]
	judged := 0
	for _, p := range l.pings {
		if now.Sub(p.sent) < judgeInFlight {
			break
		}
		judged++
		if p.back {
			l.sorted = append(l.sorted, float64(p.rtt))
		}
	}
	// With nothing back in the window every ping is late, and the score is
	// the whole penalty: a fate that stopped answering is the worst there is.
	var median time.Duration
	if len(l.sorted) > 0 {
		sort.Float64s(l.sorted)
		median = time.Duration(l.sorted[len(l.sorted)/2])
	}
	var f fateScore
	late := 0
	for i := range l.pings {
		p := &l.pings[i]
		if now.Sub(p.sent) < judgeInFlight {
			break
		}
		isLate := !p.back || p.rtt > judgeInFlight || p.rtt > median+lateOver
		if isLate {
			late++
		}
		if !p.settled {
			p.settled = true
			f.settled++
			if isLate {
				f.late++
			}
		}
	}
	if judged >= judgeMinPings {
		share := float64(late) / float64(judged)
		f.score, f.ok = median+time.Duration(share*float64(latePenalty)), true
	}
	return f
}

// gain is how much lower entry b's scores are than entry a's, summed over
// the fates both have scored; ok is false unless both scored the stream.
// What both entries share (the pool's own spread, the user's line) cancels,
// and what one entry adds on either fate counts.
func gain(a, b [2]fateScore) (time.Duration, bool) {
	if !a[fateStream].ok || !b[fateStream].ok {
		return 0, false
	}
	var g time.Duration
	for f := range a {
		if a[f].ok && b[f].ok {
			g += a[f].score - b[f].score
		}
	}
	return g, true
}
