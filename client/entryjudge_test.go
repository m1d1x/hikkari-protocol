package client

// The best entry (v1.08, spec/v1.md "How an entry is judged", "Moving to a
// better entry") on pings of a made-up clock: no carrier, only the judgement.

import (
	"context"
	"math/rand/v2"
	"net"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/observe"
	M "github.com/sagernet/sing/common/metadata"
)

// fakeEntries is a client's health with n entries whose pings a test feeds.
func fakeEntries(n int, start time.Time) *health {
	c := &Client{}
	for range n {
		c.paths = append(c.paths, &path{Path: Path{Datagram: nowhere{}}})
	}
	h := &health{c: c, start: start, tick: start, lastScore: start, anyever: true,
		heard: make([]time.Time, n), logs: make([][2]pingLog, n), dgramOK: make([]bool, n),
		fates: make([][2]fateScore, n), silent: make([]bool, n), since: make([]time.Time, n)}
	h.counts = make([]observe.Entry, n)
	return h
}

// nowhere is a datagram channel that is up and never dialed: the test feeds
// its pings itself.
type nowhere struct{}

func (nowhere) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (nowhere) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

// pathShape draws a ping's round trip on one fate of one entry: the median,
// a spread around it, and a share of pings that come late by late.
type pathShape struct {
	median, spread time.Duration
	lateShare      float64
	lateMin        time.Duration
	lateMax        time.Duration
}

func (s pathShape) draw(r *rand.Rand) time.Duration {
	if r.Float64() < s.lateShare {
		return s.median + s.lateMin + time.Duration(r.Int64N(int64(s.lateMax-s.lateMin)+1))
	}
	return s.median + time.Duration(r.NormFloat64()*float64(s.spread))
}

// feed runs the clock from start for d, pinging every entry's fates every
// PingEvery with shapes[entry][fate] and scoring every scoreEvery as the
// watcher does; it returns the moves by quality with their times.
func feed(h *health, r *rand.Rand, start time.Time, d time.Duration, shapes [][2]pathShape) []time.Duration {
	var moves []time.Duration
	var seq uint64
	for t := time.Duration(0); t < d; t += PingEvery {
		now := start.Add(t)
		seq++
		for i, sh := range shapes {
			for f := range sh {
				if sh[f].median == 0 {
					continue
				}
				h.logs[i][f].sent(seq, now)
				rtt := max(sh[f].draw(r), time.Millisecond)
				// The answer is in the log by its arrival; scoring before it
				// sees the ping in flight or late, as on a real carrier.
				h.answer(i, fate(f), seq, now.Add(rtt))
			}
		}
		if now.Sub(h.lastScore) >= scoreEvery {
			h.lastScore = now
			if m := h.scoreLocked(now); m != nil {
				moves = append(moves, t)
			}
		}
	}
	return moves
}

// stormShape is 26.11 as the pings saw it (research 2026-11-26): through
// aezamsk1 the stream answered with a median as good as cbxmsk1's and a
// heavier tail, and the trunk's UDP gave 31 pauses over 60 ms a minute.
var (
	calmStream  = pathShape{median: 75 * time.Millisecond, spread: 15 * time.Millisecond, lateShare: 0.01, lateMin: 160 * time.Millisecond, lateMax: 400 * time.Millisecond}
	stormStream = pathShape{median: 80 * time.Millisecond, spread: 18 * time.Millisecond, lateShare: 0.03, lateMin: 160 * time.Millisecond, lateMax: 600 * time.Millisecond}
	calmDgram   = pathShape{median: 58 * time.Millisecond, spread: 5 * time.Millisecond, lateShare: 0.003, lateMin: 60 * time.Millisecond, lateMax: 150 * time.Millisecond}
	stormDgram  = pathShape{median: 60 * time.Millisecond, spread: 8 * time.Millisecond, lateShare: 0.02, lateMin: 60 * time.Millisecond, lateMax: 600 * time.Millisecond}
)

// TestAStormLikeThe26thMovesTheClientToTheCleanEntry: entry 0 as aezamsk1
// on 26.11, entry 1 as cbxmsk1; the client moves once, after the window
// filled and the lead held.
func TestAStormLikeThe26thMovesTheClientToTheCleanEntry(t *testing.T) {
	start := time.Unix(1795676400, 0)
	h := fakeEntries(2, start)
	h.dgramOK[0], h.dgramOK[1] = true, true
	moves := feed(h, rand.New(rand.NewPCG(26, 11)), start, 10*time.Minute,
		[][2]pathShape{{stormStream, stormDgram}, {calmStream, calmDgram}})
	if len(moves) != 1 || h.chosen != 1 {
		t.Fatalf("moves at %v, chosen %d; want one move to entry 1", moves, h.chosen)
	}
	if moves[0] > 150*time.Second {
		t.Errorf("moved %v after the start, want within 2 min 30 s (a minute of pings, the storm filling the window, 30 s held)", moves[0])
	}
	t.Logf("moved to entry 1 %v in", moves[0])
}

// TestEntriesAsGoodAsEachOtherDoNotTradePlaces: two calm entries for an
// hour, as aezamsk1 and cbxmsk1 after 13:00 UTC 26.11: no move.
func TestEntriesAsGoodAsEachOtherDoNotTradePlaces(t *testing.T) {
	for seed := uint64(1); seed <= 10; seed++ {
		start := time.Unix(1795676400, 0)
		h := fakeEntries(2, start)
		h.dgramOK[0], h.dgramOK[1] = true, true
		other := calmStream
		other.median += 8 * time.Millisecond // cbxmsk1 is 8 ms further
		moves := feed(h, rand.New(rand.NewPCG(seed, 27)), start, time.Hour,
			[][2]pathShape{{calmStream, calmDgram}, {other, calmDgram}})
		if len(moves) != 0 {
			t.Errorf("seed %d: moves at %v between entries as good as each other", seed, moves)
		}
	}
}

// TestTheClientComesBackWhenTheStormEnds: storm on entry 0 for 10 minutes,
// then entry 1 is the worse: the client goes there and back, once each way.
func TestTheClientComesBackWhenTheStormEnds(t *testing.T) {
	start := time.Unix(1795676400, 0)
	h := fakeEntries(2, start)
	h.dgramOK[0], h.dgramOK[1] = true, true
	r := rand.New(rand.NewPCG(13, 0))
	moves := feed(h, r, start, 10*time.Minute, [][2]pathShape{{stormStream, stormDgram}, {calmStream, calmDgram}})
	later := start.Add(10 * time.Minute)
	moves = append(moves, feed(h, r, later, 10*time.Minute, [][2]pathShape{{calmStream, calmDgram}, {stormStream, stormDgram}})...)
	if len(moves) != 2 || h.chosen != 0 {
		t.Fatalf("moves at %v, chosen %d; want to entry 1 and back to entry 0", moves, h.chosen)
	}
}

// TestADeadDatagramFateIsTheWorstThereIs: entry 0's UDP stops answering
// while its stream is as good as entry 1's; the client leaves it.
func TestADeadDatagramFateIsTheWorstThereIs(t *testing.T) {
	start := time.Unix(1795676400, 0)
	h := fakeEntries(2, start)
	h.dgramOK[0], h.dgramOK[1] = true, true
	dead := pathShape{median: 60 * time.Millisecond, lateShare: 1, lateMin: 5 * time.Second, lateMax: 5 * time.Second}
	moves := feed(h, rand.New(rand.NewPCG(1, 1)), start, 3*time.Minute,
		[][2]pathShape{{calmStream, dead}, {calmStream, calmDgram}})
	if len(moves) != 1 || h.chosen != 1 {
		t.Fatalf("moves at %v, chosen %d; want one move off the dead UDP", moves, h.chosen)
	}
}

// TestASilentEntryIsLeftAtOnceForTheBestAlive: three entries, the chosen one
// goes silent; the client takes the better of the other two at once, with
// no hold, and counts it a move by silence.
func TestASilentEntryIsLeftAtOnceForTheBestAlive(t *testing.T) {
	start := time.Unix(1795676400, 0)
	h := fakeEntries(3, start)
	feed(h, rand.New(rand.NewPCG(3, 3)), start, 2*time.Minute,
		[][2]pathShape{{calmStream, {}}, {stormStream, {}}, {calmStream, {}}})
	now := start.Add(2 * time.Minute)
	if a := h.activeLocked(now); a != 0 {
		t.Fatalf("active %d before the silence, want 0", a)
	}
	h.heard[0] = now.Add(-2 * EntrySilence)
	if a := h.activeLocked(now); a != 2 {
		t.Fatalf("active %d after entry 0 went silent, want 2 (better than 1)", a)
	}
	if h.counts[2].MovesSilence != 1 {
		t.Errorf("moves by silence to entry 2: %d, want 1", h.counts[2].MovesSilence)
	}
}
