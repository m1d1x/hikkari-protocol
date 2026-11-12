package trunk

import (
	"encoding/binary"
	"math/rand"
	"reflect"
	"sort"
	"testing"
	"time"
)

// callEvent is one step of a recorded call: a tick (a send, then the windows
// due) or an answer coming back.
type callEvent struct {
	at   time.Time
	tick bool
	seq  uint64
	s    *Session
	ord  int // ties keep the order they were made in
}

// recordCall makes a call of n ticks with what a real trunk does to it:
// losses, answers late past the grace, copies delivered twice, answers out of
// order, the box sleeping through ticks and the session changing.
func recordCall(r *rand.Rand, cfg CallConfig, start time.Time, n int) []callEvent {
	sessions := []*Session{{}, {}, {}}
	cur := sessions[0]
	var ev []callEvent
	at := start
	var seq uint64
	add := func(e callEvent) { e.ord = len(ev); ev = append(ev, e) }
	for i := 0; i < n; i++ {
		// A tick late now and then (the box's own pause), rarely seconds.
		step := cfg.Every
		switch x := r.Intn(1000); {
		case x < 3:
			step += time.Duration(r.Intn(3000)) * time.Millisecond
		case x < 30:
			step += time.Duration(r.Intn(200)) * time.Millisecond
		}
		at = at.Add(step + time.Duration(r.Intn(1000))*time.Microsecond)
		if r.Intn(500) == 0 {
			cur = sessions[r.Intn(len(sessions))]
		}
		seq++
		add(callEvent{at: at, tick: true, seq: seq, s: cur})
		if r.Intn(100) < 3 {
			continue // lost
		}
		rtt := 40*time.Millisecond + time.Duration(r.Intn(30000))*time.Microsecond
		switch x := r.Intn(1000); {
		case x < 5:
			rtt += time.Duration(r.Intn(4000)) * time.Millisecond // late, often past the grace
		case x < 50:
			rtt += time.Duration(r.Intn(300)) * time.Millisecond // out of order
		}
		add(callEvent{at: at.Add(rtt), seq: seq})
		if r.Intn(100) < 2 {
			add(callEvent{at: at.Add(rtt + time.Duration(r.Intn(50))*time.Millisecond), seq: seq}) // a copy twice
		}
		if r.Intn(1000) == 0 {
			add(callEvent{at: at.Add(rtt), seq: seq + 1000000}) // a seq never sent
		}
	}
	sort.SliceStable(ev, func(i, j int) bool {
		if !ev[i].at.Equal(ev[j].at) {
			return ev[i].at.Before(ev[j].at)
		}
		return ev[i].ord < ev[j].ord
	})
	return ev
}

// TestCallRingAgreesWithTheMap: on recorded calls the ring reports, window by
// window, exactly what the map it replaced reported.
func TestCallRingAgreesWithTheMap(t *testing.T) {
	cfgs := []CallConfig{
		CallConfig{Copies: 1}.withDefaults(),
		CallConfig{Copies: 2, Every: 10 * time.Millisecond, Window: time.Second, Grace: 200 * time.Millisecond}.withDefaults(),
		CallConfig{Copies: 1, Window: 5 * time.Second, Grace: 3 * time.Second}.withDefaults(),
	}
	for ci, cfg := range cfgs {
		for seed := int64(1); seed <= 8; seed++ {
			r := rand.New(rand.NewSource(seed))
			start := time.Date(2026, 11, 12, 1, 0, 0, 0, time.UTC).Add(time.Duration(r.Intn(60000)) * time.Millisecond)
			ev := recordCall(r, cfg, start, 20000)
			ref, ring := newRefCall(cfg, start), newCall(cfg, start)
			p := make([]byte, 8)
			var got, want []CallWindow
			for _, e := range ev {
				if e.tick {
					ref.sent(e.seq, e.at, e.s)
					ring.sent(e.seq, e.at, e.s)
					want = append(want, ref.due(e.at)...)
					got = append(got, ring.due(e.at)...)
					continue
				}
				binary.BigEndian.PutUint64(p, e.seq)
				ref.answerAt(e.at, p)
				ring.answerAt(e.at, p)
			}
			if len(want) < 3 {
				t.Fatalf("cfg %d seed %d: %d windows, the recording is too short", ci, seed, len(want))
			}
			if !reflect.DeepEqual(got, want) {
				for i := range want {
					if i >= len(got) || !reflect.DeepEqual(got[i], want[i]) {
						var g CallWindow
						if i < len(got) {
							g = got[i]
						}
						t.Fatalf("cfg %d seed %d window %d of %d:\nring %+v\nmap  %+v", ci, seed, i, len(want), g, want[i])
					}
				}
				t.Fatalf("cfg %d seed %d: ring %d windows, map %d", ci, seed, len(got), len(want))
			}
			var lost, late int
			for _, w := range want {
				lost += w.Lost()
				late += w.Gaps150
			}
			if lost == 0 || late == 0 {
				t.Fatalf("cfg %d seed %d: lost %d, pauses %d: the recording does not test them", ci, seed, lost, late)
			}
			if ring.n > int(cfg.Window/cfg.Every)*3 {
				t.Fatalf("cfg %d seed %d: %d datagrams kept, the ring does not let go", ci, seed, ring.n)
			}
		}
	}
}
