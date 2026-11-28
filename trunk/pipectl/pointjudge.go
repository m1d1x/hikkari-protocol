package pipectl

// pointjudge.go: which border points carry the trunk (spec/trunk.md, "Border
// points by quality"; hikkari-client plans/2026-11-28-border-points-by-quality.md).
// The hub offers the points; the judge keeps on the path every one but a
// point clearly worse than the best by the whole window's quality, as the
// client judges its entries (client paths.go, v1.08): the median round trip
// of the point's members plus a fine for the share of late seconds, not the
// worst moment. A second is late when no member at the point is up or none
// proved a round trip within LatePoint. A point out of the path comes back
// to be judged again after a hold, and at once when the path has fewer than
// two points alive: the judge never leaves the trunk on one point, so a
// call's copies keep two points (G6) and a freeze of one is not heard.
//
// On 27.11 edislv1 (Riga) went into the people's path beside unl1 and hkfi1:
// its members' latest proof was older than 300 ms in 25–30% of the minute
// samples (up to 967 ms), unl1's and hkfi1's in none of 138 (at most 144 ms),
// and a third of every client's stream rode it in turns (member i at point i
// mod n): vitya-001's tunnel stalls over 300 ms went from 0–2 to 18 a minute.

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
)

const (
	// LatePoint is how old a point's latest proof may be for its second to
	// count in time: an idle pool proves itself every 250 ms (keep_proof),
	// a datagram wire every 100 ms, and the pipe says the points once a
	// second. 27.11 the good points stayed under 144 ms, edislv1 went over
	// 300 ms in a quarter of the samples.
	LatePoint = 300 * time.Millisecond
	// pointWindow is how many seconds a point's score reads (the client's
	// entry window of Q2, 2 min); pointJudged is how many it needs to be
	// judged at all.
	pointWindow = 120
	pointJudged = 60
	// pointLateFine is the fine for late seconds: 400 ms times their share,
	// as the entry score of Q2 (+40 ms at 10% late).
	pointLateFine = 400 * time.Millisecond
	// pointMargin is how much worse than the best a point must score to
	// leave the path, and pointMarginShare the same as a share of the best:
	// a stream goes in turns over every point's members, so it waits on
	// the slowest; 20 ms is the cost a stream feels, under hkfi1's +15 ms
	// from aezamsk1 (27.11) and over edislv1's +22 ms and +31 ms.
	pointMargin      = 20 * time.Millisecond
	pointMarginShare = 5 // a fifth of the best score
	// pointWorseFor is how long a point stays that much worse before it
	// leaves: a minute's storm of one point is not a move.
	pointWorseFor = 30 * time.Second
	// pointSettle is how long the path holds after a change: the members
	// that moved dial their new points; pointWarm is how long after a change
	// no second is counted, while they do.
	pointSettle = 60 * time.Second
	pointWarm   = 20 * time.Second
	// pointHold is how long a point stays out before it comes back to be
	// judged, doubled each time it leaves again within pointRelapse of
	// coming back, up to pointHoldMax.
	pointHold    = 10 * time.Minute
	pointHoldMax = 60 * time.Minute
	pointRelapse = time.Hour
	// pointPathMin is the fewest points the judge leaves on the path.
	pointPathMin = 2
)

// pointSecond is one second of a point: late or not, and its round trip
// (negative: none of its members up has one).
type pointSecond struct {
	late bool
	rtt  time.Duration
}

// pointOut is a point out of the path: when it comes back, and the hold it
// left with.
type pointOut struct {
	until time.Time
	hold  time.Duration
}

// PointJudge decides which offered points carry the trunk. Its zero value
// is ready.
type PointJudge struct {
	seconds    map[netip.Addr][]pointSecond
	worseSince map[netip.Addr]time.Time
	out        map[netip.Addr]pointOut
	// backAt and holds are when each point last came back and the hold it
	// had been out for: leaving again within pointRelapse doubles it.
	backAt     map[netip.Addr]time.Time
	holds      map[netip.Addr]time.Duration
	changedAt  time.Time
	lastSample time.Time
}

// PointVerdict is the judge's answer: the points on the path in the order
// offered, whether it changed, which point left or came back, and why.
type PointVerdict struct {
	Path       []netip.Addr
	Change     bool
	Left, Back []netip.Addr
	Why        string
}

func (j *PointJudge) init() {
	if j.seconds == nil {
		j.seconds = map[netip.Addr][]pointSecond{}
		j.worseSince = map[netip.Addr]time.Time{}
		j.out = map[netip.Addr]pointOut{}
		j.backAt = map[netip.Addr]time.Time{}
		j.holds = map[netip.Addr]time.Duration{}
	}
}

// Path is offered without the points out of it, in the order offered.
func (j *PointJudge) Path(offered []netip.Addr) []netip.Addr {
	path := make([]netip.Addr, 0, len(offered))
	for _, ip := range offered {
		if _, out := j.out[ip]; !out {
			path = append(path, ip)
		}
	}
	return path
}

// Step judges the pipe's latest point ticks (the points on the path, as
// the pipe said them age ago) at now. A second is late by the proof the
// pipe measured at its tick, not aged: the word's own age (up to the
// second between the pipe's tick and the judge's) would eat LatePoint and
// make lateness the phase of two timers (27.11 night, aezamsk1: unl1 late
// 2 of 80 seconds, then 16 of 79, with every minute's proof under 120 ms).
// A point's death (DeadAfter) reads the proof aged by age. offered is the
// hub's points; paused is how long ago the pipe or the brain came back from
// a pause (negative: none).
func (j *PointJudge) Step(now time.Time, offered []netip.Addr, ticks []PointTick, age, paused time.Duration) PointVerdict {
	j.init()
	j.forgetUnoffered(offered)
	path := j.Path(offered)
	v := PointVerdict{Path: path}
	if paused >= 0 && paused < DeadAfter {
		v.Why = "a pause of the entry's own: every proof is old"
		return v
	}
	if back := j.backForLife(path, ticks, age); len(back) > 0 {
		return j.change(now, offered, nil, back, fmt.Sprintf("fewer than %d points alive", pointPathMin))
	}
	if back := j.backFromHold(now); len(back) > 0 {
		return j.change(now, offered, nil, back, "its hold is over: judged again")
	}
	j.sample(now, path, ticks)
	if len(path) <= pointPathMin {
		v.Why = "no point to spare"
		return v
	}
	if now.Sub(j.changedAt) < pointSettle {
		v.Why = "settling after a change"
		return v
	}
	worst, why, ok := j.worstOf(now, path)
	if !ok {
		v.Why = why
		return v
	}
	return j.change(now, offered, []netip.Addr{worst}, nil, why)
}

// forgetUnoffered drops what the judge knows of points the hub no longer
// offers.
func (j *PointJudge) forgetUnoffered(offered []netip.Addr) {
	for ip := range j.out {
		if !slices.Contains(offered, ip) {
			delete(j.out, ip)
		}
	}
	for ip := range j.seconds {
		if !slices.Contains(offered, ip) {
			delete(j.seconds, ip)
			delete(j.worseSince, ip)
		}
	}
}

// backForLife is every point out when fewer than pointPathMin points on the
// path are alive: a point is alive while a member is up or one proved a
// round trip within DeadAfter, its proof aged by the word's age.
func (j *PointJudge) backForLife(path []netip.Addr, ticks []PointTick, age time.Duration) []netip.Addr {
	if len(j.out) == 0 {
		return nil
	}
	alive := 0
	for _, ip := range path {
		if t, ok := tickOf(ticks, ip); !ok || t.Up > 0 || t.ProofAgo >= 0 && t.ProofAgo+age < DeadAfter {
			alive++
		}
	}
	if alive >= pointPathMin {
		return nil
	}
	return j.outPoints()
}

// backFromHold is the point out whose hold ended first, if any did.
func (j *PointJudge) backFromHold(now time.Time) []netip.Addr {
	var back netip.Addr
	for ip, o := range j.out {
		if !now.Before(o.until) && (!back.IsValid() || o.until.Before(j.out[back].until)) {
			back = ip
		}
	}
	if !back.IsValid() {
		return nil
	}
	return []netip.Addr{back}
}

func (j *PointJudge) outPoints() []netip.Addr {
	ips := make([]netip.Addr, 0, len(j.out))
	for ip := range j.out {
		ips = append(ips, ip)
	}
	slices.SortFunc(ips, netip.Addr.Compare)
	return ips
}

// sample counts a second of every point on the path, once a second, past
// the warm-up after a change. A point the pipe did not report (the tick is
// of the path before the change) counts nothing.
func (j *PointJudge) sample(now time.Time, path []netip.Addr, ticks []PointTick) {
	if now.Sub(j.lastSample) < time.Second || now.Sub(j.changedAt) < pointWarm {
		return
	}
	j.lastSample = now
	for _, ip := range path {
		t, ok := tickOf(ticks, ip)
		if !ok {
			continue
		}
		s := pointSecond{late: t.Up == 0 || t.ProofAgo < 0 || t.ProofAgo > LatePoint, rtt: t.RTT}
		ss := append(j.seconds[ip], s)
		if len(ss) > pointWindow {
			ss = ss[len(ss)-pointWindow:]
		}
		j.seconds[ip] = ss
	}
}

// score is a point's quality over its window: the median round trip plus
// pointLateFine times the share of late seconds; ok is false while it has
// fewer than pointJudged seconds.
func (j *PointJudge) score(ip netip.Addr) (time.Duration, bool) {
	ss := j.seconds[ip]
	if len(ss) < pointJudged {
		return 0, false
	}
	late := 0
	rtts := make([]time.Duration, 0, len(ss))
	for _, s := range ss {
		if s.late {
			late++
		}
		if s.rtt >= 0 {
			rtts = append(rtts, s.rtt)
		}
	}
	var med time.Duration
	if len(rtts) > 0 {
		slices.Sort(rtts)
		med = rtts[len(rtts)/2]
	}
	return med + pointLateFine*time.Duration(late)/time.Duration(len(ss)), true
}

// worstOf is the point to take off the path: the worst one, worse than the
// best by the margin for pointWorseFor; every point on the path judged.
func (j *PointJudge) worstOf(now time.Time, path []netip.Addr) (netip.Addr, string, bool) {
	var best, worst netip.Addr
	var bestS, worstS time.Duration
	for _, ip := range path {
		s, ok := j.score(ip)
		if !ok {
			return netip.Addr{}, "not every point judged yet", false
		}
		if !best.IsValid() || s < bestS {
			best, bestS = ip, s
		}
		if !worst.IsValid() || s > worstS {
			worst, worstS = ip, s
		}
	}
	margin := max(pointMargin, bestS/pointMarginShare)
	if worstS-bestS < margin {
		clear(j.worseSince)
		return netip.Addr{}, "no point worse than the best by the margin", false
	}
	for ip := range j.worseSince {
		if ip != worst {
			delete(j.worseSince, ip)
		}
	}
	since, ok := j.worseSince[worst]
	if !ok {
		j.worseSince[worst] = now
		since = now
	}
	why := fmt.Sprintf("%s scores %s against %s's %s (%s)", worst, worstS.Round(time.Millisecond), best, bestS.Round(time.Millisecond), j.scores(path))
	if now.Sub(since) < pointWorseFor {
		return netip.Addr{}, why + ", not for long enough", false
	}
	return worst, why + " for " + now.Sub(since).Round(time.Second).String(), true
}

// scores says every point's score on path and what it is made of: the
// median round trip and the share of late seconds, for the line the hub
// keeps beside each change.
func (j *PointJudge) scores(path []netip.Addr) string {
	parts := make([]string, 0, len(path))
	for _, ip := range path {
		ss := j.seconds[ip]
		s, ok := j.score(ip)
		if !ok || len(ss) == 0 {
			parts = append(parts, ip.String()+" unjudged")
			continue
		}
		late := 0
		for _, x := range ss {
			if x.late {
				late++
			}
		}
		med := s - pointLateFine*time.Duration(late)/time.Duration(len(ss))
		parts = append(parts, fmt.Sprintf("%s %s = rtt %s + late %d/%d", ip, s.Round(time.Millisecond), med.Round(time.Millisecond), late, len(ss)))
	}
	return strings.Join(parts, "; ")
}

// change takes left off the path and brings back back: the members move,
// so every window starts again after the warm-up.
func (j *PointJudge) change(now time.Time, offered, left, back []netip.Addr, why string) PointVerdict {
	for _, ip := range left {
		hold := pointHold
		if at, ok := j.backAt[ip]; ok && now.Sub(at) < pointRelapse {
			hold = min(2*j.holds[ip], pointHoldMax)
		}
		j.out[ip] = pointOut{until: now.Add(hold), hold: hold}
	}
	for _, ip := range back {
		j.backAt[ip] = now
		j.holds[ip] = j.out[ip].hold
		delete(j.out, ip)
	}
	clear(j.seconds)
	clear(j.worseSince)
	j.changedAt = now
	return PointVerdict{Path: j.Path(offered), Change: true, Left: left, Back: back, Why: why}
}

func tickOf(ticks []PointTick, ip netip.Addr) (PointTick, bool) {
	for _, t := range ticks {
		if t.IP == ip {
			return t, true
		}
	}
	return PointTick{}, false
}
