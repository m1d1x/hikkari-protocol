package pipectl

import (
	"net/netip"
	"slices"
	"testing"
	"time"
)

var (
	unl1  = netip.MustParseAddr("10.0.0.1")
	hkfi1 = netip.MustParseAddr("10.0.0.2")
	riga  = netip.MustParseAddr("10.0.0.3")
)

// pointShape is how a point answers each second: its round trip and how
// often it is late (every late-th second; 0: never).
type pointShape struct {
	rtt  time.Duration
	late int
}

// runPoints steps a judge once a second for d from start with the points
// shaped as shapes, the offered ones in order; it stops at the first change
// and says it, and the time it came.
func runPoints(j *PointJudge, start time.Time, d time.Duration, offered []netip.Addr, shapes map[netip.Addr]pointShape) (PointVerdict, time.Time) {
	for s := time.Duration(0); s <= d; s += time.Second {
		now := start.Add(s)
		var ticks []PointTick
		sec := int(s / time.Second)
		for _, ip := range j.Path(offered) {
			sh := shapes[ip]
			t := PointTick{IP: ip, Members: 11, Up: 11, ProofAgo: 80 * time.Millisecond, RTT: sh.rtt}
			if sh.late > 0 && sec%sh.late == 0 {
				t.ProofAgo = 700 * time.Millisecond
			}
			if sh.rtt < 0 {
				t.Up, t.ProofAgo = 0, 5*time.Second
			}
			ticks = append(ticks, t)
		}
		if v := j.Step(now, offered, ticks, -1); v.Change {
			return v, now
		}
	}
	return PointVerdict{}, start.Add(d)
}

// TestTheJudgeTakesOffAPointLateAQuarterOfTheTime: 27.11 edislv1 beside
// unl1 and hkfi1, 31 ms slower and late in a quarter of its seconds, leaves
// the path in under two minutes; the others stay.
func TestTheJudgeTakesOffAPointLateAQuarterOfTheTime(t *testing.T) {
	var j PointJudge
	start := time.Unix(1_800_000_000, 0)
	offered := []netip.Addr{unl1, hkfi1, riga}
	shapes := map[netip.Addr]pointShape{
		unl1:  {rtt: 62 * time.Millisecond},
		hkfi1: {rtt: 63 * time.Millisecond},
		riga:  {rtt: 93 * time.Millisecond, late: 4},
	}
	v, at := runPoints(&j, start, 5*time.Minute, offered, shapes)
	if !v.Change || !slices.Equal(v.Left, []netip.Addr{riga}) {
		t.Fatalf("verdict %+v, want riga off", v)
	}
	if !slices.Equal(v.Path, []netip.Addr{unl1, hkfi1}) {
		t.Fatalf("path %v", v.Path)
	}
	if took := at.Sub(start); took > 2*time.Minute {
		t.Fatalf("riga left after %s", took)
	}
}

// TestTheJudgeKeepsPointsAlike: three points within 15 ms of each other and
// never late (hkfi1 from aezamsk1, 27.11) all stay for an hour.
func TestTheJudgeKeepsPointsAlike(t *testing.T) {
	var j PointJudge
	start := time.Unix(1_800_000_000, 0)
	offered := []netip.Addr{unl1, hkfi1, riga}
	shapes := map[netip.Addr]pointShape{
		unl1:  {rtt: 46 * time.Millisecond},
		hkfi1: {rtt: 61 * time.Millisecond},
		riga:  {rtt: 55 * time.Millisecond, late: 60},
	}
	if v, _ := runPoints(&j, start, time.Hour, offered, shapes); v.Change {
		t.Fatalf("a point moved: %+v", v)
	}
}

// TestTheJudgeNeverLeavesFewerThanTwoPoints: of two points, however bad one
// is, both stay.
func TestTheJudgeNeverLeavesFewerThanTwoPoints(t *testing.T) {
	var j PointJudge
	start := time.Unix(1_800_000_000, 0)
	offered := []netip.Addr{unl1, riga}
	shapes := map[netip.Addr]pointShape{unl1: {rtt: 62 * time.Millisecond}, riga: {rtt: 200 * time.Millisecond, late: 2}}
	if v, _ := runPoints(&j, start, 30*time.Minute, offered, shapes); v.Change {
		t.Fatalf("a point moved: %+v", v)
	}
}

// TestAPointOutComesBackAfterItsHoldAndDoublesIt: the point out comes back
// after 10 min; still bad, it leaves again for 20 min.
func TestAPointOutComesBackAfterItsHoldAndDoublesIt(t *testing.T) {
	var j PointJudge
	start := time.Unix(1_800_000_000, 0)
	offered := []netip.Addr{unl1, hkfi1, riga}
	shapes := map[netip.Addr]pointShape{
		unl1:  {rtt: 62 * time.Millisecond},
		hkfi1: {rtt: 63 * time.Millisecond},
		riga:  {rtt: 93 * time.Millisecond, late: 4},
	}
	_, left := runPoints(&j, start, 5*time.Minute, offered, shapes)
	v, back := runPoints(&j, left.Add(time.Second), 15*time.Minute, offered, shapes)
	if !slices.Equal(v.Back, []netip.Addr{riga}) || back.Sub(left) < pointHold || back.Sub(left) > pointHold+2*time.Second {
		t.Fatalf("verdict %+v after %s, want riga back after %s", v, back.Sub(left), pointHold)
	}
	_, again := runPoints(&j, back.Add(time.Second), 5*time.Minute, offered, shapes)
	if got := j.out[riga].hold; got != 2*pointHold || !j.out[riga].until.Equal(again.Add(2*pointHold)) {
		t.Fatalf("hold %s, want %s", got, 2*pointHold)
	}
}

// TestAPointOutComesBackWhenThePathIsLeftOnOne: with a point out, one of
// the two left dies: the point out comes back at once.
func TestAPointOutComesBackWhenThePathIsLeftOnOne(t *testing.T) {
	var j PointJudge
	start := time.Unix(1_800_000_000, 0)
	offered := []netip.Addr{unl1, hkfi1, riga}
	shapes := map[netip.Addr]pointShape{
		unl1:  {rtt: 62 * time.Millisecond},
		hkfi1: {rtt: 63 * time.Millisecond},
		riga:  {rtt: 93 * time.Millisecond, late: 4},
	}
	_, left := runPoints(&j, start, 5*time.Minute, offered, shapes)
	shapes[hkfi1] = pointShape{rtt: -1}
	v, back := runPoints(&j, left.Add(time.Second), time.Minute, offered, shapes)
	if !slices.Equal(v.Back, []netip.Addr{riga}) || back.Sub(left) > 2*time.Second {
		t.Fatalf("verdict %+v after %s, want riga back at once", v, back.Sub(left))
	}
}

// TestTheJudgeHoldsThroughTheEntrysOwnPause: a pause of the entry makes
// every proof old: nothing is counted and nothing moves.
func TestTheJudgeHoldsThroughTheEntrysOwnPause(t *testing.T) {
	var j PointJudge
	now := time.Unix(1_800_000_000, 0)
	offered := []netip.Addr{unl1, hkfi1, riga}
	for s := 0; s < 600; s++ {
		ticks := []PointTick{{IP: unl1, Up: 0, ProofAgo: time.Second}, {IP: hkfi1, Up: 0, ProofAgo: time.Second}, {IP: riga, Up: 0, ProofAgo: time.Second}}
		if v := j.Step(now.Add(time.Duration(s)*time.Second), offered, ticks, 100*time.Millisecond); v.Change {
			t.Fatalf("moved in a pause: %+v", v)
		}
	}
	if len(j.seconds) != 0 {
		t.Fatalf("counted seconds in a pause: %v", j.seconds)
	}
}

// TestAPointNoLongerOfferedIsForgotten: the hub takes a point out of the
// offer while it is out of the path: nothing of it stays.
func TestAPointNoLongerOfferedIsForgotten(t *testing.T) {
	var j PointJudge
	start := time.Unix(1_800_000_000, 0)
	offered := []netip.Addr{unl1, hkfi1, riga}
	shapes := map[netip.Addr]pointShape{
		unl1:  {rtt: 62 * time.Millisecond},
		hkfi1: {rtt: 63 * time.Millisecond},
		riga:  {rtt: 93 * time.Millisecond, late: 4},
	}
	_, left := runPoints(&j, start, 5*time.Minute, offered, shapes)
	j.Step(left.Add(time.Second), []netip.Addr{unl1, hkfi1}, nil, -1)
	if _, ok := j.out[riga]; ok {
		t.Fatal("a point no longer offered is still out")
	}
	if got := j.Path(offered); !slices.Equal(got, offered) {
		t.Fatalf("offered again, path %v", got)
	}
}
