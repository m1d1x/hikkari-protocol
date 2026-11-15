//go:build lab

package udpwire

// The night of 14.11 (20:13–20:37 UTC) on the bench: an entry and an exit of
// the trunk on real sockets of this box, the udp wire on UDP, the pool on
// TCP, and the path between them shaped by netem the way the call saw it
// that night (lab/night.sh). Each arm is a way to carry one voice call's
// frames: one datagram per 20 ms frame, and copies of it on the udp wire, on
// the pool, or both. What counts is what a listener hears: a frame that is
// not there by its play time is a hole, whichever copy was meant to bring it.
//
// Run as root in the lab's netns (lab/night.sh does it):
//
//	go test -c -tags lab -o /tmp/lab.test ./udpwire
//	ip netns exec hklab /tmp/lab.test -test.run TestNight -test.v
//
// LAB_SECONDS is how long the call runs (default 120), LAB_OUT a file for
// the arms' results as JSON.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

// The exit's ports the netem filters know (lab/night.sh).
const (
	labUDPPort  = 47001
	labPoolPort = 47002
	labFrame    = 20 * time.Millisecond
)

// labSend is one way a frame leaves: on a flow, after a delay from the frame's
// time.
type labSend struct {
	flow  string
	after time.Duration
}

// labArm is one way to carry a call.
type labArm struct {
	Name  string
	What  string
	sends []labSend
}

// The arms. The flows: u1 one copy on the udp wire, u2 two copies on two of
// its members at once (the trunk's Copies), p1 one copy on the pool.
var labArms = []labArm{
	{Name: "udp", What: "одна копия по udp", sends: []labSend{{"u1", 0}}},
	{Name: "udp x2", What: "две копии по двум членам udp разом (Copies 2)", sends: []labSend{{"u2", 0}}},
	{Name: "udp x2 +10ms", What: "две копии по udp, вторая через 10 мс", sends: []labSend{{"u1", 0}, {"u1", 10 * time.Millisecond}}},
	{Name: "udp x3 +7ms", What: "три копии по udp через 7 мс", sends: []labSend{{"u1", 0}, {"u1", 7 * time.Millisecond}, {"u1", 14 * time.Millisecond}}},
	{Name: "pool", What: "одна копия по пулу (TCP)", sends: []labSend{{"p1", 0}}},
	{Name: "udp + pool", What: "копия по udp и копия по пулу (как клиент v1.02: QUIC и Naive)", sends: []labSend{{"u1", 0}, {"p1", 0}}},
	{Name: "udp x2 +10ms + pool", What: "две копии по udp через 10 мс и копия по пулу", sends: []labSend{{"u1", 0}, {"u1", 10 * time.Millisecond}, {"p1", 0}}},
}

// labCall is what one arm's frames did.
type labCall struct {
	mu      sync.Mutex
	born    []time.Time // by frame
	arrived []time.Time // the first copy back, zero if none
}

func (c *labCall) arrive(seq uint32, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if int(seq) < len(c.arrived) && c.arrived[seq].IsZero() {
		c.arrived[seq] = at
	}
}

// LabResult is what a listener of one arm heard at one play delay.
type LabResult struct {
	Arm        string  `json:"arm"`
	What       string  `json:"what"`
	BufferMS   int     `json:"buffer_ms"`
	Frames     int     `json:"frames"`
	LostPct    float64 `json:"lost_pct"`    // no copy came at all (within 2 s)
	HolesPct   float64 `json:"holes_pct"`   // not there by play time: lost or late
	Holes2     float64 `json:"holes2_min"`  // runs of 2+ frames (40 ms+) per minute
	Holes3     float64 `json:"holes3_min"`  // runs of 3+ frames (60 ms+) per minute
	WorstMS    int     `json:"worst_ms"`    // the longest run
	BadSeconds float64 `json:"bad_seconds"` // share of seconds with 3+ of 50 frames holes (6%+)
	RTTp50     float64 `json:"rtt_p50_ms"`
	RTTp99     float64 `json:"rtt_p99_ms"`
	// The call's own numbers, as the trunk's call counts them on the hub
	// (trunk/call.go): lost, and pauses between answers over 60 and 150 ms
	// per minute, to set the bench against the night.
	CallGaps60  float64 `json:"call_gaps60_min"`
	CallGaps150 float64 `json:"call_gaps150_min"`
}

func TestNight(t *testing.T) {
	seconds := 120
	if s, err := strconv.Atoi(os.Getenv("LAB_SECONDS")); err == nil && s > 0 {
		seconds = s
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	x := trunk.NewExit(trunk.Config{}, nolocal{})
	go x.Run(ctx)
	l, err := Listen(fmt.Sprintf("127.0.0.1:%d", labUDPPort), []string{key}, func(c io.ReadWriteCloser) { _ = x.ServeMember(c) })
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	tl, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", labPoolPort))
	if err != nil {
		t.Fatal(err)
	}
	defer tl.Close()
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			go func() { _ = x.ServeMember(c) }()
		}
	}()

	ports, _ := trunk.NewPortBook(40000, 41000, time.Minute)
	pool := func(ctx context.Context, localPort int) (io.ReadWriteCloser, error) {
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: localPort}}
		return d.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", labPoolPort))
	}
	e, err := trunk.NewEntry(trunk.Config{}, 4, pool, ports, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	const udp trunk.WireID = 2
	if err := e.AddWire(trunk.Wire{ID: udp, Name: "udp", Shape: "random", Members: 3, Packet: true,
		Dial: Dialer{Exit: l.Addr(), Key: key}.Dial}); err != nil {
		t.Fatal(err)
	}
	go e.Run(ctx)
	waitFor(t, func() bool { w := e.Wires(); return w[udp].Members == 3 && w[trunk.PoolWire].Members == 4 })

	frames := seconds * int(time.Second/labFrame)
	calls := make([]*labCall, len(labArms))
	for i := range calls {
		calls[i] = &labCall{born: make([]time.Time, frames), arrived: make([]time.Time, frames)}
	}
	// A datagram: arm (1 B), frame (4 B), padding to a voice frame's size.
	deliver := func(p []byte) {
		if len(p) < 5 || int(p[0]) >= len(calls) {
			return
		}
		calls[p[0]].arrive(binary.BigEndian.Uint32(p[1:5]), time.Now())
	}
	s := e.Session()
	flows := map[string]*trunk.Flow{
		"u1": s.OpenFlowWith(trunk.EchoPort, trunk.FlowOptions{Copies: 1, Class: trunk.ClassVoice, Pin: udp}, deliver, nil),
		"u2": s.OpenFlowWith(trunk.EchoPort, trunk.FlowOptions{Copies: 2, Class: trunk.ClassVoice, Pin: udp}, deliver, nil),
		"p1": s.OpenFlowWith(trunk.EchoPort, trunk.FlowOptions{Copies: 1, Class: trunk.ClassVoice, Pin: trunk.PoolWire}, deliver, nil),
	}
	start := time.Now().Add(100 * time.Millisecond)
	var wg sync.WaitGroup
	for ai, arm := range labArms {
		for _, sd := range arm.sends {
			wg.Add(1)
			go func(ai int, sd labSend) {
				defer wg.Done()
				f := flows[sd.flow]
				for seq := 0; seq < frames; seq++ {
					at := start.Add(time.Duration(seq)*labFrame + sd.after)
					time.Sleep(time.Until(at))
					p := make([]byte, 160)
					p[0] = byte(ai)
					binary.BigEndian.PutUint32(p[1:5], uint32(seq))
					if sd.after == 0 {
						calls[ai].mu.Lock()
						if calls[ai].born[seq].IsZero() {
							calls[ai].born[seq] = start.Add(time.Duration(seq) * labFrame)
						}
						calls[ai].mu.Unlock()
					}
					f.Send(p)
				}
			}(ai, sd)
		}
	}
	wg.Wait()
	time.Sleep(2 * time.Second) // the last answers

	// The play delay is the path's own round trip (the best any copy did)
	// plus a jitter buffer: what a call app holds a frame back for.
	base := time.Duration(1 << 62)
	for _, c := range calls {
		for i, a := range c.arrived {
			if !a.IsZero() && a.Sub(c.born[i]) < base {
				base = a.Sub(c.born[i])
			}
		}
	}
	var out []LabResult
	for ai, arm := range labArms {
		for _, buf := range []int{40, 60, 100} {
			out = append(out, labHeard(arm, calls[ai], base+time.Duration(buf)*time.Millisecond, buf, seconds))
		}
	}
	t.Logf("base round trip %v, %d frames an arm", base.Round(100*time.Microsecond), frames)
	t.Logf("%-20s %4s %7s %7s %7s %7s %6s %6s %7s %7s %6s %6s", "arm", "buf", "lost%", "holes%", "h2/min", "h3/min", "worst", "bad_s%", "p50", "p99", "g60", "g150")
	for _, r := range out {
		t.Logf("%-20s %4d %7.2f %7.2f %7.1f %7.1f %6d %6.1f %7.1f %7.1f %6.1f %6.1f", r.Arm, r.BufferMS, r.LostPct, r.HolesPct, r.Holes2, r.Holes3, r.WorstMS, r.BadSeconds, r.RTTp50, r.RTTp99, r.CallGaps60, r.CallGaps150)
	}
	if path := os.Getenv("LAB_OUT"); path != "" {
		b, _ := json.MarshalIndent(out, "", "  ")
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// labHeard is what a listener with the given play delay heard of c.
func labHeard(arm labArm, c *labCall, play time.Duration, buf, seconds int) LabResult {
	r := LabResult{Arm: arm.Name, What: strings.TrimSpace(arm.What), BufferMS: buf, Frames: len(c.born)}
	var lost, holes, run, worst, h2, h3 int
	perSec := make([]int, seconds+1)
	var rtts []time.Duration
	var answers []time.Time
	endRun := func() {
		if run >= 2 {
			h2++
		}
		if run >= 3 {
			h3++
		}
		if run > worst {
			worst = run
		}
		run = 0
	}
	for i, born := range c.born {
		a := c.arrived[i]
		if a.IsZero() || a.Sub(born) > 2*time.Second {
			lost++
		} else {
			rtts = append(rtts, a.Sub(born))
			answers = append(answers, a)
		}
		if a.IsZero() || a.Sub(born) > play {
			holes++
			run++
			perSec[i*int(labFrame)/int(time.Second)]++
			continue
		}
		endRun()
	}
	endRun()
	bad := 0
	for _, n := range perSec[:seconds] {
		if n >= 3 {
			bad++
		}
	}
	minutes := float64(seconds) / 60
	n := float64(len(c.born))
	r.LostPct = 100 * float64(lost) / n
	r.HolesPct = 100 * float64(holes) / n
	r.Holes2 = float64(h2) / minutes
	r.Holes3 = float64(h3) / minutes
	r.WorstMS = worst * int(labFrame/time.Millisecond)
	r.BadSeconds = 100 * float64(bad) / float64(seconds)
	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	if len(rtts) > 0 {
		r.RTTp50 = float64(rtts[len(rtts)/2]) / 1e6
		r.RTTp99 = float64(rtts[len(rtts)*99/100]) / 1e6
	}
	// The call's pauses: between answers in the order they came.
	sort.Slice(answers, func(i, j int) bool { return answers[i].Before(answers[j]) })
	var g60, g150 int
	for i := 1; i < len(answers); i++ {
		gap := answers[i].Sub(answers[i-1])
		if gap > 60*time.Millisecond {
			g60++
		}
		if gap > 150*time.Millisecond {
			g150++
		}
	}
	r.CallGaps60 = float64(g60) / minutes
	r.CallGaps150 = float64(g150) / minutes
	return r
}
