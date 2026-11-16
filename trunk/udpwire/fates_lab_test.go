//go:build lab

package udpwire

// Voice on two fates under the night of 14.11 (fates_lab.sh): a real entry
// and exit of the trunk on this box's sockets, the udp wire on UDP and the
// pool on TCP, the path to the exit shaped by netem as the bench found the
// night (plans/research/2026-11-15-voice-night-lab.md): Gilbert 14.7%/67% on
// the udp wire, random 3% on the pool's segments, 21 ms each way. One voice
// flow with one copy, routed on the udp wire as the selector routes it: the
// set carries it on the pool as well (spec/trunk.md Datagrams), and a
// listener with a 60 ms buffer hears under 1% holes and no run of two.
//
// Run as root in the lab's netns (fates_lab.sh does it):
//
//	go test -c -tags lab -o /tmp/hkfates.test ./udpwire
//	ip netns exec hklab /tmp/hkfates.test -test.run TestVoiceRidesTwoFatesUnderTheNight -test.v
//
// LAB_SECONDS is how long the call runs (default 60).

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

// The exit's ports the netem filters know (fates_lab.sh).
const (
	fatesUDPPort  = 47001
	fatesPoolPort = 47002
	fatesFrame    = 20 * time.Millisecond
)

func TestVoiceRidesTwoFatesUnderTheNight(t *testing.T) {
	seconds := 60
	if s, err := strconv.Atoi(os.Getenv("LAB_SECONDS")); err == nil && s > 0 {
		seconds = s
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	x := trunk.NewExit(trunk.Config{}, nolocal{})
	go x.Run(ctx)
	l, err := Listen(fmt.Sprintf("127.0.0.1:%d", fatesUDPPort), []string{key}, func(c io.ReadWriteCloser) { _ = x.ServeMember(c) })
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	tl, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", fatesPoolPort))
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
		return d.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", fatesPoolPort))
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
	e.SetRoute(trunk.Route{Voice: udp, Bulk: trunk.PoolWire})

	frames := seconds * int(time.Second/fatesFrame)
	born, arrived := make([]time.Time, frames), make([]time.Time, frames)
	var mu sync.Mutex
	deliver := func(p []byte) {
		if len(p) < 4 {
			return
		}
		seq := binary.BigEndian.Uint32(p)
		mu.Lock()
		if int(seq) < frames && arrived[seq].IsZero() {
			arrived[seq] = time.Now()
		}
		mu.Unlock()
	}
	f := e.Session().OpenFlowWith(trunk.EchoPort, trunk.FlowOptions{Copies: 1, Class: trunk.ClassVoice, Pin: trunk.AnyWire}, deliver, nil)
	start := time.Now().Add(100 * time.Millisecond)
	for seq := 0; seq < frames; seq++ {
		at := start.Add(time.Duration(seq) * fatesFrame)
		time.Sleep(time.Until(at))
		p := make([]byte, 160)
		binary.BigEndian.PutUint32(p, uint32(seq))
		mu.Lock()
		born[seq] = at
		mu.Unlock()
		f.Send(p)
	}
	time.Sleep(2 * time.Second)

	mu.Lock()
	defer mu.Unlock()
	best := time.Duration(1 << 62)
	for i, a := range arrived {
		if !a.IsZero() && a.Sub(born[i]) < best {
			best = a.Sub(born[i])
		}
	}
	for _, buf := range []time.Duration{40 * time.Millisecond, 60 * time.Millisecond, 100 * time.Millisecond} {
		holes, runs2, lost := 0, 0, 0
		run := 0
		for i, a := range arrived {
			if a.IsZero() {
				lost++
			}
			if a.IsZero() || a.Sub(born[i]) > best+buf {
				holes++
				run++
				continue
			}
			if run >= 2 {
				runs2++
			}
			run = 0
		}
		if run >= 2 {
			runs2++
		}
		pct := 100 * float64(holes) / float64(frames)
		t.Logf("buffer %v: holes %d of %d (%.2f%%), runs of 2+ %d, lost %d; best round trip %v", buf, holes, frames, pct, runs2, lost, best.Round(100*time.Microsecond))
		if buf == 60*time.Millisecond && (holes*100 >= frames || runs2 != 0) {
			t.Errorf("buffer 60 ms: holes %.2f%%, runs of 2+ %d: want under 1%% and none", pct, runs2)
		}
	}
}
