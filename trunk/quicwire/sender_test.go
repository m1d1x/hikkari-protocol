package quicwire

import (
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
	"github.com/m1d1x/hikkari-protocol/wire/datagram"
)

// The wire's sender, measured (hikkari-client
// plans/research/2026-11-11-trunk-quic-wire-sender.md): the entry's quic wire
// carries bulk over QUIC streams, and since v1.05 the datagram channel it is
// made of sends with the guard (no window, no pacing, a limit only on loss)
// unless told BBR. A border line between two data centres is shared: the
// bare UDP wire carrying voice crosses the same bottleneck. So each sender
// takes 12 MiB downloads exit → entry across an emulated line while a call
// (64 B every 20 ms, as the trunk's) crosses it beside them, and the line
// counts what it dropped.
//
// A measurement, not a check: HIKKARI_WIRE_SENDER=1 go test -run
// TestQuicWireSenderOnASharedLine -v.

// shapedLine is one bottleneck each way: a rate, a drop-tail queue of at
// most buffer, a one-way delay after it, and random loss.
type shapedLine struct {
	rate   float64 // bytes a second
	delay  time.Duration
	buffer time.Duration
	loss   float64

	mu      sync.Mutex
	free    [2]time.Time
	q       [2]chan held
	dropped [2]atomic.Int64 // bytes the queue or the loss took
	passed  [2]atomic.Int64
}

const (
	up   = 0 // entry → exit
	down = 1 // exit → entry
)

type held struct {
	at   time.Time
	b    []byte
	send func([]byte)
}

func newShapedLine(mbps float64, rtt, buffer time.Duration, loss float64) *shapedLine {
	l := &shapedLine{rate: mbps * 1e6 / 8, delay: rtt / 2, buffer: buffer, loss: loss}
	for d := range l.q {
		l.q[d] = make(chan held, 1<<16)
		go l.deliver(l.q[d])
	}
	return l
}

func (l *shapedLine) enter(dir int, b []byte, send func([]byte)) {
	now := time.Now()
	l.mu.Lock()
	start := l.free[dir]
	if start.Before(now) {
		start = now
	}
	if start.Sub(now) > l.buffer || l.loss > 0 && rand.Float64() < l.loss {
		l.mu.Unlock()
		l.dropped[dir].Add(int64(len(b)))
		return
	}
	done := start.Add(time.Duration(float64(len(b)) / l.rate * float64(time.Second)))
	l.free[dir] = done
	l.mu.Unlock()
	l.passed[dir].Add(int64(len(b)))
	l.q[dir] <- held{at: done.Add(l.delay), b: append([]byte(nil), b...), send: send}
}

// deliver hands packets over in order at their time.
func (l *shapedLine) deliver(q chan held) {
	for h := range q {
		if d := time.Until(h.at); d > 0 {
			time.Sleep(d)
		}
		h.send(h.b)
	}
}

// relay is a UDP address on the line in front of target: each source gets
// its own socket towards target, as a NAT would.
func (l *shapedLine) relay(t *testing.T, target netip.AddrPort) netip.AddrPort {
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { front.Close() })
	var mu sync.Mutex
	backs := map[netip.AddrPort]*net.UDPConn{}
	go func() {
		b := make([]byte, 65536)
		for {
			n, from, err := front.ReadFromUDPAddrPort(b)
			if err != nil {
				return
			}
			mu.Lock()
			back := backs[from]
			if back == nil {
				back, err = net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(target))
				if err != nil {
					mu.Unlock()
					continue
				}
				backs[from] = back
				t.Cleanup(func() { back.Close() })
				go func(back *net.UDPConn, client netip.AddrPort) {
					rb := make([]byte, 65536)
					for {
						n, err := back.Read(rb)
						if err != nil {
							return
						}
						l.enter(down, rb[:n], func(p []byte) { _, _ = front.WriteToUDPAddrPort(p, client) })
					}
				}(back, from)
			}
			mu.Unlock()
			l.enter(up, b[:n], func(p []byte) { _, _ = back.Write(p) })
		}
	}()
	return front.LocalAddr().(*net.UDPAddr).AddrPort()
}

// lineCall is the trunk's call across the line: 64 B every 20 ms to an
// echo, what came back and how long the longest silence was.
type lineCall struct {
	mu     sync.Mutex
	sent   int
	rtts   []time.Duration
	last   time.Time
	gapMax time.Duration
	gaps60 int
}

func (c *lineCall) run(conn *net.UDPConn, stop <-chan struct{}) {
	go func() {
		<-stop
		conn.Close()
	}()
	sentAt := sync.Map{}
	go func() {
		b := make([]byte, 128)
		for {
			n, err := conn.Read(b)
			if err != nil || n < 8 {
				return
			}
			seq := int64(b[0])<<24 | int64(b[1])<<16 | int64(b[2])<<8 | int64(b[3])
			at, ok := sentAt.LoadAndDelete(seq)
			if !ok {
				continue
			}
			now := time.Now()
			c.mu.Lock()
			c.rtts = append(c.rtts, now.Sub(at.(time.Time)))
			if !c.last.IsZero() {
				g := now.Sub(c.last)
				c.gapMax = max(c.gapMax, g)
				if g > 60*time.Millisecond {
					c.gaps60++
				}
			}
			c.last = now
			c.mu.Unlock()
		}
	}()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	p := make([]byte, 64)
	for seq := int64(0); ; seq++ {
		select {
		case <-stop:
			return
		case <-tick.C:
		}
		p[0], p[1], p[2], p[3] = byte(seq>>24), byte(seq>>16), byte(seq>>8), byte(seq)
		sentAt.Store(seq, time.Now())
		c.mu.Lock()
		c.sent++
		c.mu.Unlock()
		_, _ = conn.Write(p)
	}
}

func udpEcho(t *testing.T) netip.AddrPort {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := c.ReadFromUDPAddrPort(b)
			if err != nil {
				return
			}
			_, _ = c.WriteToUDPAddrPort(b[:n], from)
		}
	}()
	return c.LocalAddr().(*net.UDPAddr).AddrPort()
}

type senderCase struct {
	name   string
	mbps   float64
	buffer time.Duration
	loss   float64
}

func TestQuicWireSenderOnASharedLine(t *testing.T) {
	if os.Getenv("HIKKARI_WIRE_SENDER") == "" {
		t.Skip("a measurement: HIKKARI_WIRE_SENDER=1")
	}
	const rtt = 47 * time.Millisecond // nekko-spb ↔ unl1, the stand's call p50
	cases := []senderCase{
		{"100 Мбит/с, очередь 20 мс", 100, 20 * time.Millisecond, 0},
		{"100 Мбит/с, очередь 20 мс, потеря 0,5%", 100, 20 * time.Millisecond, 0.005},
		{"100 Мбит/с, очередь 100 мс", 100, 100 * time.Millisecond, 0},
		{"300 Мбит/с, очередь 10 мс", 300, 10 * time.Millisecond, 0},
	}
	for _, c := range cases {
		for _, s := range []string{datagram.SenderBBR, datagram.SenderGuard} {
			t.Run(c.name+"/"+s, func(t *testing.T) { senderOnALine(t, c, s, rtt) })
		}
	}
}

func senderOnALine(t *testing.T, c senderCase, sender string, rtt time.Duration) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	line := newShapedLine(c.mbps, rtt, c.buffer, c.loss)
	x := trunk.NewExit(trunk.Config{}, echoLocal{"127.0.0.1:1"})
	go x.Run(ctx)
	at := freePort(t)
	srv, err := Listen(ctx, ListenOptions{Listen: at.String(), Keys: []string{key}, SNI: "www.example.com", Sender: sender,
		Serve: func(m io.ReadWriteCloser) { _ = x.ServeMember(m) }})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ports, _ := trunk.NewPortBook(42000, 43000, time.Minute)
	pool := func(ctx context.Context, _ int) (io.ReadWriteCloser, error) {
		a, b := net.Pipe()
		go func() { _ = x.ServeMember(b) }()
		return a, nil
	}
	e, err := trunk.NewEntry(trunk.Config{}, 1, pool, ports, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	const quic trunk.WireID = 1
	d := Dialer{Exit: line.relay(t, at), Key: key, SNI: "www.example.com", Sender: sender}
	// As on the entry: four members (entry-box trunk-entry-wires udp:2,quic:4).
	if err := e.AddWire(trunk.Wire{ID: quic, Name: "quic", Shape: "browser", Members: 4, Streams: true, Dial: d.Dial}); err != nil {
		t.Fatal(err)
	}
	e.SetRoute(trunk.Route{Voice: trunk.AnyWire, Bulk: quic})
	// Run logs to the test: the test waits for it to end first.
	ran := make(chan struct{})
	go func() { defer close(ran); e.Run(ctx) }()
	defer func() { cancel(); <-ran }()
	waitFor(t, func() bool { return e.Wires()[quic].Members == 4 })

	// The call beside, settled before the bulk.
	var call lineCall
	stop := make(chan struct{})
	callConn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(line.relay(t, udpEcho(t))))
	if err != nil {
		t.Fatal(err)
	}
	go call.run(callConn, stop)
	time.Sleep(2 * time.Second)
	call.mu.Lock()
	quiet := len(call.rtts)
	call.mu.Unlock()

	const n, rounds = 12 << 20, 5
	var rates []float64
	var ends []string
	start := time.Now()
	for i := 0; i < rounds; i++ {
		dctx, dcancel := context.WithTimeout(ctx, 60*time.Second)
		r := e.Download(dctx, quic, n)
		dcancel()
		ends = append(ends, r.End)
		if r.End == "ok" {
			rates = append(rates, float64(r.Got)*8/r.Took.Seconds()/1e6)
		}
		time.Sleep(time.Second)
	}
	took := time.Since(start)
	close(stop)
	time.Sleep(100 * time.Millisecond)

	call.mu.Lock()
	defer call.mu.Unlock()
	sort.Float64s(rates)
	med := 0.0
	if len(rates) > 0 {
		med = rates[len(rates)/2]
	}
	busy := call.rtts[quiet:]
	sort.Slice(busy, func(i, j int) bool { return busy[i] < busy[j] })
	p := func(q float64) time.Duration {
		if len(busy) == 0 {
			return 0
		}
		return busy[min(len(busy)-1, int(q*float64(len(busy))))]
	}
	lost := call.sent - len(call.rtts)
	downDropped, downPassed := line.dropped[down].Load(), line.passed[down].Load()
	t.Logf("RESULT | %s | %s | 12 МиБ: %s Мбит/с, медиана %.0f | %v | линия вниз: отброшено %.1f%% (%d КиБ) | звонок: потеряно %d из %d, rtt p50 %v p99 %v, gap_max %v, gaps60 %d | %v",
		c.name, sender, fmtRates(rates), med, ends, 100*float64(downDropped)/float64(downDropped+downPassed+1), downDropped>>10,
		lost, call.sent, p(0.5).Round(time.Millisecond), p(0.99).Round(time.Millisecond), call.gapMax.Round(time.Millisecond), call.gaps60, took.Round(time.Second))
}

func fmtRates(r []float64) string {
	s := ""
	for i, v := range r {
		if i > 0 {
			s += ","
		}
		s += fmt.Sprintf("%.0f", v)
	}
	return s
}
