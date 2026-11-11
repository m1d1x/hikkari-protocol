package hikkari_test

import (
	"context"
	"crypto/tls"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/client"
	"github.com/m1d1x/hikkari-protocol/internal/testcert"
	"github.com/m1d1x/hikkari-protocol/server"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// bloatedLine is a home line whose downlink queue another download has
// filled: every packet towards the client waits bloat more, in order, the
// queue drains at the line's rate (lineSlot a packet), and none is dropped (the QUIC connections see no loss) unless limit is set.
// Every QUIC connection through the line shares its one queue. The relay's QUIC
// connections learn the line's round trip while it is idle, then the queue
// grows, as a TCP download under the call grows it.
type bloatedLine struct {
	bloat atomic.Int64 // ns
	// limit, when set, is the longest a packet may wait in the line's queue:
	// one that would wait longer is dropped, as a home router's full buffer
	// drops it, and the QUIC connections see the loss.
	limit time.Duration
	// track keeps every packet's time in the line, for delayAt.
	track bool

	mu      sync.Mutex
	last    time.Time // FIFO across the line: no packet overtakes the one before
	log     []passage // when track is set, by at
	dropped int64
}

// passage is one packet the line handed over: when, and how long it waited
// in the line's queue.
type passage struct {
	at   time.Time
	wait time.Duration
}

// enter queues one packet arriving now and says when the line hands it over,
// or false when the line drops it.
func (l *bloatedLine) enter(now time.Time) (time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	at := now.Add(time.Duration(l.bloat.Load()))
	if at.Before(l.last.Add(lineSlot)) {
		at = l.last.Add(lineSlot) // the line drains its queue at its rate
	}
	if l.limit > 0 && at.Sub(now) > l.limit {
		l.dropped++
		return time.Time{}, false
	}
	l.last = at
	if l.track {
		l.log = append(l.log, passage{at, at.Sub(now)})
	}
	return at, true
}

// delayAt is the longest wait in the line of the packets it handed over in
// [from, to]: the line's own delay at that moment, our queues not counted.
func (l *bloatedLine) delayAt(from, to time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	i := sort.Search(len(l.log), func(i int) bool { return !l.log[i].at.Before(from) })
	var worst time.Duration
	for ; i < len(l.log) && !l.log[i].at.After(to); i++ {
		worst = max(worst, l.log[i].wait)
	}
	return worst
}

// peak is the longest wait any packet had in the line since since.
func (l *bloatedLine) peak(since time.Time) time.Duration {
	return l.delayAt(since, time.Now())
}

// empty is when the line hands over the last packet it holds now.
func (l *bloatedLine) empty() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.last
}

func (l *bloatedLine) drops() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.dropped
}

func (l *bloatedLine) DialContext(ctx context.Context, network string, dest M.Socksaddr) (net.Conn, error) {
	c, err := N.SystemDialer.DialContext(ctx, network, dest)
	if err != nil {
		return nil, err
	}
	b := &bloatedConn{Conn: c, line: l, in: make(chan arrival, 1<<16)}
	go b.pump()
	return b, nil
}

func (l *bloatedLine) ListenPacket(ctx context.Context, dest M.Socksaddr) (net.PacketConn, error) {
	return N.SystemDialer.ListenPacket(ctx, dest)
}

// lineSlot is one packet's time on the line (about 40 Mbit/s).
const lineSlot = 250 * time.Microsecond

type arrival struct {
	b  []byte
	at time.Time // when the line hands it to the client
}

type bloatedConn struct {
	net.Conn
	line *bloatedLine
	in   chan arrival
	rd   atomic.Pointer[time.Time]
}

func (c *bloatedConn) pump() {
	defer close(c.in)
	b := make([]byte, 2048)
	for {
		n, err := c.Conn.Read(b)
		if err != nil {
			return
		}
		at, ok := c.line.enter(time.Now())
		if !ok {
			continue
		}
		c.in <- arrival{append([]byte(nil), b[:n]...), at}
	}
}

func (c *bloatedConn) Read(p []byte) (int, error) {
	var timeout <-chan time.Time
	if d := c.rd.Load(); d != nil && !d.IsZero() {
		t := time.NewTimer(time.Until(*d))
		defer t.Stop()
		timeout = t.C
	}
	select {
	case a, ok := <-c.in:
		if !ok {
			return 0, net.ErrClosed
		}
		time.Sleep(time.Until(a.at))
		return copy(p, a.b), nil
	case <-timeout:
		return 0, &net.OpError{Op: "read", Err: errTimeout{}}
	}
}

func (c *bloatedConn) SetReadDeadline(t time.Time) error { c.rd.Store(&t); return nil }
func (c *bloatedConn) SetDeadline(t time.Time) error {
	c.rd.Store(&t)
	return c.Conn.SetWriteDeadline(t)
}

type errTimeout struct{}

func (errTimeout) Error() string   { return "i/o timeout" }
func (errTimeout) Timeout() bool   { return true }
func (errTimeout) Temporary() bool { return true }

// fanEcho answers every packet with fan packets of the same size and the
// same first four bytes: the far end of a call that sends its small video and
// its FEC beside the voice, so the voice lane carries hundreds of packets a
// second down.
func fanEcho(t *testing.T, fan int) *net.UDPConn {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := c.ReadFromUDP(b)
			if err != nil {
				return
			}
			for i := 0; i < fan; i++ {
				_, _ = c.WriteToUDP(b[:n], from)
			}
		}
	}()
	return c
}

// laneRun sends 160 B every 20 ms for run, each answered fan times, and
// reports how many answers came and how many came later than late after
// their packet was sent.
func laneRun(conn net.PacketConn, to net.Addr, run, late time.Duration, fan int) (got, tooLate, want int, worst time.Duration) {
	var mu sync.Mutex
	sentAt := map[uint32]time.Time{}
	start := time.Now()
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 2048)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(6 * time.Second))
			n, _, err := conn.ReadFrom(b)
			if err != nil {
				return
			}
			if n != 160 {
				continue
			}
			id := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
			mu.Lock()
			if at, ok := sentAt[id]; ok {
				got++
				d := time.Since(at)
				if d > late {
					tooLate++
				}
				if d > worst {
					worst = d
				}
			}
			mu.Unlock()
		}
	}()
	for id := uint32(1); time.Since(start) < run; id++ {
		p := make([]byte, 160)
		p[0], p[1], p[2], p[3] = byte(id>>24), byte(id>>16), byte(id>>8), byte(id)
		mu.Lock()
		sentAt[id] = time.Now()
		want += fan
		mu.Unlock()
		_, _ = conn.WriteTo(p, to)
		time.Sleep(20 * time.Millisecond)
	}
	<-done
	mu.Lock()
	defer mu.Unlock()
	return
}

// TestCallOnABloatedLine is tester tamila-001 on 2026-11-11: a Discord call
// (her voice lane carried 70 to 450 small packets a second down) while she
// downloads, the stream copy stuck behind the download (her Naive copy came 6
// to 52 s late). The download grows her line's downlink queue as TCP does: a
// sawtooth from nothing to 1.5 s, with no loss, after the relay's voice
// connection has learned the idle line. Plain BBR sized that connection's
// window by the idle round trip and the rate it delivered: on the long round
// trips the call did not fit, the rate fell, the window fell to four packets
// and the call waited seconds in the queues, the newest frames lost there.
// The voice sender keeps the call within the line's own delay.
func TestCallOnABloatedLine(t *testing.T) {
	const key = "subscriber-key-0123456789abcdef"
	const peak = 1500 * time.Millisecond
	const fan = 8 // 400 answers a second
	cert, pool := testcert.New("hk.example")
	keys := &roster{keys: map[string]bool{key: true}, slots: map[int]context.CancelFunc{}}
	listen := freeUDP(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hub := server.NewDupHub(loopbackExit{}, 0)
	d, err := server.ListenDatagram(ctx, server.DatagramOptions{
		Listen:      listen,
		Certificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil },
		Admitter:    keys,
		Exit:        loopbackExit{},
		Dup:         hub,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	d.SetKeys([]string{key})
	line := &bloatedLine{}
	newDatagram := func(name string) *client.Datagram {
		dc, err := client.NewDatagram(client.DatagramOptions{
			Context: ctx, Dialer: line, Server: M.ParseSocksaddr(listen), Password: key, Name: name,
			TLS: &testcert.Client{Config: &tls.Config{ServerName: "hk.example", RootCAs: pool}},
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = dc.Close() })
		return dc
	}
	stream := &hubStream{hub: hub, key: key}
	c := client.New(client.Options{
		Stream:        stream,
		Datagram:      newDatagram("datagram"),
		VoiceDatagram: newDatagram("voice"),
		Dup:           true,
	})
	far := fanEcho(t, fan)
	defer far.Close()
	conn, err := c.ListenPacket(ctx, M.Socksaddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// The call is seen, its voice connection learns the idle line.
	_, _, _, _ = laneRun(conn, far.LocalAddr(), 3*time.Second, time.Hour, fan)
	stream.stall.Store(true)
	defer stream.stall.Store(false)
	saw := make(chan struct{})
	go func() {
		defer close(saw)
		begin := time.Now()
		for time.Since(begin) < 16*time.Second {
			phase := time.Since(begin) % (4 * time.Second)
			line.bloat.Store(int64(peak) * int64(phase) / int64(4*time.Second))
			time.Sleep(10 * time.Millisecond)
		}
		line.bloat.Store(0)
	}()
	got, tooLate, want, worst := laneRun(conn, far.LocalAddr(), 16*time.Second, peak+300*time.Millisecond, fan)
	<-saw
	t.Logf("voice lane down: %d/%d answers, %d later than the line's %v + 300 ms, worst %v", got, want, tooLate, peak, worst)
	if got < want*97/100 || tooLate > want/100 {
		t.Fatalf("the voice connection holds the call back on a bloated line: %d/%d answers, %d too late, worst %v", got, want, tooLate, worst)
	}
}
