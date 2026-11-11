package datagram

import (
	"context"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// wire is a QUIC connection's send side as the scheduler sees it: it records
// every datagram, and while gate is held each send waits for it, as
// SendDatagram waits on a full queue behind a closed window.
type wire struct {
	mu    sync.Mutex
	sent  []udpMessage
	gate  chan struct{} // nil: sends at once
	delay time.Duration
}

func (w *wire) SendDatagram(p []byte) error {
	if w.gate != nil {
		<-w.gate
	}
	if w.delay > 0 {
		time.Sleep(w.delay)
	}
	var m udpMessage
	if err := decodeUDPMessage(&m, append([]byte(nil), p...)); err != nil {
		return err
	}
	m.data = nil
	w.mu.Lock()
	w.sent = append(w.sent, m)
	w.mu.Unlock()
	return nil
}

func (w *wire) messages() []udpMessage {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]udpMessage(nil), w.sent...)
}

func (w *wire) waitFor(t *testing.T, n int) []udpMessage {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := w.messages(); len(got) >= n {
			return got
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("the wire got %d datagrams, want %d", len(w.messages()), n)
	return nil
}

func newTestQueue(t *testing.T, w *wire) *sendQueue {
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	return newSendQueue(w, done)
}

func testAssociation(q *sendQueue, id uint32) *udpPacketConn {
	c := newUDPPacketConn(context.Background(), nil, q, func() {})
	c.sessionID = id
	return c
}

var testDest = M.ParseSocksaddr("10.0.0.1:3478")

func TestTheSchedulerKeepsAnAssociationsOrder(t *testing.T) {
	w := &wire{}
	q := newTestQueue(t, w)
	c := testAssociation(q, 1)
	for i := 0; i < 100; i++ {
		if _, err := c.WriteTo(make([]byte, 100), testDest.UDPAddr()); err != nil {
			t.Fatal(err)
		}
	}
	got := w.waitFor(t, 100)
	for i, m := range got {
		if m.packetID != uint16(i+1) || m.sessionID != 1 {
			t.Fatalf("datagram %d is packet %d of session %d", i, m.packetID, m.sessionID)
		}
	}
	if s := c.TakeStats(); s.Stale != 0 || s.Queue.N() != 100 {
		t.Fatalf("stats: %d stale, %d sent", s.Stale, s.Queue.N())
	}
}

// A bulk association with a full queue and a game's beside it on one
// connection: each gets its quantum a round, so the game's few packets go
// out among the first, not after the bulk's backlog.
func TestTheSchedulerGivesEachAssociationItsTurn(t *testing.T) {
	w := &wire{gate: make(chan struct{})}
	q := newTestQueue(t, w)
	bulk, game := testAssociation(q, 1), testAssociation(q, 2)
	for i := 0; i < 200; i++ {
		_, _ = bulk.WriteTo(make([]byte, 1100), testDest.UDPAddr())
	}
	for i := 0; i < 10; i++ {
		_, _ = game.WriteTo(make([]byte, 120), testDest.UDPAddr())
	}
	go func() {
		for i := 0; i < 210; i++ {
			w.gate <- struct{}{}
		}
	}()
	got := w.waitFor(t, 210)
	last := 0
	for i, m := range got {
		if m.sessionID == 2 {
			last = i
		}
	}
	// The first bulk send may already wait in the wire when the game puts;
	// after it the two take turns: the game's ten come in the first 22.
	if last > 21 {
		t.Fatalf("the game's last packet went %d-th of 210, behind the bulk", last+1)
	}
}

// A frame older than StaleAfter before the wire is dropped and counted; the
// fresh one behind it goes.
func TestTheSchedulerDropsAStaleFrame(t *testing.T) {
	w := &wire{gate: make(chan struct{})}
	q := newTestQueue(t, w)
	q.staleAfter = 50 * time.Millisecond
	c := testAssociation(q, 1)
	_, _ = c.WriteTo(make([]byte, 100), testDest.UDPAddr()) // held in the wire
	time.Sleep(10 * time.Millisecond)
	_, _ = c.WriteTo(make([]byte, 100), testDest.UDPAddr()) // grows old behind it
	time.Sleep(80 * time.Millisecond)
	_, _ = c.WriteTo(make([]byte, 100), testDest.UDPAddr())
	go func() {
		for i := 0; i < 3; i++ {
			w.gate <- struct{}{}
		}
	}()
	got := w.waitFor(t, 2)
	time.Sleep(20 * time.Millisecond)
	got = w.messages()
	if len(got) != 2 || got[0].packetID != 1 || got[1].packetID != 3 {
		t.Fatalf("sent %+v, want packets 1 and 3", got)
	}
	if s := c.TakeStats(); s.Stale != 1 || s.Queue.N() != 2 {
		t.Fatalf("stats: %d stale, %d sent; want 1 and 2", s.Stale, s.Queue.N())
	}
}

// A message larger than the connection's datagram goes in fragments, all of
// them back to back, and a stale one is dropped whole.
func TestTheSchedulerSendsAndDropsFragmentsWhole(t *testing.T) {
	w := &wire{gate: make(chan struct{})}
	q := newTestQueue(t, w)
	q.staleAfter = 50 * time.Millisecond
	big, small := testAssociation(q, 1), testAssociation(q, 2)
	_, _ = small.WriteTo(make([]byte, 100), testDest.UDPAddr()) // held in the wire
	time.Sleep(10 * time.Millisecond)
	_, _ = big.WriteTo(make([]byte, 3000), testDest.UDPAddr()) // grows old
	time.Sleep(80 * time.Millisecond)
	_, _ = big.WriteTo(make([]byte, 3000), testDest.UDPAddr())
	for i := 0; i < 3; i++ {
		_, _ = small.WriteTo(make([]byte, 100), testDest.UDPAddr())
	}
	close(w.gate)
	got := w.waitFor(t, 1+3+3)
	time.Sleep(20 * time.Millisecond)
	got = w.messages()
	var frags []udpMessage
	firstFrag, lastFrag := -1, -1
	for i, m := range got {
		if m.sessionID == 1 {
			frags = append(frags, m)
			if firstFrag < 0 {
				firstFrag = i
			}
			lastFrag = i
		}
	}
	if len(frags) != 3 || lastFrag-firstFrag != 2 {
		t.Fatalf("the big message went as %d datagrams at %d..%d of %d", len(frags), firstFrag, lastFrag, len(got))
	}
	for i, f := range frags {
		if f.packetID != 2 || f.fragmentTotal != 3 || int(f.fragmentID) != i {
			t.Fatalf("fragment %d: packet %d, %d of %d", i, f.packetID, f.fragmentID, f.fragmentTotal)
		}
	}
	if s := big.TakeStats(); s.Stale != 1 {
		t.Fatalf("the stale big message counted %d", s.Stale)
	}
}

// Over its memory an association loses its oldest frames, counted.
func TestTheSchedulerBoundsAnAssociationsMemory(t *testing.T) {
	w := &wire{gate: make(chan struct{})}
	q := newTestQueue(t, w)
	q.limit = 10 * (1000 + len(testDest.String()) + 8)
	c := testAssociation(q, 1)
	_, _ = c.WriteTo(make([]byte, 1000), testDest.UDPAddr()) // held in the wire
	time.Sleep(10 * time.Millisecond)
	for i := 0; i < 30; i++ {
		_, _ = c.WriteTo(make([]byte, 1000), testDest.UDPAddr())
	}
	close(w.gate)
	got := w.waitFor(t, 11)
	time.Sleep(20 * time.Millisecond)
	got = w.messages()
	// The first went to the wire before the rest came; ten newest are kept.
	if len(got) != 11 || got[0].packetID != 1 || got[1].packetID != 22 || got[10].packetID != 31 {
		t.Fatalf("sent %d datagrams, first %d, second %d", len(got), got[0].packetID, got[min(1, len(got)-1)].packetID)
	}
	if s := c.TakeStats(); s.Stale != 20 {
		t.Fatalf("%d counted stale, want 20", s.Stale)
	}
}

// A writer never waits for the wire.
func TestAWriteNeverWaits(t *testing.T) {
	w := &wire{gate: make(chan struct{})}
	defer close(w.gate)
	q := newTestQueue(t, w)
	c := testAssociation(q, 1)
	start := time.Now()
	for i := 0; i < 1000; i++ {
		if _, err := c.WriteTo(make([]byte, 1200), testDest.UDPAddr()); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("1000 writes took %v with the wire held", d)
	}
}

// A closed association's waiting frames never reach the wire.
func TestAClosedAssociationsFramesStay(t *testing.T) {
	w := &wire{gate: make(chan struct{})}
	q := newTestQueue(t, w)
	c, other := testAssociation(q, 1), testAssociation(q, 2)
	_, _ = other.WriteTo(make([]byte, 100), testDest.UDPAddr()) // held in the wire
	time.Sleep(10 * time.Millisecond)
	for i := 0; i < 5; i++ {
		_, _ = c.WriteTo(make([]byte, 100), testDest.UDPAddr())
	}
	_ = c.Close()
	close(w.gate)
	time.Sleep(50 * time.Millisecond)
	if got := w.messages(); len(got) != 1 {
		t.Fatalf("%d datagrams sent, want only the other association's", len(got))
	}
}

// A key's ceiling holds all its connections together to its rate; what is
// over it ages in the schedulers and is counted stale.
func TestAKeysCeilingHoldsItsConnections(t *testing.T) {
	ceiling := NewCeiling(8_000_000) // 1 MB/s
	var queues []*sendQueue
	var conns []*udpPacketConn
	wires := []*wire{{}, {}}
	for i, w := range wires {
		q := newTestQueue(t, w)
		q.staleAfter = 10 * time.Second
		q.ceiling.Store(ceiling)
		queues = append(queues, q)
		conns = append(conns, testAssociation(q, uint32(i+1)))
	}
	start := time.Now()
	for i := 0; i < 200; i++ { // 2 × 200 × about 1 KB: 0.4 s at the ceiling
		for _, c := range conns {
			_, _ = c.WriteTo(make([]byte, 1000), testDest.UDPAddr())
		}
	}
	for _, w := range wires {
		w.waitFor(t, 200)
	}
	if d := time.Since(start); d < 300*time.Millisecond || d > 2*time.Second {
		t.Fatalf("400 KB under a 1 MB/s ceiling took %v", d)
	}

	// At the live age limit a burst over the ceiling sends what fits in
	// StaleAfter at its rate (about 150 KB and the burst), the rest is stale.
	for _, q := range queues {
		q.staleAfter = StaleAfter
	}
	c := conns[0]
	_ = c.TakeStats()
	for i := 0; i < 200; i++ {
		_, _ = c.WriteTo(make([]byte, 1000), testDest.UDPAddr())
	}
	time.Sleep(500 * time.Millisecond)
	s := c.TakeStats()
	if s.Stale < 20 || s.Queue.N() > 180 || s.Queue.N()+s.Stale != 200 {
		t.Fatalf("a burst of 200 KB over 1 MB/s: %d stale, %d sent", s.Stale, s.Queue.N())
	}
}
