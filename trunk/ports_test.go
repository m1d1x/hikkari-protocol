package trunk

import (
	"errors"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time      { return c.t }
func (c *fakeClock) add(d time.Duration) { c.t = c.t.Add(d) }
func bookAt(t *testing.T, c *fakeClock) *PortBook {
	t.Helper()
	b, err := NewPortBook(20000, 20256, time.Hour) // 257 ports
	if err != nil {
		t.Fatal(err)
	}
	b.now = c.now
	return b
}

// A book with every port dead or in use answers at once with ErrNoPorts:
// before 12.11 Take spun on random ports for ever and the entry stood still.
func TestAFullBookSaysSoAndDoesNotHang(t *testing.T) {
	c := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	b := bookAt(t, c)
	var held []func()
	for p := 20000; p <= 20256; p += 2 {
		b.Dead(p)
	}
	for p := 20001; p <= 20256; p += 2 {
		port, release, err := b.Take()
		if err != nil {
			t.Fatalf("take %d: %v", p, err)
		}
		if port%2 == 0 {
			t.Fatalf("took dead port %d", port)
		}
		held = append(held, release)
	}
	done := make(chan error, 1)
	go func() { _, _, err := b.Take(); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNoPorts) {
			t.Fatalf("full book: %v, want ErrNoPorts", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Take on a full book did not return")
	}
	held[0]()
	held[0]() // twice is once
	if port, _, err := b.Take(); err != nil || port%2 == 0 {
		t.Fatalf("after one release: %d %v", port, err)
	}
	if _, _, err := b.Take(); !errors.Is(err, ErrNoPorts) {
		t.Fatalf("double release freed two ports: %v", err)
	}
}

// Dead ports come back DeadFor after their last kill, in the order they
// died; a port killed while in use stays out after its release.
func TestDeadPortsComeBackOnTime(t *testing.T) {
	c := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	b := bookAt(t, c)
	port, release, err := b.Take()
	if err != nil {
		t.Fatal(err)
	}
	b.Dead(port) // killed under a member
	release()
	other := 20000
	if other == port {
		other = 20001
	}
	b.Dead(other)
	c.add(30 * time.Minute)
	b.Dead(other) // again: its hour starts over
	if dead, kills := b.Counts(); dead != 2 || kills != 3 {
		t.Fatalf("dead=%d kills=%d, want 2 3", dead, kills)
	}
	free := func() map[int]bool {
		m := map[int]bool{}
		for _, p := range b.free {
			m[int(p)] = true
		}
		return m
	}
	c.add(30*time.Minute + time.Second)
	if dead, _ := b.Counts(); dead != 1 || !free()[port] || free()[other] {
		t.Fatalf("after 1 h: dead=%d, %d back %v, %d back %v", dead, port, free()[port], other, free()[other])
	}
	c.add(30 * time.Minute)
	if dead, _ := b.Counts(); dead != 0 || !free()[other] || len(b.free) != 257 {
		t.Fatalf("after 1.5 h: dead=%d free=%d", dead, len(b.free))
	}
	// A port dead past its hour while still in use goes back on release.
	port, release, _ = b.Take()
	b.Dead(port)
	c.add(2 * time.Hour)
	b.Counts()
	if free()[port] {
		t.Fatal("a port in use came back as free")
	}
	release()
	if !free()[port] {
		t.Fatal("an expired port in use did not come back on release")
	}
}

// Take costs the same with the book nearly full as empty: no walk over the
// dead, no tries at random ports.
func TestTakeIsConstantTime(t *testing.T) {
	empty := testing.Benchmark(func(b *testing.B) { benchFull(b, 0) })
	full := testing.Benchmark(func(b *testing.B) { benchFull(b, 11457) })
	e, f := empty.NsPerOp(), full.NsPerOp()
	t.Logf("take+release: empty %d ns, 11457 of 12768 dead %d ns", e, f)
	if f > 4*e+200 {
		t.Fatalf("full book %d ns against empty %d ns", f, e)
	}
}

// The queue does not grow with kills that came back long ago.
func TestTheQueueHoldsOnlyTheLastHour(t *testing.T) {
	c := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	b := bookAt(t, c)
	for i := 0; i < 100_000; i++ {
		b.Dead(20000 + i%257)
		c.add(time.Second)
	}
	if n := len(b.queue) - b.head; n > 3600+1 {
		t.Fatalf("queue holds %d live entries, want about 3600", n)
	}
	if cap(b.queue) > 3*3600+2048 {
		t.Fatalf("queue cap %d after 100000 kills", cap(b.queue))
	}
}
