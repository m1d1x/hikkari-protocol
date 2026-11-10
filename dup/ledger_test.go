package dup

import (
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/observe"
)

func TestLedger(t *testing.T) {
	var l Ledger
	t0 := time.Unix(1000, 0)
	at := func(ms int) time.Time { return t0.Add(time.Duration(ms) * time.Millisecond) }
	steps := []struct {
		seq uint64
		via Via
		ms  int
		ok  bool
	}{
		{1, ViaDatagram, 0, true},
		{1, ViaStream, 30, false}, // both, the datagram 30 ms ahead
		{2, ViaStream, 40, true},  // the stream copy only: saved
		{3, ViaStream, 50, true},
		{3, ViaDatagram, 60, false}, // both, the stream 10 ms ahead
		{3, ViaDatagram, 61, false}, // a third copy changes nothing
		{4, ViaDatagram, 70, true},  // the datagram only
		{0, ViaDatagram, 70, false},
	}
	for _, s := range steps {
		if got := l.Accept(s.seq, s.via, at(s.ms)); got != s.ok {
			t.Fatalf("Accept(%d) = %v", s.seq, got)
		}
	}
	var d observe.Dup
	l.Take(&d)
	if d.Fresh != 4 || d.FirstDatagram != 2 || d.FirstStream != 2 || d.Both+d.OnlyStream+d.OnlyDatagram != 0 {
		t.Fatalf("before settling %+v", d)
	}
	if d.LeadDatagram.N() != 1 || d.LeadDatagram.Summary().Max != 30 || d.LeadStream.Summary().Max != 10 {
		t.Fatalf("leads %+v %+v", d.LeadDatagram.Summary(), d.LeadStream.Summary())
	}
	// 1 leaves the window: settled as both.
	l.Accept(1+WindowSize, ViaDatagram, at(80))
	// A copy older than the window is late, not fresh.
	if l.Accept(1, ViaStream, at(90)) {
		t.Fatal("a number older than the window accepted")
	}
	d = observe.Dup{}
	l.Take(&d)
	if d.Both != 1 || d.Late != 1 || d.Fresh != 1 {
		t.Fatalf("after 1 left %+v", d)
	}
	l.Close()
	d = observe.Dup{}
	l.Take(&d)
	// 2 stream only, 3 both, 4 and 1+WindowSize datagram only.
	if d.OnlyStream != 1 || d.Both != 1 || d.OnlyDatagram != 2 {
		t.Fatalf("closed %+v", d)
	}
	// A jump past the whole window settles everything and keeps the window
	// semantics of Window.
	var w Ledger
	w.Accept(5, ViaStream, t0)
	w.Accept(5+3*WindowSize, ViaDatagram, t0)
	d = observe.Dup{}
	w.Take(&d)
	if d.OnlyStream != 1 || w.Accept(5+2*WindowSize, ViaDatagram, t0) {
		t.Fatalf("jump %+v", d)
	}
}
