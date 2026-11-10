package dup

import (
	"time"

	"github.com/m1d1x/hikkari-protocol/observe"
)

// Via is the channel a copy came by.
type Via uint8

const (
	ViaDatagram Via = 1
	ViaStream   Via = 2
)

// Ledger is a Window that also remembers, per number in the window, which
// channels brought a copy and when the first one came (v1.04). When a number
// leaves the window it is settled: brought by the datagram channel only, by
// the stream channel only (the stream copy saved it) or by both. Not safe for
// concurrent use.
type Ledger struct {
	top   uint64
	seq   [WindowSize]uint64
	via   [WindowSize]Via
	first [WindowSize]int64 // unix ns of the first copy
	n     observe.Dup
}

// Accept reports whether seq is new and counts the copy that came by via at
// now.
func (l *Ledger) Accept(seq uint64, via Via, now time.Time) bool {
	if seq == 0 {
		return false
	}
	at := now.UnixNano()
	if seq > l.top {
		from := l.top + 1
		if seq-l.top > WindowSize {
			from = seq - WindowSize + 1
			l.settleAll()
		}
		for i := from; i <= seq; i++ {
			l.settle(i % WindowSize)
		}
		l.top = seq
		l.put(seq, via, at)
		return true
	}
	if l.top-seq >= WindowSize {
		l.n.Late++
		return false
	}
	slot := seq % WindowSize
	if l.seq[slot] != seq {
		l.put(seq, via, at)
		return true
	}
	if l.via[slot]&via == 0 {
		lead := observe.Ms(time.Duration(at - l.first[slot]))
		if l.via[slot] == ViaStream {
			l.n.LeadStream.Add(lead)
		} else {
			l.n.LeadDatagram.Add(lead)
		}
		l.via[slot] |= via
	}
	return false
}

func (l *Ledger) put(seq uint64, via Via, at int64) {
	slot := seq % WindowSize
	l.seq[slot], l.via[slot], l.first[slot] = seq, via, at
	l.n.Fresh++
	if via == ViaStream {
		l.n.FirstStream++
	} else {
		l.n.FirstDatagram++
	}
}

func (l *Ledger) settle(slot uint64) {
	if l.seq[slot] == 0 {
		return
	}
	switch l.via[slot] {
	case ViaDatagram:
		l.n.OnlyDatagram++
	case ViaStream:
		l.n.OnlyStream++
	default:
		l.n.Both++
	}
	l.seq[slot], l.via[slot] = 0, 0
}

func (l *Ledger) settleAll() {
	for i := range l.seq {
		l.settle(uint64(i))
	}
}

// Take adds what the ledger counted since the last Take to d. At the end of a
// session, close it first, so every number is settled.
func (l *Ledger) Take(d *observe.Dup) {
	n := l.n
	l.n = observe.Dup{}
	d.Fresh += n.Fresh
	d.FirstDatagram += n.FirstDatagram
	d.FirstStream += n.FirstStream
	d.OnlyDatagram += n.OnlyDatagram
	d.OnlyStream += n.OnlyStream
	d.Both += n.Both
	d.Late += n.Late
	d.LeadDatagram.Merge(&n.LeadDatagram)
	d.LeadStream.Merge(&n.LeadStream)
}

// Close settles every number still in the window.
func (l *Ledger) Close() { l.settleAll() }
