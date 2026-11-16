package trunk

import (
	"encoding/binary"
	"time"
)

// The exit's part of the trunk's call (spec/trunk.md, "Datagrams"):
// before the echo sends a call's datagram back, it writes into it when the
// datagram reached it, by its wall clock, and which of the call's last 64
// frames it has had on this flow. The entry then hears each direction apart:
// up by the exit's stamp and map, down by its own receipt (hearing.go).
//
// A call's datagram starts with its frame number (8 bytes, big endian), then
// 8 bytes of the exit's stamp and 8 of its map, sent as zeros. An exit older
// than this sends them back as zeros: the entry hears no direction then.

const (
	// callStampAt and callMapAt are where the exit writes in a call's
	// datagram; callStamped is how long a datagram must be to take both.
	callStampAt = 8
	callMapAt   = 16
	callStamped = 24
)

// echoMap is which of a flow's last 64 frame numbers the exit has had: bit i
// of bits is top-i.
type echoMap struct {
	top  uint64
	bits uint64
}

// note marks frame n had and gives the map as of n: bit i is n-i. A frame
// older than the map by 64 or more is had alone.
func (m *echoMap) note(n uint64) uint64 {
	if n > m.top {
		if d := n - m.top; d >= 64 {
			m.bits = 0
		} else {
			m.bits <<= d
		}
		m.top = n
		m.bits |= 1
		return m.bits
	}
	d := m.top - n
	if d >= 64 {
		return 1
	}
	m.bits |= 1 << d
	return m.bits >> d
}

// stamp writes the exit's part into a call's datagram p in place (the exit's
// echo, flows.go dgramLocked). A datagram too short to take it, or whose
// stamp and map are not zeros (another user of the echo: a bench, a tool),
// goes back as it came.
func (m *echoMap) stamp(p []byte, now time.Time) {
	if len(p) < callStamped || binary.BigEndian.Uint64(p[callStampAt:]) != 0 || binary.BigEndian.Uint64(p[callMapAt:]) != 0 {
		return
	}
	bits := m.note(binary.BigEndian.Uint64(p))
	binary.BigEndian.PutUint64(p[callStampAt:], uint64(now.UnixNano()))
	binary.BigEndian.PutUint64(p[callMapAt:], bits)
}
