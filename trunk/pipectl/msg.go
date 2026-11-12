// Package pipectl is the brain's end of the entry's pipe (pipe-rs, hk-pipe):
// the Go entry decides (selector, the trunk's calls, knobs from the hub,
// minute lines) and the pipe carries every packet of the clients' UDP.
//
// One local SOCK_SEQPACKET socket between them, one message per datagram.
// The brain owns the sockets: it binds the client ports and the wires'
// members and passes them with the message that uses them by SCM_RIGHTS, so
// a reload can hand the same sockets to the next pipe. The pipe sends a tick
// a second (each wire's members up, debt, last proof, counters) and the
// answers to the brain's own flows (its calls on each wire); the brain sends
// the route. What the brain decides a second at a time never sits in the
// path of a packet.
//
// The messages are pipe-rs/src/ctl.rs; integers are little-endian, and both
// sides hold the same golden bytes in their tests.
package pipectl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

// Version is the socket's version; brain and pipe say it in their hellos.
const Version = 1

// Brain → pipe.
const (
	bHello  = 0x01 // ver u16
	bListen = 0x02 // id u8, class u8, to u16, copies u8; one socket
	bWire   = 0x03 // id u8, form u8, glue_us u32, glue_max u16, dead_ms u16, key [32]; a socket per member
	bUnwire = 0x04 // id u8
	bRoute  = 0x05 // voice u8, bulk u8
	bOpen   = 0x06 // tag u32, class u8, pin u8, port u16, copies u8
	bDgram  = 0x07 // tag u32, payload
	bClose  = 0x08 // tag u32
	bMember = 0x09 // wire u8, index u8; one socket
)

// Pipe → brain.
const (
	pHello  = 0x81 // ver u16, pid u32
	pTick   = 0x82
	pMember = 0x83 // wire u8, index u8, up u8, why u8
	pDgram  = 0x84 // tag u32, payload
	pError  = 0x85 // text
)

// FormUDP is the bare UDP wire (trunk/udpwire), the only form the pipe
// carries so far.
const FormUDP = 1

// noneMS is a duration the pipe has no value for.
const noneMS = ^uint32(0)

// Why a member went up or down.
const (
	WhyHello  = 1 // the exit answered its hello
	WhySilent = 2 // it owed an answer longer than its wire's Dead
	WhyGone   = 3 // its socket failed
)

func putWire(id trunk.WireID, form byte, glue time.Duration, glueMax int, dead time.Duration, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("pipectl: wire %d: key of %d bytes, want 32", id, len(key))
	}
	b := []byte{bWire, byte(id), form}
	b = binary.LittleEndian.AppendUint32(b, uint32(glue/time.Microsecond))
	b = binary.LittleEndian.AppendUint16(b, uint16(glueMax))
	b = binary.LittleEndian.AppendUint16(b, uint16(dead/time.Millisecond))
	return append(b, key...), nil
}

func putListen(id byte, class trunk.Class, to uint16, copies int) []byte {
	b := []byte{bListen, id, byte(class)}
	b = binary.LittleEndian.AppendUint16(b, to)
	return append(b, byte(copies))
}

func putRoute(r trunk.Route) []byte { return []byte{bRoute, byte(r.Voice), byte(r.Bulk)} }

func putOpen(tag uint32, o trunk.FlowOptions, port uint16) []byte {
	b := binary.LittleEndian.AppendUint32([]byte{bOpen}, tag)
	b = append(b, byte(o.Class), byte(o.Pin))
	b = binary.LittleEndian.AppendUint16(b, port)
	return append(b, byte(o.Copies))
}

func putTag(typ byte, tag uint32) []byte { return binary.LittleEndian.AppendUint32([]byte{typ}, tag) }

// Tick is the pipe's tick: itself, then each wire.
type Tick struct {
	// PauseAgo is how long ago the pipe came back from its latest pause (a
	// turn of its loop later than 100 ms past due); negative for none.
	PauseAgo time.Duration
	Pauses   int
	// LateMax is the latest turn of the loop past due in the last second.
	LateMax time.Duration
	Flows   int
	Wires   []WireTick
}

// WireTick is one wire in a tick.
type WireTick struct {
	ID      trunk.WireID
	Members int // members it has
	Up      int // members up
	// Owed is the least of its up members' debts (trunk.WireState.Owed).
	Owed time.Duration
	// ProofAgo is how long ago one of its members last heard the exit;
	// negative before the first.
	ProofAgo time.Duration
	RTT      time.Duration // the latest ping's round trip, least over its members; 0 unknown
	// Counters since the pipe started.
	UpPkts, UpBytes, DownPkts, DownBytes uint64
	Dgrams                               uint64 // sealed datagrams sent: UpPkts/Dgrams is the glue
	Dropped                              uint64
}

const (
	tickHead = 1 + 16 + 1
	tickWire = 3 + 12 + 48
)

var errTorn = errors.New("pipectl: a torn message from the pipe")

func ms(v uint32) time.Duration {
	if v == noneMS {
		return -1
	}
	return time.Duration(v) * time.Millisecond
}

func parseTick(m []byte) (Tick, error) {
	if len(m) < tickHead {
		return Tick{}, errTorn
	}
	le := binary.LittleEndian
	t := Tick{
		PauseAgo: ms(le.Uint32(m[1:])),
		Pauses:   int(le.Uint32(m[5:])),
		LateMax:  time.Duration(le.Uint32(m[9:])) * time.Microsecond,
		Flows:    int(le.Uint32(m[13:])),
	}
	n := int(m[17])
	if len(m) != tickHead+n*tickWire {
		return Tick{}, errTorn
	}
	for i := 0; i < n; i++ {
		b := m[tickHead+i*tickWire:]
		w := WireTick{ID: trunk.WireID(b[0]), Members: int(b[1]), Up: int(b[2]),
			Owed: time.Duration(le.Uint32(b[3:])) * time.Millisecond, ProofAgo: ms(le.Uint32(b[7:])),
			RTT: time.Duration(le.Uint32(b[11:])) * time.Microsecond}
		c := []*uint64{&w.UpPkts, &w.UpBytes, &w.DownPkts, &w.DownBytes, &w.Dgrams, &w.Dropped}
		for k, p := range c {
			*p = le.Uint64(b[15+8*k:])
		}
		t.Wires = append(t.Wires, w)
	}
	return t, nil
}
