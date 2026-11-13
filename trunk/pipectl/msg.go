// Package pipectl is the brain's end of the entry's pipe (rust/pipe, hk-pipe):
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
// The messages are rust/pipe/src/ctl.rs; integers are little-endian, and both
// sides hold the same golden bytes in their tests.
package pipectl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

// Version is the socket's version; brain and pipe say it in their hellos.
const Version = 5

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
	bDrain  = 0x0a // one socket: the old end of a handoff
	bAdopt  = 0x0b // one socket: the new end of a handoff
	// tcp_listen and pool: the streams' part (rust/pipe/src/pipe/pool.rs).
	bTCPListen = 0x0c // id u8, to u16; one socket: a listening TCP socket
	bPool      = 0x0d // id u8, form u8, members u8, dead_ms u16, lo u16, hi u16, exit ip [4] port u16; Chromium: sni u8+n, key u8+n, cronet u16+n, roots
)

// A pool's forms: stream members over plain TCP to the exit's member port,
// or Chromium's CONNECT to the exit's relay (trunk/chromium).
const (
	poolPlain    = 1
	poolChromium = 2
)

// Pipe → brain.
const (
	pHello   = 0x81 // ver u16, pid u32
	pTick    = 0x82
	pMember  = 0x83 // wire u8, index u8, up u8, why u8
	pDgram   = 0x84 // tag u32, payload
	pError   = 0x85 // text
	pDrained = 0x86 // a pipe draining carries nothing more
)

// FormUDP is the bare UDP wire (trunk/udpwire), the only form the pipe
// carries so far.
const FormUDP = 1

// noneMS is a duration the pipe has no value for.
const noneMS = ^uint32(0)

// Why a member went up or down.
const (
	WhyHello  = 1 // the exit answered its hello
	WhySilent = 2 // it owed an answer past its wire's Stall while another member proved the exit alive
	WhyGone   = 3 // its socket failed
	WhyQuiet  = 4 // every member silent at once past Quiet (1 s): the exit paused or the whole path cut
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

// Pool is a wire of stream members the pipe dials itself, as the Go
// entry's pool (trunk.Entry): Members connections from source ports of
// Ports (lo, hi), each a member of the session, judged by Stall.
type Pool struct {
	ID      trunk.WireID
	Members int
	Stall   time.Duration
	Ports   [2]uint16
	// Exit is the exit's member port (plain TCP), or its relay for
	// Chromium's form.
	Exit netip.AddrPort
	// Chromium, when set, is the pool's form: Chromium's CONNECT to the
	// relay (trunk/chromium); nil is plain TCP (tests, the bench).
	Chromium *ChromiumForm
}

// ChromiumForm is what a Chromium member's CONNECT needs: the relay's
// domain (its certificate is checked against it), the trunk key the relay
// admits, libcronet's path ("": found as the Go entry finds it) and PEM
// roots that replace the system's ("": the system's).
type ChromiumForm struct {
	SNI, Key, Cronet, Roots string
}

func putTCPListen(id byte, to uint16) []byte {
	return binary.LittleEndian.AppendUint16([]byte{bTCPListen, id}, to)
}

func putPool(w Pool) ([]byte, error) {
	if w.Members < 1 || w.Members > 255 {
		return nil, fmt.Errorf("pipectl: pool %d: %d members, want 1-255", w.ID, w.Members)
	}
	if !w.Exit.Addr().Is4() {
		return nil, fmt.Errorf("pipectl: pool %d: exit %v is not IPv4", w.ID, w.Exit)
	}
	form := byte(poolPlain)
	if w.Chromium != nil {
		form = poolChromium
	}
	b := []byte{bPool, byte(w.ID), form, byte(w.Members)}
	b = binary.LittleEndian.AppendUint16(b, uint16(w.Stall/time.Millisecond))
	b = binary.LittleEndian.AppendUint16(b, w.Ports[0])
	b = binary.LittleEndian.AppendUint16(b, w.Ports[1])
	ip := w.Exit.Addr().As4()
	b = append(b, ip[:]...)
	b = binary.LittleEndian.AppendUint16(b, w.Exit.Port())
	if c := w.Chromium; c != nil {
		if len(c.SNI) > 255 || len(c.Key) > 255 || len(c.Cronet) > 65535 {
			return nil, fmt.Errorf("pipectl: pool %d: a domain, key or path too long", w.ID)
		}
		b = append(append(b, byte(len(c.SNI))), c.SNI...)
		b = append(append(b, byte(len(c.Key))), c.Key...)
		b = append(binary.LittleEndian.AppendUint16(b, uint16(len(c.Cronet))), c.Cronet...)
		b = append(b, c.Roots...)
	}
	return b, nil
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
	// turn of its loop more than 100 ms after the one before); negative for none.
	PauseAgo time.Duration
	Pauses   int
	// LateMax is the latest turn of the loop past due in the last second.
	LateMax time.Duration
	// Flows is the clients' flows open, the trunk's own calls left out (as
	// trunk Stats.Flows).
	Flows int
	// Since the pipe started, the trunk's own calls left out, as trunk
	// Stats counts them: datagrams read from clients and the brain's flows,
	// delivered, and copies dropped as already seen.
	DgramsOut, DgramsIn, DgramsCopy uint64
	// FlowsIdle is the clients' flows ended unused (trunk's FlowIdle).
	FlowsIdle uint64
	// Retired is the sessions retired for the exit's drain that still carry
	// something (trunk Entry.Retired), Coming whether a new one is coming
	// up (spec/trunk.md, Drain).
	Retired int
	Coming  bool
	// Streams is the clients' streams open, every session's (trunk
	// Stats.Streams).
	Streams int
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
	tickHead = 1 + 16 + 32 + 2 + 4 + 1
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
	for k, p := range []*uint64{&t.DgramsOut, &t.DgramsIn, &t.DgramsCopy, &t.FlowsIdle} {
		*p = le.Uint64(m[17+8*k:])
	}
	t.Retired, t.Coming = int(m[49]), m[50] == 1
	t.Streams = int(le.Uint32(m[51:]))
	n := int(m[tickHead-1])
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
