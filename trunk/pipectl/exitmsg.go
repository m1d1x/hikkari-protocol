package pipectl

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
	"github.com/m1d1x/hikkari-protocol/trunk/udpwire"
)

// The exit's pipe (rust/exit, hk-exit) under the brain: the same kind of
// socket as the entry's, its own messages (rust/exit/src/ctl.rs). The edge
// process keeps the brain (keys from the hub, the ports open to the trunk,
// observation, generations); the exit's pipe carries every packet of the
// entry's members and their streams.

// ExitVersion is the exit's socket's version.
const ExitVersion = 2

// Brain → exit.
const (
	xHello = 0x01 // ver u16
	xWire  = 0x03 // id u8, form u8, glue_us u32, glue_max u16, dead_ms u16, quiet_ms u32, n u8, keys [32] × n; one socket
	xPorts = 0x0a // n u16, port u16 × n
	xPool  = 0x0b // dead_ms u16, quiet_ms u32; one socket: the pool's listening TCP socket
)

// Exit → brain.
const (
	xpHello = 0x81 // ver u16, pid u32
	xpTick  = 0x82
	xpError = 0x85 // text
)

// maxExitKeys is the most trunk keys one exit wire opens under.
const maxExitKeys = 16

func putExitWire(id trunk.WireID, glue time.Duration, glueMax int, stall, quiet time.Duration, keys []string) ([]byte, error) {
	if len(keys) == 0 || len(keys) > maxExitKeys {
		return nil, fmt.Errorf("pipectl: exit wire %d: %d trunk keys, want 1 to %d", id, len(keys), maxExitKeys)
	}
	le := binary.LittleEndian
	b := []byte{xWire, byte(id), FormUDP}
	b = le.AppendUint32(b, uint32(glue/time.Microsecond))
	b = le.AppendUint16(b, uint16(glueMax))
	b = le.AppendUint16(b, uint16(stall/time.Millisecond))
	b = le.AppendUint32(b, uint32(quiet/time.Millisecond))
	b = append(b, byte(len(keys)))
	for _, k := range keys {
		wk, err := udpwire.Key(k)
		if err != nil {
			return nil, err
		}
		b = append(b, wk...)
	}
	return b, nil
}

func putExitPool(stall, quiet time.Duration) []byte {
	b := binary.LittleEndian.AppendUint16([]byte{xPool}, uint16(stall/time.Millisecond))
	return binary.LittleEndian.AppendUint32(b, uint32(quiet/time.Millisecond))
}

func putExitPorts(ports []uint16) []byte {
	b := binary.LittleEndian.AppendUint16([]byte{xPorts}, uint16(len(ports)))
	for _, p := range ports {
		b = binary.LittleEndian.AppendUint16(b, p)
	}
	return b
}

// ExitTick is the exit's tick: itself now, then its counters since it
// started, as trunk Exit.Stats sums them.
type ExitTick struct {
	// PauseAgo is how long ago the exit came back from its latest pause of
	// its own; negative for none.
	PauseAgo time.Duration
	Pauses   int
	LateMax  time.Duration
	Sessions int
	Members  int // packet members up: hello answered, not dead
	Flows    int // the clients' flows open
	Links    int // stream members up
	Streams  int // streams open
	// Members of either kind: Joined, Silent (buried by their stall while
	// another member proved the entry alive), Quiet (every member silent
	// past Quiet), Gone (a packet member's address silent past
	// udpwire.PeerIdle, a stream member's connection failed or ended).
	// Silent + Quiet is trunk Stats.MembersStall.
	Joined, Silent, Quiet, Gone uint64
	// The clients' datagrams, as trunk Stats: sent to the entry, delivered
	// to the relay, copies dropped; flows ended unused; datagrams to a port
	// not open or refused by the relay.
	DgramsOut, DgramsIn, DgramsCopy, FlowsIdle, Refused uint64
	// Sealed datagrams opened from the entry and sealed to it, the frames
	// in those (FramesOut / WOut is the glue down), datagrams that opened
	// under no key, sealed datagrams the socket refused.
	WIn, WOut, FramesOut, Bad, Dropped uint64
	// Streams, as trunk Stats: opened, ended by both FINs, reset by the
	// entry and here (StreamsReset is the two), times a member died carrying
	// a stream's unconfirmed chunks, chunks sent again (Resent), bytes read
	// from local ends and written to them (Up, Down).
	StreamsOpened, StreamsFin, ResetPeer, ResetLocal, Hit, Resent, Up, Down uint64
	// Chunks and FINs held for streams not open yet and dropped past the
	// bounds, opens refused (a port not open, a relay that refused),
	// datagrams that came on stream members (dropped: R2 carries them).
	Early, EarlyDropped, RefusedStreams, LinkDgrams uint64
}

const (
	exitTickHeads    = 8
	exitTickCounters = 26
	exitTickLen      = 1 + exitTickHeads*4 + exitTickCounters*8
)

func parseExitTick(m []byte) (ExitTick, error) {
	if len(m) != exitTickLen {
		return ExitTick{}, errTorn
	}
	le := binary.LittleEndian
	u := func(i int) uint32 { return le.Uint32(m[1+4*i:]) }
	t := ExitTick{PauseAgo: ms(u(0)), Pauses: int(u(1)), LateMax: time.Duration(u(2)) * time.Microsecond,
		Sessions: int(u(3)), Members: int(u(4)), Flows: int(u(5)), Links: int(u(6)), Streams: int(u(7))}
	c := []*uint64{&t.Joined, &t.Silent, &t.Quiet, &t.Gone, &t.DgramsOut, &t.DgramsIn, &t.DgramsCopy, &t.FlowsIdle,
		&t.Refused, &t.WIn, &t.WOut, &t.FramesOut, &t.Bad, &t.Dropped,
		&t.StreamsOpened, &t.StreamsFin, &t.ResetPeer, &t.ResetLocal, &t.Hit, &t.Resent, &t.Up, &t.Down,
		&t.Early, &t.EarlyDropped, &t.RefusedStreams, &t.LinkDgrams}
	at := 1 + exitTickHeads*4
	for k, p := range c {
		*p = le.Uint64(m[at+8*k:])
	}
	return t, nil
}
