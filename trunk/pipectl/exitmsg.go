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
// entry's packet members.

// ExitVersion is the exit's socket's version.
const ExitVersion = 1

// Brain → exit.
const (
	xHello = 0x01 // ver u16
	xWire  = 0x03 // id u8, form u8, glue_us u32, glue_max u16, dead_ms u16, quiet_ms u32, n u8, keys [32] × n; one socket
	xPorts = 0x0a // n u16, port u16 × n
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
	Members  int // up: hello answered, not dead
	Flows    int // the clients' flows open
	// Joined, Silent (buried by their stall while another member proved the
	// entry alive), Quiet (every member silent past Quiet), Gone (an address
	// silent past udpwire.PeerIdle). Silent + Quiet is trunk Stats.MembersStall.
	Joined, Silent, Quiet, Gone uint64
	// The clients' datagrams, as trunk Stats: sent to the entry, delivered
	// to the relay, copies dropped; flows ended unused; datagrams to a port
	// not open or refused by the relay.
	DgramsOut, DgramsIn, DgramsCopy, FlowsIdle, Refused uint64
	// Sealed datagrams opened from the entry and sealed to it, the frames
	// in those (FramesOut / WOut is the glue down), datagrams that opened
	// under no key, sealed datagrams the socket refused.
	WIn, WOut, FramesOut, Bad, Dropped uint64
}

const exitTickLen = 1 + 6*4 + 14*8

func parseExitTick(m []byte) (ExitTick, error) {
	if len(m) != exitTickLen {
		return ExitTick{}, errTorn
	}
	le := binary.LittleEndian
	u := func(i int) uint32 { return le.Uint32(m[1+4*i:]) }
	t := ExitTick{PauseAgo: ms(u(0)), Pauses: int(u(1)), LateMax: time.Duration(u(2)) * time.Microsecond,
		Sessions: int(u(3)), Members: int(u(4)), Flows: int(u(5))}
	c := []*uint64{&t.Joined, &t.Silent, &t.Quiet, &t.Gone, &t.DgramsOut, &t.DgramsIn, &t.DgramsCopy, &t.FlowsIdle,
		&t.Refused, &t.WIn, &t.WOut, &t.FramesOut, &t.Bad, &t.Dropped}
	for k, p := range c {
		*p = le.Uint64(m[25+8*k:])
	}
	return t, nil
}
