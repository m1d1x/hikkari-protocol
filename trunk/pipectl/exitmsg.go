package pipectl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
	"github.com/m1d1x/hikkari-protocol/trunk/h3dgram"
	"github.com/m1d1x/hikkari-protocol/trunk/udpwire"
)

// The exit's pipe (rust/exit, hk-exit) under the brain: the same kind of
// socket as the entry's, its own messages (rust/exit/src/ctl.rs). The edge
// process keeps the brain (keys from the hub, the ports open to the trunk,
// observation, generations); the exit's pipe carries every packet of the
// entry's members and their streams.

// ExitVersion is the exit's socket's version.
const ExitVersion = 4

// Brain → exit.
const (
	xHello  = 0x01 // ver u16
	xWire   = 0x03 // id u8, form u8, glue_us u32, glue_max u16, dead_ms u16, quiet_ms u32, n u8, keys [32] × n; on FormH3Dgram then cert_len u16, cert path, key_len u16, key path; one socket
	xPorts  = 0x0a // n u16, port u16 × n
	xPool   = 0x0b // dead_ms u16, quiet_ms u32; one socket: the pool's listening TCP socket, or none (members come by xLink)
	xGen    = 0x0c // gen u8: the generation the exit's QUIC connection ids name, before any wire
	xDrain  = 0x0d // one socket: the old end of a handoff (HandoffLink)
	xAdopt  = 0x0e // one socket: the new end of a handoff
	xMark   = 0x0f // kind u8, session [16], stream u32, id u64: a tester's stream or flow
	xLink   = 0x10 // one socket: a stream member's connected socket, as if accepted on the pool's port
	xCopies = 0x11 // window_us u32: answers on a stream member that carried no stream wait this long (spec/trunk.md, "Copies on the pool"); 0: none
)

// Exit → brain.
const (
	xpHello    = 0x81 // ver u16, pid u32
	xpTick     = 0x82
	xpError    = 0x85 // text
	xpDrained  = 0x86 // an exit draining carries nothing more: no client's flow, no stream
	xpLocal    = 0x87 // open u8, kind u8, port u16, session [16], stream u32: a connection to the relay
	xpObserved = 0x88 // a report of a tester's stream or flow, as the entry pipe's pObserved (no client TCP)
)

// maxExitKeys is the most trunk keys one exit wire opens under.
const maxExitKeys = 16

type ExitPointTLS struct {
	CoreName    string
	AllowLegacy bool
	Points      []ExitPointCertificate
}

type ExitPointCertificate struct {
	BorderPoint
	CertFile, KeyFile string
}

func appendPointTLS(b []byte, tls *ExitPointTLS) ([]byte, error) {
	if !ValidPointSNI(tls.CoreName) || len(tls.Points) == 0 || len(tls.Points) > MaxPoints {
		return nil, errors.New("pipectl: invalid core name or point certificate count")
	}
	legacy := byte(0)
	if tls.AllowLegacy {
		legacy = 1
	}
	b = append(b, legacy, byte(len(tls.Points)), byte(len(tls.CoreName)))
	b = append(b, tls.CoreName...)
	ips, names := map[netip.Addr]bool{}, map[string]bool{tls.CoreName: true}
	for _, p := range tls.Points {
		if !p.IP.Is4() || !ValidPointSNI(p.SNI) || ips[p.IP] || names[p.SNI] {
			return nil, fmt.Errorf("pipectl: invalid or repeated point TLS identity %s %q", p.IP, p.SNI)
		}
		ips[p.IP], names[p.SNI] = true, true
		ip := p.IP.As4()
		b = append(b, ip[:]...)
		b = append(b, byte(len(p.SNI)))
		b = append(b, p.SNI...)
		for _, path := range []string{p.CertFile, p.KeyFile} {
			if path == "" || len(path) > 0xffff {
				return nil, errors.New("pipectl: point TLS certificate and key paths are required")
			}
			b = binary.LittleEndian.AppendUint16(b, uint16(len(path)))
			b = append(b, path...)
		}
	}
	return b, nil
}

// putExitWire is the wire message: for FormUDP each trunk key goes as
// udpwire.Key, for FormH3Dgram as h3dgram.Token, followed by the paths of
// the wire's certificate chain and key (PEM), which the exit reads.
func putExitWire(w ExitWire) ([]byte, error) {
	id, keys := w.ID, w.Keys
	if len(keys) == 0 || len(keys) > maxExitKeys {
		return nil, fmt.Errorf("pipectl: exit wire %d: %d trunk keys, want 1 to %d", id, len(keys), maxExitKeys)
	}
	derive := udpwire.Key
	switch w.Form {
	case FormUDP:
	case FormH3Dgram:
		derive = h3dgram.Token
		if w.CertFile == "" || w.KeyFile == "" || len(w.CertFile) > 0xffff || len(w.KeyFile) > 0xffff {
			return nil, fmt.Errorf("pipectl: exit wire %d: the QUIC wire needs its certificate's and key's files", id)
		}
	default:
		return nil, fmt.Errorf("pipectl: exit wire %d: form %d is not one the exit carries", id, w.Form)
	}
	le := binary.LittleEndian
	b := []byte{xWire, byte(id), w.Form}
	glue, glueMax, stall, quiet := w.Glue, w.GlueMax, w.Stall, w.Quiet
	b = le.AppendUint32(b, uint32(glue/time.Microsecond))
	b = le.AppendUint16(b, uint16(glueMax))
	b = le.AppendUint16(b, uint16(stall/time.Millisecond))
	b = le.AppendUint32(b, uint32(quiet/time.Millisecond))
	b = append(b, byte(len(keys)))
	for _, k := range keys {
		wk, err := derive(k)
		if err != nil {
			return nil, err
		}
		b = append(b, wk...)
	}
	if w.Form == FormH3Dgram {
		for _, f := range []string{w.CertFile, w.KeyFile} {
			b = le.AppendUint16(b, uint16(len(f)))
			b = append(b, f...)
		}
		if w.PointTLS != nil {
			return appendPointTLS(b, w.PointTLS)
		}
	}
	return b, nil
}

func putExitPool(stall, quiet time.Duration) []byte {
	b := binary.LittleEndian.AppendUint16([]byte{xPool}, uint16(stall/time.Millisecond))
	return binary.LittleEndian.AppendUint32(b, uint32(quiet/time.Millisecond))
}

func putExitCopies(window time.Duration) []byte {
	return binary.LittleEndian.AppendUint32([]byte{xCopies}, uint32(window/time.Microsecond))
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

// ExitLocal is a connection of the exit to its relay, opened or closed: the
// relay sees its local port as its peer's, and the brain knows by it which
// stream or flow of which session a connection is (the Go exit's
// trunkTargets, edge trunk_observe.go).
type ExitLocal struct {
	Open    bool
	Kind    trunk.ObsKind
	Port    uint16
	Session trunk.SessionID
	Stream  uint32
}

const exitLocalLen = 25

func parseExitLocal(m []byte) (ExitLocal, error) {
	if len(m) != exitLocalLen || m[0] != xpLocal || m[1] > 1 {
		return ExitLocal{}, fmt.Errorf("pipectl: the exit's local of %d bytes", len(m))
	}
	l := ExitLocal{Open: m[1] == 1, Kind: trunk.ObsKind(m[2]), Port: binary.LittleEndian.Uint16(m[3:]),
		Stream: binary.LittleEndian.Uint32(m[21:])}
	copy(l.Session[:], m[5:21])
	return l, nil
}

func putExitMark(kind trunk.ObsKind, session trunk.SessionID, stream uint32, id uint64) []byte {
	b := append([]byte{xMark, byte(kind)}, session[:]...)
	b = binary.LittleEndian.AppendUint32(b, stream)
	return binary.LittleEndian.AppendUint64(b, id)
}
