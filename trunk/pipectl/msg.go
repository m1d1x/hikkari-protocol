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
	"slices"
	"strings"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

// Version is the socket's version; brain and pipe say it in their hellos.
const Version = 12

// Brain → pipe.
const (
	bHello  = 0x01 // ver u16
	bListen = 0x02 // id u8, class u8, to u16, copies u8; one socket
	bWire   = 0x03 // id u8, form u8, glue_us u32, glue_max u16, dead_ms u16, key [32]; FormUDP: a socket per member; FormH3Dgram: see putH3
	bUnwire = 0x04 // id u8
	bRoute  = 0x05 // voice u8, bulk u8, video u8, n u8 + n × (wire u8, copies u8, after_ms u16), m u8 + m × (wire u8, fate u8): putRoute
	bOpen   = 0x06 // tag u32, class u8, pin u8, port u16, copies u8
	bDgram  = 0x07 // tag u32, payload
	bClose  = 0x08 // tag u32
	bMember = 0x09 // wire u8, index u8; one socket
	bDrain  = 0x0a // one socket: the old end of a handoff
	bAdopt  = 0x0b // one socket: the new end of a handoff
	// tcp_listen and pool: the streams' part (rust/pipe/src/pipe/pool.rs).
	bTCPListen = 0x0c // id u8, to u16; one socket: a listening TCP socket
	bCopies    = 0x10 // members u8, window_us u32: the pool's members of copies and their window; 0 members: none
	bPool      = 0x0d // id u8, form u8, members u8, dead_ms u16, lo u16, hi u16, exit ip [4] port u16; Chromium: sni u8+n, key u8+n, cronet u16+n, roots
	bClients   = 0x0e // the leg client → entry of the minute, now (answered by pClients)
	bStats     = 0x0f // the counters of the minute line, now (answered by pStats)
	// receiver and active: the receivers (rust/pipe/src/pipe/session.rs).
	bReceiver = 0x11 // rx u8, ip [4], pool_members u8: a receiver on standby at ip on the active one's ports (0.0.0.0: taken away)
	bActive   = 0x12 // rx u8: the receiver that carries everything from now
	// demand: the voice class's copies on the pool on demand
	// (rust/trunk/src/demand.rs, spec/trunk.md "Copies on demand").
	bDemand = 0x13 // hold_ms u32: held this long after a loss; 0: copies always
	// points: the active receiver's border points (spec/trunk.md "Border
	// points", rust/pipe/src/pipe/points.rs).
	bPoints      = 0x14 // n u8 + n × ip [4]: member i of every wire to point i mod n; n 0: none
	bNamedPoints = 0x15 // n u8 + n × (ip [4], name length u8, name bytes)
	// stream window: the window the pipe gives every stream it receives
	// from now (rust/trunk/src/stream.rs Recv::with_window).
	bStreamWindow = 0x16 // kib u32
)

// A pool's forms: stream members over plain TCP to the exit's member port,
// or Chromium's CONNECT to the exit's relay (trunk/chromium).
const (
	poolPlain    = 1
	poolChromium = 2
)

// Pipe → brain.
const (
	pHello     = 0x81 // ver u16, pid u32
	pTick      = 0x82
	pMember    = 0x83 // wire u8, index u8, up u8, why u8
	pDgram     = 0x84 // tag u32, payload
	pError     = 0x85 // text
	pDrained   = 0x86 // a pipe draining carries nothing more
	pStats     = 0x89 // see parseStats
	pObserved  = 0x88 // a report of a tester's stream or flow: see parseObserved
	pClients   = 0x87 // conns u32, closed u32, sending u32, segs u64, retrans u64, rtt_p50_us u32, rtt_p90_us u32 (noneMS: none)
	pPoints    = 0x8b // n u8 + n × (ip [4], members u8, up u8, proof_ago_ms u32): see parsePoints
	pReceivers = 0x8a // active u8, n u8 + n × (rx u8, ip [4], k u8 + k × (wire u8, members u8, up u8, proof_ago_ms u32)): see parseReceivers
)

// FormUDP is the bare UDP wire (trunk/udpwire): the brain dials its members.
const FormUDP = 1

// FormH3Dgram is the Chromium QUIC wire (spec/trunk.md, h3dgram, trunk/h3dgram):
// the exit's pipe serves it since R6.2, the entry's since R6.3, whose members
// are CONNECT-UDP tunnels the pipe opens itself (rust/pipe/src/pipe/h3.rs).
const FormH3Dgram = 2

// How a QUIC wire's member uses its session (H3Form.Usage).
const (
	usageDestination = 0
	usageProxy       = 1
)

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

// H3Form is what the QUIC wire's members are opened with: the exit's domain
// (its certificate is checked against it), libcronet's path ("": found as
// the Go entry finds it), PEM roots that replace the system's ("": the
// system's), how the members use their QUIC sessions (Usage: "destination",
// Chrome's to a site, the default by the owner's choice of 2026-11-14, or
// "proxy") and the book of their source ports (Ports: lo, hi; the pipe's
// 20000-32767 when zero). A wire given another form comes up anew.
type H3Form struct {
	SNI, Cronet, Roots string
	Usage              string
	Ports              [2]uint16
}

// putH3 is a QUIC wire's B_WIRE: the head as putWire's with the wire's
// token for its key, then members u8, usage u8, lo u16, hi u16, exit ip [4]
// port u16, sni u8+n, cronet u16+n, roots (rest).
func putH3(id trunk.WireID, glue time.Duration, glueMax int, dead time.Duration, token []byte, members int, exit netip.AddrPort, f H3Form) ([]byte, error) {
	if members < 1 || members > 255 {
		return nil, fmt.Errorf("pipectl: wire %d: %d members, want 1-255", id, members)
	}
	if !exit.Addr().Is4() {
		return nil, fmt.Errorf("pipectl: wire %d: exit %v is not IPv4", id, exit)
	}
	var usage byte
	switch f.Usage {
	case "", "destination":
		usage = usageDestination
	case "proxy":
		usage = usageProxy
	default:
		return nil, fmt.Errorf("pipectl: wire %d: session usage %q is not destination or proxy", id, f.Usage)
	}
	if len(f.SNI) > 255 || len(f.Cronet) > 65535 {
		return nil, fmt.Errorf("pipectl: wire %d: a domain or path too long", id)
	}
	b, err := putWire(id, FormH3Dgram, glue, glueMax, dead, token)
	if err != nil {
		return nil, err
	}
	b = append(b, byte(members), usage)
	b = binary.LittleEndian.AppendUint16(b, f.Ports[0])
	b = binary.LittleEndian.AppendUint16(b, f.Ports[1])
	ip := exit.Addr().As4()
	b = append(b, ip[:]...)
	b = binary.LittleEndian.AppendUint16(b, exit.Port())
	b = append(append(b, byte(len(f.SNI))), f.SNI...)
	b = append(binary.LittleEndian.AppendUint16(b, uint16(len(f.Cronet))), f.Cronet...)
	return append(b, f.Roots...), nil
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
	// Fate is what must break on the path for the pool to lose a frame
	// (trunk Wire.Fate); empty is tcp, as for any pool.
	Fate trunk.Fate
}

// ChromiumForm is what a Chromium member's CONNECT needs: the relay's
// domain (its certificate is checked against it), the trunk key the relay
// admits, libcronet's path ("": found as the Go entry finds it) and PEM
// roots that replace the system's ("": the system's).
type ChromiumForm struct {
	SNI, Key, Cronet, Roots string
}

// Copies is the pool's members of copies (rust/pipe/src/copies.rs,
// spec/trunk.md "Copies on the pool"): Members of the pool carry datagrams'
// copies and no client's stream, the copies of each Window held on one of
// them and written at once. Members 0 is the pool as before: copies go
// round every member, each written at once.
type Copies struct {
	Members int
	Window  time.Duration
}

func putCopies(c Copies) ([]byte, error) {
	if c.Members < 0 || c.Members > 255 || c.Window < 0 || c.Window > time.Second {
		return nil, fmt.Errorf("pipectl: copies: %d members, window %v; want 0-255 and at most 1s", c.Members, c.Window)
	}
	return binary.LittleEndian.AppendUint32([]byte{bCopies, byte(c.Members)}, uint32(c.Window/time.Microsecond)), nil
}

// The stream window's bounds, as the pipe holds them: what every receiver
// gives at least (DefaultWindow) and the most one stream may keep.
const (
	MinStreamWindow = DefaultStreamWindow
	MaxStreamWindow = 64 << 20
	// DefaultStreamWindow is the window every stream gives unless told
	// (rust stream::WINDOW).
	DefaultStreamWindow = trunk.DefaultWindow
)

func putStreamWindow(bytes int) ([]byte, error) {
	if bytes < MinStreamWindow || bytes > MaxStreamWindow || bytes%1024 != 0 {
		return nil, fmt.Errorf("pipectl: stream window %d bytes; want whole KiB from %d to %d", bytes, MinStreamWindow, MaxStreamWindow)
	}
	return binary.LittleEndian.AppendUint32([]byte{bStreamWindow}, uint32(bytes/1024)), nil
}

// MaxDemandHold is the longest hold of copies on demand the pipe takes.
const MaxDemandHold = time.Hour

func putDemand(hold time.Duration) ([]byte, error) {
	if hold < 0 || hold > MaxDemandHold {
		return nil, fmt.Errorf("pipectl: copies on demand: hold %v; want 0 (always) to %v", hold, MaxDemandHold)
	}
	return binary.LittleEndian.AppendUint32([]byte{bDemand}, uint32(hold/time.Millisecond)), nil
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

// The pipe's numbers of the fates (rust/pipe/src/route.rs): it only compares
// them. 0 is a wire the route says nothing of; any fate past these two gets
// a number from fateOther up, in the order of its name.
const (
	fateUDP   = 1
	fateTCP   = 2
	fateOther = 3
)

// putRoute is the route and the wires' fates (trunk fates.go): voice's main
// wire, bulk's, video's, voice's whole set when the route has one, and the
// fate of each wire the brain gave a fate. A set's delay goes in whole
// milliseconds, at most 65535.
func putRoute(r trunk.Route, fates map[trunk.WireID]trunk.Fate) []byte {
	b := []byte{bRoute, byte(r.Voice), byte(r.Bulk), byte(r.Video()), byte(r.VoiceSet.Len())}
	for i := 0; i < r.VoiceSet.Len(); i++ {
		c := r.VoiceSet.At(i)
		b = append(b, byte(c.Wire), byte(c.Copies))
		b = binary.LittleEndian.AppendUint16(b, uint16(min(c.After/time.Millisecond, 65535)))
	}
	ids := make([]trunk.WireID, 0, len(fates))
	var others []trunk.Fate
	for id, f := range fates {
		ids = append(ids, id)
		if f != trunk.FateUDP && f != trunk.FateTCP && !slices.Contains(others, f) {
			others = append(others, f)
		}
	}
	slices.Sort(ids)
	slices.Sort(others)
	b = append(b, byte(len(ids)))
	for _, id := range ids {
		code := byte(fateUDP)
		switch f := fates[id]; f {
		case trunk.FateUDP:
		case trunk.FateTCP:
			code = fateTCP
		default:
			code = byte(fateOther + slices.Index(others, f))
		}
		b = append(b, byte(id), code)
	}
	return b
}

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

// putReceiver is a receiver on standby (ip invalid: taken away), its pools
// keeping poolMembers (0: as many as the active one's).
func putReceiver(rx byte, ip netip.Addr, poolMembers int) ([]byte, error) {
	if poolMembers < 0 || poolMembers > 255 {
		return nil, fmt.Errorf("pipectl: receiver %d: %d pool members, 0-255", rx, poolMembers)
	}
	var a [4]byte
	if ip.IsValid() {
		if !ip.Is4() {
			return nil, fmt.Errorf("pipectl: receiver %d: %s is not IPv4", rx, ip)
		}
		a = ip.As4()
	}
	return append([]byte{bReceiver, rx}, a[0], a[1], a[2], a[3], byte(poolMembers)), nil
}

func putActive(rx byte) []byte { return []byte{bActive, rx} }

// MaxPoints is the most border points a receiver has.
const MaxPoints = 8

// BorderPoint is a forwarding address and its TLS name. Empty SNI uses the core's name.
type BorderPoint struct {
	IP  netip.Addr
	SNI string
}

// ValidPointSNI permits DNS hostnames that Chromium can put in a proxy URL.
func ValidPointSNI(name string) bool {
	if len(name) > 253 || !strings.Contains(name, ".") {
		return false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func putBorderPoints(points []BorderPoint) ([]byte, []netip.Addr, error) {
	ips := make([]netip.Addr, len(points))
	named := false
	for i, p := range points {
		ips[i] = p.IP
		named = named || p.SNI != ""
		if p.SNI != "" && !ValidPointSNI(p.SNI) {
			return nil, nil, fmt.Errorf("pipectl: invalid TLS name for border point %s", p.IP)
		}
	}
	b, err := putPoints(ips)
	if err != nil || !named {
		return b, ips, err
	}
	b = []byte{bNamedPoints, byte(len(points))}
	for _, p := range points {
		ip := p.IP.As4()
		b = append(b, ip[:]...)
		b = append(b, byte(len(p.SNI)))
		b = append(b, p.SNI...)
	}
	return b, ips, nil
}

// putPoints is the active receiver's border points, the core's own address
// first.
func putPoints(ips []netip.Addr) ([]byte, error) {
	if len(ips) > MaxPoints {
		return nil, fmt.Errorf("pipectl: %d border points, at most %d", len(ips), MaxPoints)
	}
	b := []byte{bPoints, byte(len(ips))}
	for _, ip := range ips {
		if !ip.Is4() {
			return nil, fmt.Errorf("pipectl: border point %s is not IPv4", ip)
		}
		a := ip.As4()
		b = append(b, a[:]...)
	}
	return b, nil
}

// Receivers is the pipe's word on the receivers after each tick: the active
// one, and each on standby with its wires and pools (ID, Members, Up and
// ProofAgo of a WireTick; none before its session is open).
type Receivers struct {
	Active  byte
	Standby []ReceiverTick
}

// ReceiverTick is one receiver on standby.
type ReceiverTick struct {
	Rx    byte
	IP    netip.Addr
	Wires []WireTick
}

func parseReceivers(m []byte) (Receivers, error) {
	if len(m) < 3 {
		return Receivers{}, errTorn
	}
	r := Receivers{Active: m[1]}
	at := 3
	for i := 0; i < int(m[2]); i++ {
		if len(m) < at+6 {
			return Receivers{}, errTorn
		}
		t := ReceiverTick{Rx: m[at], IP: netip.AddrFrom4([4]byte(m[at+1 : at+5]))}
		k := int(m[at+5])
		at += 6
		if len(m) < at+7*k {
			return Receivers{}, errTorn
		}
		for j := 0; j < k; j++ {
			b := m[at:]
			t.Wires = append(t.Wires, WireTick{ID: trunk.WireID(b[0]), Members: int(b[1]), Up: int(b[2]), ProofAgo: ms(binary.LittleEndian.Uint32(b[3:]))})
			at += 7
		}
		r.Standby = append(r.Standby, t)
	}
	if at != len(m) {
		return Receivers{}, errTorn
	}
	return r, nil
}

// PointTick is the pipe's word on one border point after each tick
// (rust/pipe/src/pipe/points.rs point_ticks): every member of the current
// session's wires and pools at that point (member i at point i mod n), how
// many are up, and how long ago one of them last proved its round trip or
// joined (negative: none ever did). No member up is a point the entry
// cannot reach the core through: dead, frozen or cut.
type PointTick struct {
	IP          netip.Addr
	Members, Up int
	ProofAgo    time.Duration
}

func parsePoints(m []byte) ([]PointTick, error) {
	if len(m) < 2 || len(m) != 2+10*int(m[1]) {
		return nil, errTorn
	}
	out := make([]PointTick, 0, m[1])
	for at := 2; at < len(m); at += 10 {
		b := m[at:]
		out = append(out, PointTick{IP: netip.AddrFrom4([4]byte(b[:4])), Members: int(b[4]), Up: int(b[5]), ProofAgo: ms(binary.LittleEndian.Uint32(b[6:]))})
	}
	return out, nil
}

// Clients is a minute of the leg client → entry over every client's TCP
// socket of the pipe (rust/pipe/src/streams.rs Leg; the Go entry's
// trunkentry clients.go adds up the same): sockets open and closed in the
// minute, the sockets that sent, the segments sent to clients and sent
// again, and the round trip of the sockets that sent at p50 and p90 (-1:
// none sent). No client is named in it.
type Clients struct {
	Conns, Closed, Sending uint32
	Segs, Retrans          uint64
	RTTP50, RTTP90         time.Duration
}

func parseClients(m []byte) (Clients, error) {
	if len(m) != 37 || m[0] != pClients {
		return Clients{}, fmt.Errorf("pipectl: clients of %d bytes", len(m))
	}
	le := binary.LittleEndian
	us := func(v uint32) time.Duration {
		if v == noneMS {
			return -1
		}
		return time.Duration(v) * time.Microsecond
	}
	return Clients{Conns: le.Uint32(m[1:]), Closed: le.Uint32(m[5:]), Sending: le.Uint32(m[9:]),
		Segs: le.Uint64(m[13:]), Retrans: le.Uint64(m[21:]), RTTP50: us(le.Uint32(m[29:])), RTTP90: us(le.Uint32(m[33:]))}, nil
}

// Observed is the pipe's report of a tester's stream or flow (rust/pipe/src
// observe.rs; spec/trunk.md, "Observation"), as the Go entry's session
// reports one (trunk.Report): at the mark the exit sent, and at its end. For a
// stream, TCP is its client's socket as the kernel saw it at the report.
type Observed struct {
	Report  trunk.Report
	TCP     ClientTCP
	HaveTCP bool
}

// ClientTCP is a client's TCP socket (tcp_info): the Go entry's tcpSample
// (hikkari-control trunkentry observe.go).
type ClientTCP struct {
	RTT, RTTVar                                 time.Duration
	Retrans, Lost, Unack, Cwnd, SegsOut, SegsIn int64
}

// observedLen is a pObserved message's length.
const observedLen = 116

// observedEnds are the pipe's end codes (observe.rs END_*) as the trunk says
// them.
var observedEnds = []string{"", trunk.EndFin, trunk.EndLocal, trunk.EndPeer, trunk.EndEpoch, trunk.EndSession, trunk.EndIdle}

func parseObserved(m []byte) (Observed, error) {
	if len(m) != observedLen || m[0] != pObserved {
		return Observed{}, fmt.Errorf("pipectl: observed of %d bytes", len(m))
	}
	le := binary.LittleEndian
	u64 := func(at int) int64 { return int64(le.Uint64(m[at:])) }
	u32 := func(at int) uint32 { return le.Uint32(m[at:]) }
	if m[82] >= byte(len(observedEnds)) || m[10] > 1 {
		return Observed{}, fmt.Errorf("pipectl: observed with phase %d, end %d", m[10], m[82])
	}
	phase := trunk.PhaseMark
	if m[10] == 1 {
		phase = trunk.PhaseEnd
	}
	o := Observed{Report: trunk.Report{
		ID: le.Uint64(m[1:]), Kind: trunk.ObsKind(m[9]), Phase: phase, Port: le.Uint16(m[11:]),
		Age: time.Duration(u32(13)) * time.Millisecond,
		Up:  u64(17), Down: u64(25), Chunks: u64(33), Resent: u64(41), Carriers: int(m[49]), Deaths: int(u32(50)),
		MaxWait:   time.Duration(u32(54)) * time.Millisecond,
		DgramsOut: u64(58), DgramsIn: u64(66), DgramsCopy: u64(74), End: observedEnds[m[82]],
	}, HaveTCP: m[83] == 1}
	if o.HaveTCP {
		o.TCP = ClientTCP{RTT: time.Duration(u32(84)) * time.Microsecond, RTTVar: time.Duration(u32(88)) * time.Microsecond,
			Retrans: int64(u32(92)), Lost: int64(u32(96)), Unack: int64(u32(100)), Cwnd: int64(u32(104)),
			SegsOut: int64(u32(108)), SegsIn: int64(u32(112))}
	}
	return o, nil
}

// Stats are the counters of the brain's minute line the ticks do not carry
// (rust/pipe/src/ctl.rs Stats), since the pipe started, in the Go entry's
// words (trunk.Stats): clients' streams opened and reset either way, chunks
// sent again, client bytes up and down, the pool's dead ports and kills, the
// pipe's own pauses in all, and the pool's members' round trips at p50, p90
// and the most (-1: no member up).
type Stats struct {
	Opened, Reset, Resent, Up, Down int64
	DeadPorts, PortKills            int64
	Paused                          time.Duration
	RTTP50, RTTP90, RTTMax          time.Duration
}

const statsLen = 73

func parseStats(m []byte) (Stats, error) {
	if len(m) != statsLen || m[0] != pStats {
		return Stats{}, fmt.Errorf("pipectl: stats of %d bytes", len(m))
	}
	le := binary.LittleEndian
	u64 := func(at int) int64 { return int64(le.Uint64(m[at:])) }
	us := func(at int) time.Duration {
		if v := le.Uint32(m[at:]); v != noneMS {
			return time.Duration(v) * time.Microsecond
		}
		return -1
	}
	return Stats{Opened: u64(1), Reset: u64(9), Resent: u64(17), Up: u64(25), Down: u64(33),
		DeadPorts: int64(le.Uint32(m[41:])), PortKills: u64(45), Paused: time.Duration(u64(53)) * time.Millisecond,
		RTTP50: us(61), RTTP90: us(65), RTTMax: us(69)}, nil
}
