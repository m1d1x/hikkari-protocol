package trunk

import "time"

// Wires (t2): one session over members of more than one form
// (hikkari-client plans/2026-11-11-trunk-wires-stage4.md, раздел 4.1).
//
// The pool of TCP members on Chromium's stack is one wire. Another wire is
// members of another form: QUIC streams, an encrypted UDP socket, a tunnel.
// A wire is a kind of member, not a session of its own, so moving a stream
// from one wire to another is what moving it from a dead member to a live
// one is today: its unconfirmed chunks go again on the other wire, no new
// open, the client's connection does not notice. A datagram has nothing to
// move: the next one goes on the other wire.
//
// A member says its wire in its hello (t2, wire.go). Two flags shape it:
// Streams (it carries streams' chunks and acks; a member without it has no
// congestion control or order of its own and carries only datagrams and
// pings), and Packet (each frame goes in a datagram of its own and may be
// lost: such a member pings often and dies only after several pings in a
// row go unanswered).
//
// Which wire carries what is the entry's choice, per class of traffic
// (Route): voice (a client's calls, small datagrams) and bulk (streams and
// every other datagram). The exit follows: it answers a stream or a flow on
// the wire the entry last sent it on. The trunk's own call can be pinned to
// one wire (FlowOptions.Pin) to measure it whatever the route.

// WireID names a wire of the trunk.
type WireID uint8

const (
	// PoolWire is the pool of TCP members on Chromium's stack (t1).
	PoolWire WireID = 0
	// AnyWire is no preference: any member that can carry it.
	AnyWire WireID = 255
)

// Flags of a member's kind, in its t2 hello.
const (
	kindStreams byte = 1 // carries streams
	kindPacket  byte = 2 // each frame in a datagram of its own, lossy
)

// memberKind is what a member is: its wire and its form.
type memberKind struct {
	wire    WireID
	streams bool
	packet  bool
}

// poolKind is a t1 member: the pool's, carrying everything.
var poolKind = memberKind{wire: PoolWire, streams: true}

func kindOf(w WireID, flags byte) memberKind {
	return memberKind{wire: w, streams: flags&kindStreams != 0, packet: flags&kindPacket != 0}
}

func (k memberKind) flags() byte {
	var f byte
	if k.streams {
		f |= kindStreams
	}
	if k.packet {
		f |= kindPacket
	}
	return f
}

// t1 says the member speaks the pool's hello, which every exit knows.
func (k memberKind) t1() bool { return k == poolKind }

// Wire is one wire of an entry (Entry.AddWire): its members and how to dial
// them.
type Wire struct {
	ID WireID
	// Name is what logs and reports call it ("pool", "quic", "udp").
	Name string
	// Shape is the form an observer sees on the path ("browser": TLS or
	// QUIC as Chromium speaks it; "random": bytes that look like nothing).
	// The selector keeps its warm pair in two shapes, so that one rule
	// against one form does not take both (stage plan, принцип 5).
	Shape string
	// Members is how many members the wire keeps up.
	Members int
	// Dial opens a member. localPort is from Ports (the entry's own book
	// when nil); a wire that picks its own ports ignores it.
	Dial  Dial
	Ports *PortBook
	// Streams and Packet are the members' form (memberKind).
	Streams bool
	Packet  bool
	// Knobs names what Dial was made from (a port, an SNI, a password):
	// SetWires restarts a wire whose Knobs changed.
	Knobs string
}

func (w Wire) kind() memberKind {
	return memberKind{wire: w.ID, streams: w.Streams, packet: w.Packet}
}

// Class is a class of traffic the entry routes on its own wire.
type Class uint8

const (
	// ClassBulk is streams and datagrams that are not a call.
	ClassBulk Class = iota
	// ClassVoice is a client's calls and other small, live datagrams.
	ClassVoice
)

func (c Class) String() string {
	if c == ClassVoice {
		return "voice"
	}
	return "bulk"
}

// Route is which wire each class goes on. AnyWire is any member, as a t1
// session; a wire with no member up now is passed over for any member that
// can carry the traffic.
type Route struct {
	Voice, Bulk WireID
}

// AnyRoute is no preference for either class.
var AnyRoute = Route{Voice: AnyWire, Bulk: AnyWire}

func (r Route) of(c Class) WireID {
	if c == ClassVoice {
		return r.Voice
	}
	return r.Bulk
}

// FlowOptions shape a datagram flow (Session.OpenFlowWith).
type FlowOptions struct {
	// Copies is how many members carry each datagram; 0 is the session's.
	Copies int
	// Class is the route the flow follows.
	Class Class
	// Pin, when not AnyWire, holds the flow to one wire whatever the route,
	// and drops its datagrams while that wire has no member: what the
	// trunk's call on a wire must hear. The zero value pins to the pool:
	// use AnyWire for no pin.
	Pin WireID
}

// WireState is what a session sees of one wire now.
type WireState struct {
	ID      WireID
	Members int
	// Proof is the latest progress one of its members showed: a chunk
	// confirmed, a ping answered. Zero before the first.
	Proof    time.Time
	Inflight int // unconfirmed bytes on its members
	// Owed is how long the wire's members have owed progress and shown
	// none: the least of its members' debts, 0 while one of them owes
	// nothing. An idle wire owes nothing; a cut one owes more every tick.
	Owed time.Duration
}

// Packet members ping this often, an answered ping or not: a lost pong is
// not a dead member, and a member is judged by the oldest ping still owed.
const packetKeepalive = 100 * time.Millisecond
