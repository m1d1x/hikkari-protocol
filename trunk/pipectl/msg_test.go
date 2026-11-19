package pipectl

import (
	"encoding/hex"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

// The same bytes as rust/pipe/src/ctl.rs WIRE_GOLDEN and TICK_GOLDEN.
const (
	wireGolden         = "030301e8030000b0042c01000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	poolPlainGolden    = "0d0001202c01204eff7f7f000001de4f"
	poolChromiumGolden = "0d0002042c01204eff7f7f000001bb010a686b2e6578616d706c651a676f6c64656e2d746573742d6b65792d3031323334353637383911002f6f70742f6c696263726f6e65742e736f50454d"
	tcpListenGolden    = "0c01fb20"
	copiesGolden       = "1004a00f0000"
	demandGolden       = "13e0930400"
	openRxGolden       = "140700000001ff00000101"
	h3WireGolden       = "030602e8030000b0042c01000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0400204eff7f7f0000015d110a686b2e6578616d706c6511002f6f70742f6c696263726f6e65742e736f50454d"
	tickGolden         = "82ffffffff020000003905000007000000080000000000000009000000000000000a000000000000000b0000000000000003010500000001020302fa00000064000000b80b0000010000000000000002000000000000000300000000000000040000000000000005000000000000000600000000000000"
)

// TestGolden: the brain writes a wire and reads a tick in the bytes the pipe
// reads and writes.
func TestGolden(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	b, err := putWire(3, FormUDP, time.Millisecond, 1200, 300*time.Millisecond, key)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(b); got != wireGolden {
		t.Fatalf("wire %s, want %s", got, wireGolden)
	}
	m, _ := hex.DecodeString(tickGolden)
	tk, err := parseTick(m)
	if err != nil {
		t.Fatal(err)
	}
	want := Tick{PauseAgo: -1, Pauses: 2, LateMax: 1337 * time.Microsecond, Flows: 7,
		DgramsOut: 8, DgramsIn: 9, DgramsCopy: 10, FlowsIdle: 11, Retired: 3, Coming: true, Streams: 5, Wires: []WireTick{{
			ID: 2, Members: 3, Up: 2, Owed: 250 * time.Millisecond, ProofAgo: 100 * time.Millisecond, RTT: 3 * time.Millisecond,
			UpPkts: 1, UpBytes: 2, DownPkts: 3, DownBytes: 4, Dgrams: 5, Dropped: 6}}}
	if !reflect.DeepEqual(tk, want) {
		t.Fatalf("tick %+v, want %+v", tk, want)
	}
	if _, err := parseTick(m[:len(m)-1]); err == nil {
		t.Fatal("a torn tick read")
	}
	if _, err := putWire(3, FormUDP, 0, 0, 0, key[:31]); err == nil {
		t.Fatal("a short key taken")
	}
	// rust/pipe/src/ctl.rs OPEN_RX_GOLDEN: the call held to receiver 1.
	if got := hex.EncodeToString(putOpenRx(7, trunk.FlowOptions{Class: trunk.ClassVoice, Pin: trunk.AnyWire, Copies: 1}, trunk.EchoPort, 1)); got != openRxGolden {
		t.Fatalf("open rx %s, want %s", got, openRxGolden)
	}
	// rust/pipe/src/ctl.rs parses_the_brains_drain_and_adopt_alone.
	if bDrain != 0x0a || bAdopt != 0x0b || pDrained != 0x86 {
		t.Fatalf("drain %#x, adopt %#x, drained %#x", bDrain, bAdopt, pDrained)
	}
	// rust/pipe/src/ctl.rs parses_the_brains_pool_and_tcp_port.
	pp, err := putPool(Pool{ID: 0, Members: 32, Stall: 300 * time.Millisecond, Ports: [2]uint16{20000, 32767},
		Exit: netip.MustParseAddrPort("127.0.0.1:20446")})
	if err != nil || hex.EncodeToString(pp) != poolPlainGolden {
		t.Fatalf("plain pool %x %v, want %s", pp, err, poolPlainGolden)
	}
	pc, err := putPool(Pool{ID: 0, Members: 4, Stall: 300 * time.Millisecond, Ports: [2]uint16{20000, 32767},
		Exit:     netip.MustParseAddrPort("127.0.0.1:443"),
		Chromium: &ChromiumForm{SNI: "hk.example", Key: "golden-test-key-0123456789", Cronet: "/opt/libcronet.so", Roots: "PEM"}})
	if err != nil || hex.EncodeToString(pc) != poolChromiumGolden {
		t.Fatalf("Chromium pool %x %v, want %s", pc, err, poolChromiumGolden)
	}
	// rust/pipe/src/ctl.rs parses_the_brains_quic_wire.
	h3, err := putH3(6, time.Millisecond, 1200, 300*time.Millisecond, key, 4, netip.MustParseAddrPort("127.0.0.1:4445"),
		H3Form{SNI: "hk.example", Cronet: "/opt/libcronet.so", Roots: "PEM", Ports: [2]uint16{20000, 32767}})
	if err != nil || hex.EncodeToString(h3) != h3WireGolden {
		t.Fatalf("QUIC wire %x %v, want %s", h3, err, h3WireGolden)
	}
	if _, err := putH3(6, 0, 0, 0, key, 4, netip.MustParseAddrPort("127.0.0.1:4445"), H3Form{Usage: "kProxy"}); err == nil {
		t.Fatal("a usage that is neither destination nor proxy taken")
	}
	if b, err := putCopies(Copies{Members: 4, Window: 4 * time.Millisecond}); err != nil || hex.EncodeToString(b) != copiesGolden {
		t.Fatalf("copies %x %v, want %s", b, err, copiesGolden)
	}
	if _, err := putCopies(Copies{Members: 4, Window: 2 * time.Second}); err == nil {
		t.Fatal("a window of 2 s went")
	}
	if b, err := putDemand(5 * time.Minute); err != nil || hex.EncodeToString(b) != demandGolden {
		t.Fatalf("demand %x %v, want %s", b, err, demandGolden)
	}
	if _, err := putDemand(2 * time.Hour); err == nil {
		t.Fatal("a hold of 2 h went")
	}
	if got := hex.EncodeToString(putTCPListen(1, 8443)); got != tcpListenGolden {
		t.Fatalf("tcp listen %s, want %s", got, tcpListenGolden)
	}
	if got := putRoute(trunk.Route{Voice: 2, Bulk: trunk.AnyWire}, nil); !reflect.DeepEqual(got, []byte{bRoute, 2, 255, 2, 0, 0}) {
		t.Fatalf("route % x", got)
	}
}

// TestRouteBytes: voice's main wire, bulk's, video's, voice's set and the
// wires' fates in the bytes the pipe reads (rust/pipe/src/route.rs
// ROUTE_GOLDEN). A fate past udp and tcp gets a number of its own.
func TestRouteBytes(t *testing.T) {
	set := trunk.SetOf(trunk.Carry{Wire: 2}, trunk.Carry{Wire: 1, Copies: 1, After: 10 * time.Millisecond})
	r := trunk.Route{Voice: 1, VoiceSet: set, Bulk: 0}.WithVideo(3)
	got := hex.EncodeToString(putRoute(r, map[trunk.WireID]trunk.Fate{1: trunk.FateUDP, 0: trunk.FateTCP}))
	if got != "05010003020200000001010a000200020101" {
		t.Fatalf("route %s", got)
	}
	got = hex.EncodeToString(putRoute(trunk.Route{Voice: 1, Bulk: 1}, map[trunk.WireID]trunk.Fate{4: "border-b", 5: "border-a", 1: trunk.FateUDP}))
	if got != "050101010003010104040503" {
		t.Fatalf("route with fates of its own %s", got)
	}
}

// TestClientsGolden: the leg's minute in the bytes the pipe writes
// (rust/pipe/src/ctl.rs clients_golden).
func TestClientsGolden(t *testing.T) {
	m, _ := hex.DecodeString("870c00000003000000090000005abc000000000000250000000000000060470000e8ee0000")
	c, err := parseClients(m)
	if err != nil {
		t.Fatal(err)
	}
	want := Clients{Conns: 12, Closed: 3, Sending: 9, Segs: 48218, Retrans: 37, RTTP50: 18272 * time.Microsecond, RTTP90: 61160 * time.Microsecond}
	if c != want {
		t.Fatalf("clients %+v, want %+v", c, want)
	}
	for i := 29; i < 37; i++ {
		m[i] = 0xff
	}
	if c, _ := parseClients(m); c.RTTP50 != -1 || c.RTTP90 != -1 {
		t.Fatalf("no round trip read as %v, %v", c.RTTP50, c.RTTP90)
	}
	if _, err := parseClients(m[:36]); err == nil {
		t.Fatal("a torn clients read")
	}
}

// TestObservedGolden: a tester's report in the bytes the pipe writes
// (rust/pipe/src/ctl.rs observed_golden).
func TestObservedGolden(t *testing.T) {
	m, _ := hex.DecodeString("88efcdab90785634120101fb200f2700000700000000000000080000000000000009000000000000000a000000000000000b0c0000000d000000000000000000000000000000000000000000000000000000010110270000e803000003000000010000000200000040000000c8000000c9000000")
	o, err := parseObserved(m)
	if err != nil {
		t.Fatal(err)
	}
	want := Observed{Report: trunk.Report{ID: 0x1234567890abcdef, Kind: trunk.ObsStream, Phase: trunk.PhaseEnd, Port: 8443,
		Age: 9999 * time.Millisecond, Up: 7, Down: 8, Chunks: 9, Resent: 10, Carriers: 11, Deaths: 12, MaxWait: 13 * time.Millisecond,
		End: trunk.EndFin}, HaveTCP: true, TCP: ClientTCP{RTT: 10 * time.Millisecond, RTTVar: time.Millisecond, Retrans: 3, Lost: 1,
		Unack: 2, Cwnd: 64, SegsOut: 200, SegsIn: 201}}
	if !reflect.DeepEqual(o, want) {
		t.Fatalf("observed %+v, want %+v", o, want)
	}
	if _, err := parseObserved(m[:115]); err == nil {
		t.Fatal("a torn report read")
	}
}

// TestStatsGolden: the minute line's counters in the bytes the pipe writes
// (rust/pipe/src/ctl.rs stats_golden).
func TestStatsGolden(t *testing.T) {
	m, _ := hex.DecodeString("8901000000000000000200000000000000030000000000000004000000000000000500000000000000060000000700000000000000080000000000000010270000204e000030750000")
	s, err := parseStats(m)
	if err != nil {
		t.Fatal(err)
	}
	want := Stats{Opened: 1, Reset: 2, Resent: 3, Up: 4, Down: 5, DeadPorts: 6, PortKills: 7, Paused: 8 * time.Millisecond,
		RTTP50: 10 * time.Millisecond, RTTP90: 20 * time.Millisecond, RTTMax: 30 * time.Millisecond}
	if s != want {
		t.Fatalf("stats %+v, want %+v", s, want)
	}
}

// TestReceiversGolden: the brain writes a receiver and the active one, and
// reads the receivers, in the bytes of rust/pipe/src/ctl.rs
// speaks_the_brains_receivers.
func TestReceiversGolden(t *testing.T) {
	b, err := putReceiver(1, netip.MustParseAddr("10.0.0.2"), 8)
	if err != nil || hex.EncodeToString(b) != "11010a00000208" {
		t.Fatalf("receiver %x %v", b, err)
	}
	if b, _ := putReceiver(1, netip.Addr{}, 0); hex.EncodeToString(b) != "11010000000000" {
		t.Fatalf("a receiver taken away %x", b)
	}
	if _, err := putReceiver(1, netip.MustParseAddr("::1"), 0); err == nil {
		t.Fatal("an IPv6 receiver taken")
	}
	if got := hex.EncodeToString(putActive(1)); got != "1201" {
		t.Fatalf("active %s", got)
	}
	m, _ := hex.DecodeString("8a0001010a0000020203060578000000000808ffffffff")
	r, err := parseReceivers(m)
	if err != nil {
		t.Fatal(err)
	}
	want := Receivers{Active: 0, Standby: []ReceiverTick{{Rx: 1, IP: netip.MustParseAddr("10.0.0.2"), Wires: []WireTick{
		{ID: 3, Members: 6, Up: 5, ProofAgo: 120 * time.Millisecond}, {ID: 0, Members: 8, Up: 8, ProofAgo: -1}}}}}
	if !reflect.DeepEqual(r, want) {
		t.Fatalf("receivers %+v, want %+v", r, want)
	}
	if _, err := parseReceivers(m[:len(m)-1]); err == nil {
		t.Fatal("torn receivers read")
	}
}
