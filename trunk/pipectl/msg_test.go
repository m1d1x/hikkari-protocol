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
	if got := hex.EncodeToString(putTCPListen(1, 8443)); got != tcpListenGolden {
		t.Fatalf("tcp listen %s, want %s", got, tcpListenGolden)
	}
	if got := putRoute(trunk.Route{Voice: 2, Bulk: trunk.AnyWire}); !reflect.DeepEqual(got, []byte{bRoute, 2, 255}) {
		t.Fatalf("route % x", got)
	}
}
