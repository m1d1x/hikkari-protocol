package pipectl

import (
	"encoding/hex"
	"reflect"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

// The same bytes as rust/pipe/src/ctl.rs WIRE_GOLDEN and TICK_GOLDEN.
const (
	wireGolden = "030301e8030000b0042c01000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	tickGolden = "82ffffffff020000003905000007000000080000000000000009000000000000000a000000000000000b00000000000000030101020302fa00000064000000b80b0000010000000000000002000000000000000300000000000000040000000000000005000000000000000600000000000000"
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
		DgramsOut: 8, DgramsIn: 9, DgramsCopy: 10, FlowsIdle: 11, Retired: 3, Coming: true, Wires: []WireTick{{
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
	if got := putRoute(trunk.Route{Voice: 2, Bulk: trunk.AnyWire}); !reflect.DeepEqual(got, []byte{bRoute, 2, 255}) {
		t.Fatalf("route % x", got)
	}
}
