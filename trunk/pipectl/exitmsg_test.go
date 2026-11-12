package pipectl

import (
	"encoding/hex"
	"reflect"
	"testing"
	"time"
)

// The same bytes as rust/exit/src/ctl.rs WIRE_GOLDEN, TICK_GOLDEN and
// POOL_GOLDEN. The
// wire's keys there are 0xaa and 0xbb repeated: the brain sends udpwire.Key
// of each trunk key, so the test sets them past the derivation.
const (
	exitWireGolden = "030201e8030000b0042c013075000002aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	exitTickGolden = "82ffffffff01000000390500000200000004000000030000001300000014000000050000000000000006000000000000000700000000000000080000000000000009000000000000000a000000000000000b000000000000000c000000000000000d000000000000000e000000000000000f00000000000000100000000000000011000000000000001200000000000000150000000000000016000000000000001700000000000000180000000000000019000000000000001a000000000000001b000000000000001c000000000000001d000000000000001e000000000000001f000000000000002000000000000000"
	exitPoolGolden = "0b2c0130750000"
)

func TestExitGolden(t *testing.T) {
	b, err := putExitWire(2, time.Millisecond, 1200, 300*time.Millisecond, 30*time.Second, []string{"k1-0123456789abcdefghijkl", "k2-0123456789abcdefghijkl"})
	if err != nil {
		t.Fatal(err)
	}
	head := 16
	for i := range 64 {
		b[head+i] = 0xaa
		if i >= 32 {
			b[head+i] = 0xbb
		}
	}
	if got := hex.EncodeToString(b); got != exitWireGolden {
		t.Fatalf("exit wire %s, want %s", got, exitWireGolden)
	}
	if _, err := putExitWire(2, 0, 0, 0, 0, nil); err == nil {
		t.Fatal("a wire with no key taken")
	}
	if got := putExitPorts([]uint16{8443, 80}); !reflect.DeepEqual(got, []byte{xPorts, 2, 0, 0xfb, 0x20, 0x50, 0}) {
		t.Fatalf("ports % x", got)
	}
	if got := hex.EncodeToString(putExitPool(300*time.Millisecond, 30*time.Second)); got != exitPoolGolden {
		t.Fatalf("exit pool %s, want %s", got, exitPoolGolden)
	}
	m, _ := hex.DecodeString(exitTickGolden)
	tk, err := parseExitTick(m)
	if err != nil {
		t.Fatal(err)
	}
	want := ExitTick{PauseAgo: -1, Pauses: 1, LateMax: 1337 * time.Microsecond, Sessions: 2, Members: 4, Flows: 3,
		Links: 19, Streams: 20,
		Joined: 5, Silent: 6, Quiet: 7, Gone: 8, DgramsOut: 9, DgramsIn: 10, DgramsCopy: 11, FlowsIdle: 12, Refused: 13,
		WIn: 14, WOut: 15, FramesOut: 16, Bad: 17, Dropped: 18,
		StreamsOpened: 21, StreamsFin: 22, ResetPeer: 23, ResetLocal: 24, Hit: 25, Resent: 26, Up: 27, Down: 28,
		Early: 29, EarlyDropped: 30, RefusedStreams: 31, LinkDgrams: 32}
	if tk != want {
		t.Fatalf("exit tick %+v, want %+v", tk, want)
	}
	if _, err := parseExitTick(m[:len(m)-1]); err == nil {
		t.Fatal("a torn exit tick read")
	}
}
