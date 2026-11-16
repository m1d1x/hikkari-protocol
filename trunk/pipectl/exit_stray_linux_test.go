package pipectl

import (
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

// TestAPoolCallComesBackAfterAStrayExitOnTheWire: a second exit reads the
// pipe's udp wire beside the one that serves the session (as an older
// generation that took the wires back did on unl1, 16.11: two hk-exit on one
// port, the kernel giving each datagram to either). The members' hellos
// answer with both exits' epochs, the pipe resets the session's flows on
// every change. Once the stray exit is gone, the brain's call on the pool
// must hear its answers again within seconds: on 16.11 the stand's and the
// people's pool calls stayed at 0 of 3000 a minute, members up, until the
// brain was reloaded.
func TestAPoolCallComesBackAfterAStrayExitOnTheWire(t *testing.T) {
	r := newRustReload(t)
	p, err := Start(Config{Bin: pipeBin(t), Args: []string{"--flow-idle-ms", exitIdle}, Stderr: os.Stderr, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	if err := p.SetWire(Wire{ID: dgramWire, Name: "udp", Exit: r.wire.LocalAddr().(*net.UDPAddr).AddrPort(), Key: testKey, Members: 4}); err != nil {
		t.Fatal(err)
	}
	if err := p.SetPool(Pool{ID: trunk.PoolWire, Members: 4, Exit: netip.MustParseAddrPort(r.pool.Addr().String())}); err != nil {
		t.Fatal(err)
	}
	p.SetRoute(trunk.Route{Voice: dgramWire, Bulk: trunk.PoolWire})
	waitFor(t, 5*time.Second, "the pipe's members up", func() bool { return wireUp(p, dgramWire, 4) && wireUp(p, trunk.PoolWire, 4) })
	call := startBrainCall(p, trunk.PoolWire)
	defer call.hangUp()
	time.Sleep(2 * time.Second)
	if call.got.Load() < 50 {
		t.Fatalf("the pool call before the stray exit: %d answers", call.got.Load())
	}

	stray := startRustExit(t, 7)
	if err := stray.SetWire(ExitWire{ID: dgramWire, Conn: r.wire, Keys: []string{testKey}}); err != nil {
		t.Fatal(err)
	}
	if err := stray.SetPorts([]uint16{r.udp, r.tcp}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Second)
	stray.Close()
	gone := time.Now()

	// Within 10 s of the stray exit's end the call hears 90% of what it
	// sends over 3 s.
	deadline := gone.Add(10 * time.Second)
	for {
		before := call.got.Load()
		time.Sleep(3 * time.Second)
		heard := call.got.Load() - before
		if heard >= int64(3*time.Second/callEvery)*9/10 {
			t.Logf("the pool call hears %d answers in 3 s, %v after the stray exit ended", heard, time.Since(gone).Round(100*time.Millisecond))
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the pool call heard %d answers in the last 3 s, %v after the stray exit ended: %+v", heard, time.Since(gone).Round(100*time.Millisecond), freshTick(p))
		}
	}
}
