package pipectl

import (
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

// TestAPoolCallHearsTheLiveExitWhenAnotherNumberedItsAnswersHigher: two exit
// processes answer the same flow, each numbering the answers from its own
// count (on unl1, 16.11, an older generation that took the wires back beside
// the newest). The first has answered it for 25 s (over the replay window of
// 1024), the second comes up beside it on the same sockets and the pool's
// members spread over both; then the first ends. The live one's answers
// must be heard within seconds: numbered below the first's, they fell under
// the replay window as old, every one, until a reload of the brain (the
// stand's and the people's pool calls at 0 of 3000 a minute, 16.11).
func TestAPoolCallHearsTheLiveExitWhenAnotherNumberedItsAnswersHigher(t *testing.T) {
	r := newRustReload(t)
	p, err := Start(Config{Bin: pipeBin(t), Args: []string{"--flow-idle-ms", exitIdle}, Stderr: os.Stderr, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	pool := Pool{ID: trunk.PoolWire, Members: 4, Exit: netip.MustParseAddrPort(r.pool.Addr().String())}
	if err := p.SetPool(pool); err != nil {
		t.Fatal(err)
	}
	p.SetRoute(trunk.Route{Voice: trunk.PoolWire, Bulk: trunk.PoolWire})
	waitFor(t, 5*time.Second, "the pool up", func() bool { return wireUp(p, trunk.PoolWire, 4) })
	call := startBrainCall(p, trunk.PoolWire)
	defer call.hangUp()
	time.Sleep(25 * time.Second)
	if got := call.got.Load(); got < 1100 {
		t.Fatalf("the first exit answered %d, want over the window of 1024", got)
	}

	// The second exit on the same sockets; the pool dialed anew spreads
	// over both.
	second := startRustExit(t, 3)
	if err := second.SetPool(r.pool, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := second.SetPorts([]uint16{r.udp, r.tcp}); err != nil {
		t.Fatal(err)
	}
	pool.Members = 8
	if err := p.SetPool(pool); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "the pool of 8 up", func() bool { return wireUp(p, trunk.PoolWire, 8) })
	waitFor(t, 5*time.Second, "members at both exits", func() bool {
		return freshExit(r.old).Links > 0 && freshExit(second).Links > 0
	})
	time.Sleep(3 * time.Second)
	r.old.Close()
	gone := time.Now()

	deadline := gone.Add(10 * time.Second)
	for {
		before := call.got.Load()
		time.Sleep(3 * time.Second)
		heard := call.got.Load() - before
		if heard >= int64(3*time.Second/callEvery)*9/10 {
			t.Logf("the call hears %d answers in 3 s, %v after the first exit ended", heard, time.Since(gone).Round(100*time.Millisecond))
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the call heard %d answers in the last 3 s, %v after the first exit ended", heard, time.Since(gone).Round(100*time.Millisecond))
		}
	}
}
