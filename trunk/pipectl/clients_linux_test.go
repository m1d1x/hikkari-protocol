package pipectl

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

// The leg client → entry in the pipe (rust/pipe/src/streams.rs Leg; the Go
// entry's trunkentry clients.go adds up the same): each minute the brain asks,
// the pipe reads every client's socket and answers the sums of the minute;
// a socket that closed in it counts once, and the next minute starts empty.
func TestThePipeAddsUpItsClientsSocketsOfTheMinute(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	x := newGoStreamExit(t, ctx)
	p := poolPipe(t, Pool{ID: trunk.PoolWire, Members: 4, Exit: netip.MustParseAddrPort(x.pool)})
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.TCPListen(1, l, tcpEcho(t)); err != nil {
		t.Fatal(err)
	}
	if c, err := p.Clients(); err != nil || c.Conns != 0 || c.Segs != 0 || c.RTTP50 != -1 {
		t.Fatalf("the first minute %+v %v: want no socket", c, err)
	}
	// One stream stays open (written and read back, its side not shut),
	// the other ends whole (echoed shuts its side, the exit's echo its own).
	open, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer open.Close()
	data := make([]byte, 256<<10)
	if _, err := open.Write(data); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(open, data); err != nil {
		t.Fatal(err)
	}
	ended, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer ended.Close()
	if err := echoed(ended, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "one stream left", func() bool { return freshTick(p).Streams == 1 })
	c, err := p.Clients()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("the minute: %+v", c)
	if c.Conns != 1 || c.Closed != 1 || c.Sending != 2 || c.Segs < 32 || c.Retrans != 0 || c.RTTP50 <= 0 || c.RTTP90 < c.RTTP50 {
		t.Fatalf("the minute %+v: want 1 open, 1 closed, both sending, their segments and round trips, nothing sent again", c)
	}
	next, err := p.Clients()
	if err != nil {
		t.Fatal(err)
	}
	if next.Conns != 1 || next.Closed != 0 || next.Segs != 0 || next.Sending != 0 || next.RTTP50 != -1 {
		t.Fatalf("an idle minute %+v", next)
	}
	// The minute line's counters (Stats): both streams, their bytes, the
	// pool's members' round trips.
	var st Stats
	waitFor(t, 10*time.Second, "the members' round trips", func() bool {
		st, err = p.Stats()
		return err == nil && st.RTTP50 > 0
	})
	t.Logf("stats: %+v", st)
	if st.Opened != 2 || st.Up < 1<<20 || st.Down < 1<<20 || st.Reset != 0 || st.RTTP50 <= 0 || st.RTTMax < st.RTTP90 || st.RTTP90 < st.RTTP50 {
		t.Fatalf("stats %+v: want 2 streams opened, 1 MiB each way, none reset, the members' round trips", st)
	}
}
