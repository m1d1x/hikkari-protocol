package pipectl

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

// A tester's stream and flow through the pipe (spec/trunk.md, "Observation";
// trunk TestObserveStream, TestObserveFlow on the Go entry): the exit's relay
// knows the key and marks them, the exit tells the pipe the observation's
// id (the pipe's hellos say it reads observe frames), and the pipe reports
// each to the brain at the mark and at its end, with the trunk's counters and
// a stream's client TCP. A stream nobody marked is reported by no one.

// markLocal is the exit's relay that says which stream or flow each of its
// connections is for, as the edge's registry learns it.
type markLocal struct {
	local
	targets chan trunk.Target
}

func (l markLocal) DialStream(ctx context.Context, port uint16) (net.Conn, error) {
	if t, ok := trunk.TargetFrom(ctx); ok {
		l.targets <- t
	}
	return l.local.DialStream(ctx, port)
}

func (l markLocal) DialFlow(ctx context.Context, port uint16) (net.Conn, error) {
	if t, ok := trunk.TargetFrom(ctx); ok {
		l.targets <- t
	}
	return l.local.DialFlow(ctx, port)
}

func nextObserved(t *testing.T, c chan Observed, what string) Observed {
	t.Helper()
	select {
	case o := <-c:
		return o
	case <-time.After(10 * time.Second):
		t.Fatalf("no %s report", what)
		return Observed{}
	}
}

func TestATestersStreamAndFlowAreReportedAtTheMarkAndAtTheirEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ml := markLocal{targets: make(chan trunk.Target, 16)}
	x := trunk.NewExit(trunk.Config{}, ml)
	go x.Run(ctx)
	pl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pl.Close() })
	go func() {
		for {
			c, err := pl.Accept()
			if err != nil {
				return
			}
			go func() { _ = x.ServeMember(c) }()
		}
	}()
	seen := make(chan Observed, 16)
	p, err := Start(Config{Bin: pipeBin(t), Args: []string{"--flow-idle-ms", "500"}, Stderr: os.Stderr, Logf: t.Logf,
		OnObserved: func(o Observed) { seen <- o }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	if err := p.SetPool(Pool{ID: trunk.PoolWire, Members: 4, Exit: netip.MustParseAddrPort(pl.Addr().String())}); err != nil {
		t.Fatal(err)
	}
	p.SetRoute(trunk.Route{Voice: trunk.PoolWire, Bulk: trunk.PoolWire})
	waitFor(t, 10*time.Second, "the pool's members up", func() bool { return wireUp(p, trunk.PoolWire, 4) })
	tl, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.TCPListen(1, tl, tcpEcho(t)); err != nil {
		t.Fatal(err)
	}
	ul, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ul.Close() })
	if err := p.Listen(1, ul, trunk.ClassVoice, udpEcho(t), 1); err != nil {
		t.Fatal(err)
	}

	// A stream nobody marks: no report.
	plain, err := net.Dial("tcp", tl.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := echoed(plain, 64<<10, nil); err != nil {
		t.Fatal(err)
	}
	<-ml.targets
	plain.Close()

	// The tester's stream.
	c, err := net.Dial("tcp", tl.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	b := make([]byte, 1<<10)
	if _, err := c.Write(b); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatal(err)
	}
	tg := <-ml.targets
	id, ok := tg.Session.Observe(tg.Kind, tg.ID, "tester-key")
	if !ok || tg.Kind != trunk.ObsStream {
		t.Fatalf("the exit did not mark the stream: %+v", tg)
	}
	m := nextObserved(t, seen, "the stream's mark")
	if r := m.Report; r.ID != id || r.Kind != trunk.ObsStream || r.Phase != trunk.PhaseMark || r.Up != 1<<10 || r.Down != 1<<10 || !m.HaveTCP || m.TCP.SegsOut == 0 {
		t.Fatalf("the stream's mark %+v, want id %x, 1 KiB each way, its client's TCP", m, id)
	}
	big := make([]byte, 1<<20)
	if _, err := c.Write(big); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, big); err != nil {
		t.Fatal(err)
	}
	_ = c.(*net.TCPConn).CloseWrite()
	_, _ = io.Copy(io.Discard, c)
	e := nextObserved(t, seen, "the stream's end")
	want := int64(1<<10 + 1<<20)
	if r := e.Report; r.ID != id || r.Phase != trunk.PhaseEnd || r.End != trunk.EndFin || r.Up != want || r.Down != want ||
		r.Chunks == 0 || r.Carriers == 0 || r.MaxWait < 0 || !e.HaveTCP {
		t.Fatalf("the stream's end %+v, want %d bytes each way, chunks, carriers, fin, its client's TCP", e, want)
	}
	t.Logf("the stream: %+v", e)

	// The tester's flow: ends unused after the pipe's 500 ms.
	u, err := net.Dial("udp", ul.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	if _, err := u.Write(make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	ft := <-ml.targets
	fid, ok := ft.Session.Observe(ft.Kind, ft.ID, "tester-key")
	if !ok || ft.Kind != trunk.ObsFlow {
		t.Fatalf("the exit did not mark the flow: %+v", ft)
	}
	fm := nextObserved(t, seen, "the flow's mark")
	if r := fm.Report; r.ID != fid || r.Kind != trunk.ObsFlow || r.Phase != trunk.PhaseMark || r.DgramsOut != 1 || fm.HaveTCP {
		t.Fatalf("the flow's mark %+v", fm)
	}
	for i := 0; i < 4; i++ {
		_, _ = u.Write(make([]byte, 100))
		time.Sleep(20 * time.Millisecond)
	}
	fe := nextObserved(t, seen, "the flow's end")
	if r := fe.Report; r.ID != fid || r.Phase != trunk.PhaseEnd || r.End != trunk.EndIdle || r.DgramsOut != 5 || r.DgramsIn != 5 {
		t.Fatalf("the flow's end %+v, want 5 out and in, ended unused", fe)
	}
	select {
	case o := <-seen:
		t.Fatalf("a report more: %+v", o)
	case <-time.After(300 * time.Millisecond):
	}
}
