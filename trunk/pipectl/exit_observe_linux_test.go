package pipectl

import (
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

// A tester's stream and flow through the pipe to the Rust exit (R6.4.2;
// spec/trunk.md, "Observation"; the Go exit's TestATestersStreamAndFlow…
// in observe_linux_test.go). The relay is the brain's process here: the
// exit tells the brain each connection it opens to the relay (its local
// port, session and stream), the brain marks the one the relay admitted a
// tester's key on, and both ends report it at the mark and at its end under
// the same id; only the exit's reports carry the tag. A stream nobody
// marked is reported by no one.

func nextLocal(t *testing.T, c chan ExitLocal, open bool, kind trunk.ObsKind) ExitLocal {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case l := <-c:
			if l.Open == open && l.Kind == kind {
				return l
			}
		case <-deadline:
			t.Fatalf("the exit told no %v connection open=%v", kind, open)
			return ExitLocal{}
		}
	}
}

func nextExitReport(t *testing.T, c chan trunk.Report, what string) trunk.Report {
	t.Helper()
	select {
	case r := <-c:
		return r
	case <-time.After(10 * time.Second):
		t.Fatalf("no %s report from the exit", what)
		return trunk.Report{}
	}
}

func TestATestersStreamAndFlowAreReportedByTheRustExitAndThePipeUnderOneID(t *testing.T) {
	locals := make(chan ExitLocal, 64)
	exitSeen := make(chan trunk.Report, 16)
	x, err := StartExit(ExitConfig{Bin: exitBin(t), Args: []string{"--flow-idle-ms", exitIdle}, Stderr: os.Stderr, Logf: t.Logf,
		Local: func(l ExitLocal) { locals <- l }, Observe: func(r trunk.Report) { exitSeen <- r }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { x.Close() })
	wc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if err := x.SetWire(ExitWire{ID: dgramWire, Conn: wc, Keys: []string{testKey}}); err != nil {
		t.Fatal(err)
	}
	pl, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if err := x.SetPool(pl, 0, 0); err != nil {
		t.Fatal(err)
	}
	tcpTo, udpTo := tcpEcho(t), udpEcho(t)
	if err := x.SetPorts([]uint16{tcpTo, udpTo}); err != nil {
		t.Fatal(err)
	}

	seen := make(chan Observed, 16)
	p, err := Start(Config{Bin: pipeBin(t), Args: []string{"--flow-idle-ms", exitIdle}, Stderr: os.Stderr, Logf: t.Logf,
		OnObserved: func(o Observed) { seen <- o }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	if err := p.SetPool(Pool{ID: trunk.PoolWire, Members: 4, Exit: netip.MustParseAddrPort(pl.Addr().String())}); err != nil {
		t.Fatal(err)
	}
	if err := p.SetWire(Wire{ID: dgramWire, Name: "udp", Exit: wc.LocalAddr().(*net.UDPAddr).AddrPort(), Key: testKey, Members: 2}); err != nil {
		t.Fatal(err)
	}
	p.SetRoute(trunk.Route{Voice: dgramWire, Bulk: trunk.PoolWire})
	waitFor(t, 10*time.Second, "the pool's and the wire's members up", func() bool {
		return wireUp(p, trunk.PoolWire, 4) && wireUp(p, dgramWire, 2)
	})
	tl, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.TCPListen(1, tl, tcpTo); err != nil {
		t.Fatal(err)
	}
	ul, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ul.Close() })
	if err := p.Listen(1, ul, trunk.ClassVoice, udpTo, 1); err != nil {
		t.Fatal(err)
	}

	// A stream nobody marks: the exit tells its connection, nobody reports.
	plain, err := net.Dial("tcp", tl.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := echoed(plain, 64<<10, nil); err != nil {
		t.Fatal(err)
	}
	pl0 := nextLocal(t, locals, true, trunk.ObsStream)
	plain.Close()
	if l := nextLocal(t, locals, false, trunk.ObsStream); l.Port != pl0.Port || l.Stream != pl0.Stream {
		t.Fatalf("the unmarked stream's connection closed as %+v, opened as %+v", l, pl0)
	}

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
	sl := nextLocal(t, locals, true, trunk.ObsStream)
	if sl.Port == 0 || sl.Port == pl0.Port && sl.Stream == pl0.Stream {
		t.Fatalf("the tester's stream's connection %+v", sl)
	}
	id, err := x.Mark(trunk.ObsStream, sl.Session, sl.Stream, "tester-key")
	if err != nil {
		t.Fatal(err)
	}
	xm := nextExitReport(t, exitSeen, "the stream's mark")
	if xm.ID != id || xm.Kind != trunk.ObsStream || xm.Phase != trunk.PhaseMark || xm.Tag != "tester-key" || xm.Port != tcpTo ||
		xm.Up != 1<<10 || xm.Down != 1<<10 {
		t.Fatalf("the exit's mark of the stream %+v, want id %x, tag, port %d, 1 KiB each way", xm, id, tcpTo)
	}
	m := nextObserved(t, seen, "the pipe's mark of the stream")
	if r := m.Report; r.ID != id || r.Phase != trunk.PhaseMark || r.Tag != "" || !m.HaveTCP {
		t.Fatalf("the pipe's mark of the stream %+v, want id %x, no tag, its client's TCP", m, id)
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
	want := int64(1<<10 + 1<<20)
	xe := nextExitReport(t, exitSeen, "the stream's end")
	if xe.ID != id || xe.Phase != trunk.PhaseEnd || xe.End != trunk.EndFin || xe.Up != want || xe.Down != want ||
		xe.Chunks == 0 || xe.Carriers == 0 || xe.Tag != "tester-key" {
		t.Fatalf("the exit's end of the stream %+v, want %d bytes each way, chunks, carriers, fin", xe, want)
	}
	e := nextObserved(t, seen, "the pipe's end of the stream")
	if r := e.Report; r.ID != id || r.Phase != trunk.PhaseEnd || r.End != trunk.EndFin || r.Up != want || r.Down != want {
		t.Fatalf("the pipe's end of the stream %+v", e)
	}
	t.Logf("the stream at the exit: %+v", xe)

	// The tester's flow: ends unused after the exit's 500 ms.
	u, err := net.Dial("udp", ul.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	if _, err := u.Write(make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	fl := nextLocal(t, locals, true, trunk.ObsFlow)
	fid, err := x.Mark(trunk.ObsFlow, fl.Session, fl.Stream, "tester-key")
	if err != nil {
		t.Fatal(err)
	}
	if r := nextExitReport(t, exitSeen, "the flow's mark"); r.ID != fid || r.Kind != trunk.ObsFlow || r.Phase != trunk.PhaseMark || r.DgramsIn != 1 {
		t.Fatalf("the exit's mark of the flow %+v, want 1 datagram delivered", r)
	}
	if fm := nextObserved(t, seen, "the pipe's mark of the flow"); fm.Report.ID != fid || fm.Report.Kind != trunk.ObsFlow {
		t.Fatalf("the pipe's mark of the flow %+v", fm)
	}
	for i := 0; i < 4; i++ {
		_, _ = u.Write(make([]byte, 100))
		time.Sleep(20 * time.Millisecond)
	}
	fe := nextExitReport(t, exitSeen, "the flow's end")
	if fe.ID != fid || fe.Phase != trunk.PhaseEnd || fe.End != trunk.EndIdle || fe.DgramsIn != 5 || fe.DgramsOut != 5 {
		t.Fatalf("the exit's end of the flow %+v, want 5 delivered and 5 answered, ended unused", fe)
	}
	if l := nextLocal(t, locals, false, trunk.ObsFlow); l.Port != fl.Port {
		t.Fatalf("the flow's connection closed as %+v, opened as %+v", l, fl)
	}
	if pe := nextObserved(t, seen, "the pipe's end of the flow"); pe.Report.ID != fid || pe.Report.End != trunk.EndIdle {
		t.Fatalf("the pipe's end of the flow %+v", pe)
	}
	select {
	case r := <-exitSeen:
		t.Fatalf("a report more from the exit: %+v", r)
	case <-time.After(300 * time.Millisecond):
	}
}
