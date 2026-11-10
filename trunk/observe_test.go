package trunk

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// targetLocal is the exit's relay that tells which stream or flow each of
// its connections is for, as the edge's registry learns it.
type targetLocal struct {
	*loopLocal
	targets chan Target
}

func (l *targetLocal) DialStream(ctx context.Context, port uint16) (net.Conn, error) {
	if t, ok := TargetFrom(ctx); ok {
		l.targets <- t
	}
	return l.loopLocal.DialStream(ctx, port)
}

func (l *targetLocal) DialFlow(ctx context.Context, port uint16) (net.Conn, error) {
	if t, ok := TargetFrom(ctx); ok {
		l.targets <- t
	}
	return l.loopLocal.DialFlow(ctx, port)
}

func reports() (chan Report, func(Report)) {
	c := make(chan Report, 64)
	return c, func(r Report) { c <- r }
}

func next(t *testing.T, c chan Report, what string) Report {
	t.Helper()
	select {
	case r := <-c:
		return r
	case <-time.After(10 * time.Second):
		t.Fatalf("no %s report", what)
		return Report{}
	}
}

func quiet(t *testing.T, c chan Report, what string) {
	t.Helper()
	select {
	case r := <-c:
		t.Fatalf("%s reported %+v", what, r)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestObserveStream: a stream the exit marks is reported by both ends under
// one id, at the mark and at the end, with the bytes each end carried; a
// stream nobody marked is reported by neither.
func TestObserveStream(t *testing.T) {
	entryR, entryObs := reports()
	exitR, exitObs := reports()
	local := &targetLocal{newLoopLocal(t, nil), make(chan Target, 8)}
	h := newHarnessLocal(t, Config{Observe: entryObs}, Config{Observe: exitObs}, 4, nil, local)

	plain := h.carry()
	roundTrip(t, plain, 64<<10)
	<-local.targets
	plain.Close()

	c := h.carry()
	roundTrip(t, c, 1<<10)
	tg := <-local.targets
	if tg.Kind != ObsStream || tg.Session == nil {
		t.Fatalf("target %+v", tg)
	}
	id, ok := tg.Session.Observe(tg.Kind, tg.ID, "tester-key")
	if !ok || id == 0 {
		t.Fatal("not marked")
	}
	if again, _ := tg.Session.Observe(tg.Kind, tg.ID, "tester-key"); again != id {
		t.Fatal("marked twice")
	}
	xm, em := next(t, exitR, "exit mark"), next(t, entryR, "entry mark")
	for _, r := range []Report{xm, em} {
		if r.ID != id || r.Phase != PhaseMark || r.Kind != ObsStream || r.Port != 443 {
			t.Fatalf("mark %+v, id %x", r, id)
		}
	}
	if xm.Tag != "tester-key" || em.Tag != "" {
		t.Fatalf("tags: exit %q entry %q (the entry must not learn it)", xm.Tag, em.Tag)
	}
	if em.Up != 1<<10 || em.Local == nil {
		t.Fatalf("entry mark carried %d up, local %v", em.Up, em.Local)
	}
	roundTrip(t, c, 1<<20)
	c.Close()
	xe, ee := next(t, exitR, "exit end"), next(t, entryR, "entry end")
	for _, r := range []Report{xe, ee} {
		if r.ID != id || r.Phase != PhaseEnd || r.End == "" {
			t.Fatalf("end %+v", r)
		}
	}
	want := int64(1<<10 + 1<<20)
	if ee.Up != want || xe.Down != want || ee.Chunks == 0 || ee.Carriers == 0 {
		t.Fatalf("entry up %d chunks %d carriers %d, exit down %d, want %d", ee.Up, ee.Chunks, ee.Carriers, xe.Down, want)
	}
	quiet(t, entryR, "the unmarked stream, entry")
	quiet(t, exitR, "the unmarked stream, exit")
}

// TestObserveFlow: a marked flow reports datagrams at both ends, and its end
// when the session closes.
func TestObserveFlow(t *testing.T) {
	entryR, entryObs := reports()
	exitR, exitObs := reports()
	local := &targetLocal{newLoopLocal(t, nil), make(chan Target, 8)}
	h := newHarnessLocal(t, Config{Observe: entryObs}, Config{Observe: exitObs}, 4, nil, local)
	got := make(chan []byte, 64)
	f := h.entry.Session().OpenFlowCopies(443, 1, func(p []byte) { got <- p }, nil)
	f.Send([]byte("hello"))
	<-got
	tg := <-local.targets
	if tg.Kind != ObsFlow {
		t.Fatalf("target %+v", tg)
	}
	id, _ := tg.Session.Observe(tg.Kind, tg.ID, "tester-key")
	xm, em := next(t, exitR, "exit mark"), next(t, entryR, "entry mark")
	if xm.ID != id || em.ID != id || em.Kind != ObsFlow || em.DgramsOut != 1 || em.DgramsIn != 1 || xm.DgramsIn != 1 {
		t.Fatalf("marks: exit %+v entry %+v", xm, em)
	}
	for i := 0; i < 9; i++ {
		f.Send([]byte("voice"))
		<-got
	}
	h.cancel()
	ee := next(t, entryR, "entry end")
	if ee.ID != id || ee.Phase != PhaseEnd || ee.DgramsOut != 10 || ee.DgramsIn != 10 || ee.End != EndSession {
		t.Fatalf("entry end %+v", ee)
	}
}

// TestObserveOldEntry: an entry whose hello does not say it reads observe
// frames never gets one; the exit still reports its own end.
func TestObserveOldEntry(t *testing.T) {
	exitR, exitObs := reports()
	local := &targetLocal{newLoopLocal(t, nil), make(chan Target, 8)}
	h := newHarnessLocal(t, Config{}, Config{Observe: exitObs}, 2, nil, local)
	c := h.carry()
	roundTrip(t, c, 1<<10)
	tg := <-local.targets
	tg.Session.mu.Lock()
	peer := tg.Session.peerObserve
	tg.Session.mu.Unlock()
	if peer {
		t.Fatal("an entry without Observe said it reads observe frames")
	}
	if _, ok := tg.Session.Observe(tg.Kind, tg.ID, "tester-key"); !ok {
		t.Fatal("not marked")
	}
	next(t, exitR, "exit mark")
	roundTrip(t, c, 1<<10) // the session lives on: no unknown frame reached the entry
	c.Close()
	next(t, exitR, "exit end")
}

var _ io.Closer = (*closer)(nil)
