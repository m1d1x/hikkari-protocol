package trunk

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Dial opens one member to the exit from the given local port, with the
// tunnel ready to carry frames (TLS, HTTP/2 CONNECT answered).
type Dial func(ctx context.Context, localPort int) (io.ReadWriteCloser, error)

// Entry keeps an entry's pool: Members members up at all times, each on a
// source port the path has not killed before.
//
// # Generations
//
// When the exit says it drains (its process is being replaced without a cut,
// fDrain), the entry opens a new session, with a new id and a full pool of its
// own, whose members reach the exit's new process; every new stream and flow
// goes there (Session) once a quarter of its pool is up (takeOver), or after
// TakeOverLimit: until then the old session takes them, as the exit's old
// process still serves, and nothing new waits for a pool that is not there.
// The old session then is retired: it keeps the members it has, replaces
// none, and is closed when it carries nothing more or after RetireLimit. Its
// members ending is what lets the exit's old process go.
//
// An entry whose own process is being replaced (Retire) retires its current
// session too, and opens none after it: an fDrain from the exit then changes
// nothing, since a process that takes no new clients has no use for a pool.
type Entry struct {
	cfg     Config
	members int
	dial    Dial
	ports   *PortBook
	logf    func(string, ...any)
	spread  time.Duration
	// wires are the wires besides the pool (AddWire); every generation
	// keeps members of each.
	wires []Wire

	mu      sync.Mutex
	cur     *generation
	run     context.Context
	slots   sync.WaitGroup
	retired []*generation
	next    *generation // drained: comes up, then takes over from cur
	leaving bool        // Retire: no new generation, ever
	route   Route       // every generation's, the next one's too
}

// generation is one session of the entry and its pool.
type generation struct {
	s       *Session
	id      SessionID
	retired atomic.Bool
	handing atomic.Bool // the exit drains it: its slots replace no member
	since   time.Time   // when it was retired

	mu    sync.Mutex
	epoch Epoch
	known bool

	// runs are its wires' slots, under the entry's mu: a wire changed or
	// taken away (SetWires) has its run cancelled, which closes its members.
	runs map[WireID]*wireRun
}

type wireRun struct {
	w      Wire
	cancel context.CancelFunc
}

// TakeOverLimit is how long a new session waits for a quarter of its pool
// before it takes over anyway.
var TakeOverLimit = 10 * time.Second

// takeOverEvery is how often a new session's pool is looked at.
var takeOverEvery = 10 * time.Millisecond

// RetireLimit closes a retired session that still carries something: the
// exit's old process gives up its sessions after as long (edge handoff.go).
var RetireLimit = 30 * time.Minute

// retireEvery is how often retired sessions are looked at.
var retireEvery = 5 * time.Second

// NewEntry makes an entry for members members. logf gets one line per
// member that could not come up or died, one per epoch of the exit (the
// first, and every change: the exit restarted and the streams were reset),
// one per drain of the exit, and one per pause of the entry itself (the box
// did not run it); no client data in any.
func NewEntry(cfg Config, members int, dial Dial, ports *PortBook, logf func(string, ...any)) (*Entry, error) {
	if members < 1 {
		return nil, errors.New("trunk: an entry needs at least one member")
	}
	e := &Entry{cfg: cfg, members: members, dial: dial, ports: ports, logf: logf, spread: replaceSpread, route: AnyRoute}
	g, err := e.newGeneration()
	if err != nil {
		return nil, err
	}
	e.cur = g
	return e, nil
}

// AddWire adds a wire besides the pool (wires.go), before Run. Its id must
// be neither the pool's nor AnyWire, and one wire per id.
func (e *Entry) AddWire(w Wire) error {
	if w.ID == PoolWire || w.ID == AnyWire {
		return fmt.Errorf("trunk: wire %q: id %d is reserved", w.Name, w.ID)
	}
	if w.Members < 1 || w.Dial == nil {
		return fmt.Errorf("trunk: wire %q needs a dial and at least one member", w.Name)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.run != nil {
		return fmt.Errorf("trunk: wire %q: the entry runs already", w.Name)
	}
	for _, o := range e.wires {
		if o.ID == w.ID {
			return fmt.Errorf("trunk: wire %q: id %d is %q's", w.Name, w.ID, o.Name)
		}
	}
	if w.Ports == nil {
		w.Ports = e.ports
	}
	e.wires = append(e.wires, w)
	return nil
}

// SetRoute says which wire each class goes on, for the sessions up now and
// the ones to come.
func (e *Entry) SetRoute(r Route) {
	e.mu.Lock()
	e.route = r
	all := e.allLocked()
	e.mu.Unlock()
	for _, g := range all {
		g.s.SetRoute(r)
	}
}

// Wires is what the current session sees of each wire.
func (e *Entry) Wires() map[WireID]WireState { return e.Session().Wires() }

// poolWire is the pool as a Wire.
func (e *Entry) poolWire() Wire {
	return Wire{ID: PoolWire, Name: "pool", Shape: "browser", Members: e.members, Dial: e.dial, Ports: e.ports, Streams: true}
}

func (e *Entry) newGeneration() (*generation, error) {
	g := &generation{s: newSession(e.cfg, nil), runs: map[WireID]*wireRun{}}
	g.s.route = e.route
	if _, err := rand.Read(g.id[:]); err != nil {
		return nil, err
	}
	g.s.onPause = func(d time.Duration) { e.logf("trunk: paused %s", d.Round(time.Millisecond)) }
	g.s.onDrain = func() { e.drained(g) }
	go g.s.clock()
	return g, nil
}

// Session is where new clients' connections and datagrams go: the current
// generation's. Ask for each new connection or flow; one that started on a
// retired session stays there.
func (e *Entry) Session() *Session {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cur.s
}

// Retired is how many retired sessions still carry something.
func (e *Entry) Retired() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.retired)
}

// Retire makes the current session a retired one, for an entry whose own
// process is being replaced: it keeps what it carries and the members it has,
// replaces none, and closes when it carries nothing more or after
// RetireLimit; no new session follows, not even on the exit's fDrain. Session
// still answers with it, for what a client already started there.
func (e *Entry) Retire() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.leaving {
		return
	}
	e.leaving = true
	g := e.cur
	if g.retired.Load() {
		return
	}
	g.retired.Store(true)
	g.since = time.Now()
	e.retired = append(e.retired, g)
}

// Carrying is what all the entry's sessions carry now, the current one and
// the retired ones: open streams and clients' datagram flows.
func (e *Entry) Carrying() (streams, flows int) {
	e.mu.Lock()
	all := e.allLocked()
	e.mu.Unlock()
	for _, g := range all {
		st := g.s.Stats()
		streams += st.Streams
		flows += st.Flows
	}
	return streams, flows
}

// allLocked is every session the entry has not closed, each once.
func (e *Entry) allLocked() []*generation {
	all := append([]*generation(nil), e.retired...)
	for _, g := range []*generation{e.cur, e.next} {
		if g == nil {
			continue
		}
		dup := false
		for _, r := range all {
			dup = dup || r == g
		}
		if !dup {
			all = append(all, g)
		}
	}
	return all
}

// Ports is the entry's book of source ports.
func (e *Entry) Ports() *PortBook { return e.ports }

// Run keeps the pool up until ctx ends, then closes the sessions, and says
// what was cut with them.
func (e *Entry) Run(ctx context.Context) {
	e.mu.Lock()
	e.run = ctx
	g := e.cur
	e.startLocked(g)
	e.mu.Unlock()
	t := time.NewTicker(retireEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			e.mu.Lock()
			all := e.allLocked()
			e.mu.Unlock()
			streams, flows := 0, 0
			for _, g := range all {
				st := g.s.Stats()
				streams += st.Streams
				flows += st.Flows
				g.s.Close()
			}
			if streams > 0 || flows > 0 {
				e.logf("trunk: closed with %d stream(s) and %d flow(s) cut", streams, flows)
			}
			e.slots.Wait()
			return
		case <-t.C:
			e.closeRetired(false)
		}
	}
}

func (e *Entry) startLocked(g *generation) {
	for _, w := range append([]Wire{e.poolWire()}, e.wires...) {
		e.startWireLocked(g, w)
	}
}

// startWireLocked starts w's slots in g, under a context of their own.
func (e *Entry) startWireLocked(g *generation, w Wire) {
	ctx, cancel := context.WithCancel(e.run)
	g.runs[w.ID] = &wireRun{w: w, cancel: cancel}
	for i := 0; i < w.Members; i++ {
		e.slots.Add(1)
		go func() { defer e.slots.Done(); e.slot(ctx, g, w, i) }()
	}
}

// SetWires makes ws the wires besides the pool, while the entry runs: a
// new wire comes up, a wire gone has its members closed (what they carried
// goes again on the others), a wire changed (members, shape, form or Knobs)
// is closed and comes up anew. Only the current session and the one coming
// up open members; retired ones lose a wire gone and get none new. The hub
// changes a wire's knobs this way, without a new process (stage plan, шаг 6).
func (e *Entry) SetWires(ws []Wire) error {
	seen := map[WireID]bool{}
	for i := range ws {
		w := &ws[i]
		if w.ID == PoolWire || w.ID == AnyWire || seen[w.ID] {
			return fmt.Errorf("trunk: wire %q: id %d reserved or twice", w.Name, w.ID)
		}
		if w.Members < 1 || w.Dial == nil {
			return fmt.Errorf("trunk: wire %q needs a dial and at least one member", w.Name)
		}
		seen[w.ID] = true
		if w.Ports == nil {
			w.Ports = e.ports
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.wires = append([]Wire(nil), ws...)
	if e.run == nil {
		return nil
	}
	want := map[WireID]Wire{}
	for _, w := range ws {
		want[w.ID] = w
	}
	for _, g := range e.allLocked() {
		live := g == e.cur || g == e.next
		for id, r := range g.runs {
			if id == PoolWire {
				continue
			}
			if w, ok := want[id]; !ok || !sameWire(w, r.w) {
				r.cancel()
				delete(g.runs, id)
			}
		}
		if !live || g.retired.Load() || g.handing.Load() {
			continue
		}
		for _, w := range ws {
			if g.runs[w.ID] == nil {
				e.startWireLocked(g, w)
			}
		}
	}
	return nil
}

// sameWire says a running wire needs no restart for w.
func sameWire(a, b Wire) bool {
	return a.Name == b.Name && a.Shape == b.Shape && a.Members == b.Members && a.Streams == b.Streams && a.Packet == b.Packet && a.Knobs == b.Knobs
}

// drained answers the exit's fDrain on g: a new generation comes up, takes
// everything new once it can carry it (takeOver), and g retires. A retired
// g, the entry's own included (Retire), opens nothing: it takes nothing new.
func (e *Entry) drained(g *generation) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if g != e.cur || e.next != nil || e.leaving || g.retired.Load() || g.handing.Load() || e.run == nil || e.run.Err() != nil {
		return
	}
	next, err := e.newGeneration()
	if err != nil {
		e.logf("trunk: exit drains, no new session: %v", err)
		return
	}
	// g's members reach the exit's old process; one that dies now would
	// come back at the new one under g's id, so none is replaced.
	g.handing.Store(true)
	e.next = next
	e.startLocked(next)
	go e.takeOver(e.run, g, next)
}

// takeOver makes next the current session once a quarter of its pool is
// up, or after TakeOverLimit, and retires g. An entry that retires in the
// meantime (Retire) keeps g and lets next go.
func (e *Entry) takeOver(ctx context.Context, g, next *generation) {
	want := (e.members + 3) / 4
	started := time.Now()
	t := time.NewTicker(takeOverEvery)
	defer t.Stop()
	for next.s.Stats().Members < want && time.Since(started) < TakeOverLimit {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		e.mu.Lock()
		leaving := e.leaving
		e.mu.Unlock()
		if leaving {
			break
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.next != next {
		return
	}
	e.next = nil
	if e.leaving {
		next.retired.Store(true)
		next.since = time.Now()
		e.retired = append(e.retired, next)
		return
	}
	if !g.retired.Load() {
		g.retired.Store(true)
		g.since = time.Now()
		e.retired = append(e.retired, g)
	}
	e.cur = next
	up := next.s.Stats().Members
	if up < want {
		e.logf("trunk: exit drains: the new session has %d of %d member(s) after %s, it takes over anyway", up, e.members, TakeOverLimit)
	}
	st := g.s.Stats()
	e.logf("trunk: exit drains: new session, the old one keeps %d stream(s) and %d flow(s)", st.Streams, st.Flows)
}

// closeRetired closes the retired sessions that carry nothing or have
// outlived RetireLimit.
func (e *Entry) closeRetired(force bool) {
	e.mu.Lock()
	keep := e.retired[:0]
	var done []*generation
	for _, g := range e.retired {
		if force || !g.s.Busy() || time.Since(g.since) > RetireLimit {
			done = append(done, g)
		} else {
			keep = append(keep, g)
		}
	}
	e.retired = keep
	e.mu.Unlock()
	for _, g := range done {
		if st := g.s.Stats(); st.Streams > 0 || st.Flows > 0 {
			e.logf("trunk: retired session closed after %s with %d stream(s) and %d flow(s)", RetireLimit, st.Streams, st.Flows)
		}
		g.s.Close()
	}
}

// replaceSpread spreads the dials that replace dead members: members that
// die together come back one by one, not as one burst of new flows from one
// address in one second.
var replaceSpread = time.Second

func (e *Entry) slot(ctx context.Context, g *generation, w Wire, n int) {
	name := fmt.Sprintf("member %d", n)
	if w.ID != PoolWire {
		name = fmt.Sprintf("%s member %d", w.Name, n)
	}
	backoff := time.Duration(0)
	stalls := 0 // in a row
	replace := false
	for ctx.Err() == nil && !g.retired.Load() && !g.handing.Load() {
		wait := backoff
		if replace && e.spread > 0 {
			r, _ := rand.Int(rand.Reader, big.NewInt(int64(e.spread)))
			wait += time.Duration(r.Int64())
		}
		if wait > 0 {
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return
			}
			if g.retired.Load() || g.handing.Load() {
				return
			}
		}
		grow := func() {
			if backoff == 0 {
				backoff = 200 * time.Millisecond
			} else if backoff < 5*time.Second {
				backoff *= 2
			}
		}
		port, release, err := w.Ports.Take()
		if err != nil {
			e.logf("trunk: %s: %v", name, err)
			grow()
			continue
		}
		conn, err := w.Dial(ctx, port)
		if err != nil {
			release()
			if errors.Is(err, syscall.EADDRINUSE) {
				continue // that port is someone else's: another one, now
			}
			if errors.Is(err, ErrSilent) {
				w.Ports.Dead(port)
			}
			e.logf("trunk: %s: dial: %v", name, err)
			grow()
			continue
		}
		epoch, r, err := exchangeHello(conn, g.id, e.cfg.Observe != nil, w.kind())
		if err != nil {
			conn.Close()
			release()
			if errors.Is(err, ErrSilent) {
				w.Ports.Dead(port)
			}
			e.logf("trunk: %s: hello: %v", name, err)
			grow()
			continue
		}
		g.mu.Lock()
		switch {
		case !g.known:
			e.logf("trunk: exit epoch %x", epoch[:])
		case epoch != g.epoch:
			// The exit restarted: what it held of our streams is gone.
			e.logf("trunk: exit epoch %x after %x: streams reset", epoch[:], g.epoch[:])
			g.s.Reset()
		}
		g.epoch, g.known = epoch, true
		g.mu.Unlock()
		started := time.Now()
		// A wire taken away (SetWires) closes its members.
		unhook := context.AfterFunc(ctx, func() { conn.Close() })
		err = g.s.serve(conn, r, w.kind(), nil)
		unhook()
		release()
		replace = true
		if err != nil && ctx.Err() == nil && !g.retired.Load() && !g.handing.Load() {
			e.logf("trunk: %s: down after %s: %v", name, time.Since(started).Round(time.Second), err)
		}
		switch {
		case errors.Is(err, ErrStalled):
			// The path killed the flow, not the exit: the port is to
			// blame, another one goes up now. Many in a row is the path
			// itself, and then the slot waits like any other failure.
			w.Ports.Dead(port)
			if stalls++; stalls > 3 {
				grow()
			} else {
				backoff = 0
			}
		case time.Since(started) < 5*time.Second:
			stalls = 0
			grow()
		default:
			stalls, backoff = 0, 0
		}
	}
}

// ErrSilent is a dial or hello that got no answer in time: what a killed
// flow looks like from its end.
var ErrSilent = errors.New("trunk: no answer")

const helloTimeout = 5 * time.Second

// exchangeHello says the session's id and reads the exit's epoch, for a
// member of kind k (a t1 hello for the pool's, t2 for any other), and gives
// the reader the member's frames are read from after it. observe says the
// entry reads observe frames (capObserve in the epoch it sends, which is
// otherwise zero: an entry has no epoch). A packet member says its hello
// again every helloAgain until it is answered: a datagram may be lost.
func exchangeHello(conn io.ReadWriteCloser, id SessionID, observe bool, k memberKind) (Epoch, *bufio.Reader, error) {
	var epoch Epoch
	timer := time.AfterFunc(helloTimeout, func() { conn.Close() })
	defer timer.Stop()
	var caps Epoch
	if observe {
		caps[0] = capObserve
	}
	hello := appendHelloFor(nil, id, caps, k)
	if _, err := conn.Write(hello); err != nil {
		return epoch, nil, err
	}
	answered := make(chan struct{})
	defer close(answered)
	if k.packet {
		go func() {
			t := time.NewTicker(helloAgain)
			defer t.Stop()
			for {
				select {
				case <-answered:
					return
				case <-t.C:
					if _, err := conn.Write(hello); err != nil {
						return
					}
				}
			}
		}()
	}
	r := bufio.NewReaderSize(conn, 64<<10)
	f, err := readFrame(r)
	if err != nil {
		if !timer.Stop() {
			return epoch, nil, ErrSilent
		}
		return epoch, nil, err
	}
	if f.typ != fHello || f.session != id || f.kind != k {
		return epoch, nil, errMagic
	}
	return f.epoch, r, nil
}

// helloAgain is how often a packet member says its hello until answered.
var helloAgain = 250 * time.Millisecond
