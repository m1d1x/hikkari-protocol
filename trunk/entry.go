package trunk

import (
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

	mu      sync.Mutex
	cur     *generation
	run     context.Context
	slots   sync.WaitGroup
	retired []*generation
	next    *generation // drained: comes up, then takes over from cur
	leaving bool        // Retire: no new generation, ever
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
	e := &Entry{cfg: cfg, members: members, dial: dial, ports: ports, logf: logf, spread: replaceSpread}
	g, err := e.newGeneration()
	if err != nil {
		return nil, err
	}
	e.cur = g
	return e, nil
}

func (e *Entry) newGeneration() (*generation, error) {
	g := &generation{s: newSession(e.cfg, nil)}
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
	for i := 0; i < e.members; i++ {
		e.slots.Add(1)
		go func() { defer e.slots.Done(); e.slot(e.run, g, i) }()
	}
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

func (e *Entry) slot(ctx context.Context, g *generation, n int) {
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
		port, release := e.ports.Take()
		conn, err := e.dial(ctx, port)
		if err != nil {
			release()
			if errors.Is(err, syscall.EADDRINUSE) {
				continue // that port is someone else's: another one, now
			}
			if errors.Is(err, ErrSilent) {
				e.ports.Dead(port)
			}
			e.logf("trunk: member %d: dial: %v", n, err)
			grow()
			continue
		}
		epoch, err := exchangeHello(conn, g.id, e.cfg.Observe != nil)
		if err != nil {
			conn.Close()
			release()
			if errors.Is(err, ErrSilent) {
				e.ports.Dead(port)
			}
			e.logf("trunk: member %d: hello: %v", n, err)
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
		err = g.s.Serve(conn)
		release()
		replace = true
		if err != nil && ctx.Err() == nil && !g.retired.Load() && !g.handing.Load() {
			e.logf("trunk: member %d: down after %s: %v", n, time.Since(started).Round(time.Second), err)
		}
		switch {
		case errors.Is(err, ErrStalled):
			// The path killed the flow, not the exit: the port is to
			// blame, another one goes up now. Many in a row is the path
			// itself, and then the slot waits like any other failure.
			e.ports.Dead(port)
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

// exchangeHello says the session's id and reads the exit's epoch.
// observe says the entry reads observe frames (capObserve in the epoch it
// sends, which is otherwise zero: an entry has no epoch).
func exchangeHello(conn io.ReadWriteCloser, id SessionID, observe bool) (Epoch, error) {
	var epoch Epoch
	timer := time.AfterFunc(helloTimeout, func() { conn.Close() })
	defer timer.Stop()
	var caps Epoch
	if observe {
		caps[0] = capObserve
	}
	if _, err := conn.Write(appendHello(nil, id, caps)); err != nil {
		return epoch, err
	}
	var b [29]byte
	if _, err := io.ReadFull(conn, b[:]); err != nil {
		if !timer.Stop() {
			return epoch, ErrSilent
		}
		return epoch, err
	}
	if b[0] != fHello || string(b[1:5]) != magic || [16]byte(b[5:21]) != id {
		return epoch, errMagic
	}
	copy(epoch[:], b[21:29])
	return epoch, nil
}

// PortBook hands out source ports for members and remembers the ones the
// path killed. A flow killed by source port dies again on that port (the
// same verdict 62 s later, plans/2026-11-02-tcp-flow-loss.md), so a dead port
// is not offered again for DeadFor.
type PortBook struct {
	lo, hi  int
	deadFor time.Duration

	mu    sync.Mutex
	dead  map[int]time.Time
	inUse map[int]bool
	kills int64
}

// DefaultDeadFor is how long a killed port stays out of use.
const DefaultDeadFor = time.Hour

// NewPortBook offers ports in [lo, hi].
func NewPortBook(lo, hi int, deadFor time.Duration) (*PortBook, error) {
	if lo < 1024 || hi > 65535 || hi-lo < 256 {
		return nil, fmt.Errorf("trunk: source ports %d-%d: need at least 256 above 1023", lo, hi)
	}
	if deadFor <= 0 {
		deadFor = DefaultDeadFor
	}
	return &PortBook{lo: lo, hi: hi, deadFor: deadFor, dead: map[int]time.Time{}, inUse: map[int]bool{}}, nil
}

// Take picks a port neither dead nor in use; release gives it back.
func (b *PortBook) Take() (int, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	for port, at := range b.dead {
		if now.Sub(at) > b.deadFor {
			delete(b.dead, port)
		}
	}
	span := int64(b.hi - b.lo + 1)
	for {
		n, _ := rand.Int(rand.Reader, big.NewInt(span))
		port := b.lo + int(n.Int64())
		if _, d := b.dead[port]; d || b.inUse[port] {
			continue
		}
		b.inUse[port] = true
		var once sync.Once
		return port, func() {
			once.Do(func() { b.mu.Lock(); delete(b.inUse, port); b.mu.Unlock() })
		}
	}
}

// Dead marks a port the path killed.
func (b *PortBook) Dead(port int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.dead[port] = time.Now()
	b.kills++
}

// Counts says how many ports are out of use now and how many kills it saw.
func (b *PortBook) Counts() (dead int, kills int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.dead), b.kills
}
