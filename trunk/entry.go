package trunk

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"syscall"
	"time"
)

// Dial opens one member to the exit from the given local port, with the
// tunnel ready to carry frames (TLS, HTTP/2 CONNECT answered).
type Dial func(ctx context.Context, localPort int) (io.ReadWriteCloser, error)

// Entry keeps an entry's pool: Members members up at all times, each on a
// source port the path has not killed before.
type Entry struct {
	s       *Session
	id      SessionID
	members int
	dial    Dial
	ports   *PortBook
	logf    func(string, ...any)
	spread  time.Duration

	mu    sync.Mutex
	epoch Epoch
	known bool
}

// NewEntry makes an entry for members members. logf gets one line per
// member that could not come up or died, one per epoch of the exit (the
// first, and every change: the exit restarted and the streams were reset),
// and one per pause of the entry itself (the box did not run it); no client
// data in any.
func NewEntry(cfg Config, members int, dial Dial, ports *PortBook, logf func(string, ...any)) (*Entry, error) {
	if members < 1 {
		return nil, errors.New("trunk: an entry needs at least one member")
	}
	e := &Entry{s: newSession(cfg, nil), members: members, dial: dial, ports: ports, logf: logf, spread: replaceSpread}
	if _, err := rand.Read(e.id[:]); err != nil {
		return nil, err
	}
	e.s.onPause = func(d time.Duration) { logf("trunk: paused %s", d.Round(time.Millisecond)) }
	go e.s.clock()
	return e, nil
}

// Session is where clients' connections and datagrams go.
func (e *Entry) Session() *Session { return e.s }

// Ports is the entry's book of source ports.
func (e *Entry) Ports() *PortBook { return e.ports }

// Run keeps the pool up until ctx ends, then closes the session.
func (e *Entry) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for i := 0; i < e.members; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); e.slot(ctx, i) }()
	}
	<-ctx.Done()
	e.s.Close()
	wg.Wait()
}

// replaceSpread spreads the dials that replace dead members: members that
// die together come back one by one, not as one burst of new flows from one
// address in one second.
var replaceSpread = time.Second

func (e *Entry) slot(ctx context.Context, n int) {
	backoff := time.Duration(0)
	stalls := 0 // in a row
	replace := false
	for ctx.Err() == nil {
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
		epoch, err := exchangeHello(conn, e.id)
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
		e.mu.Lock()
		switch {
		case !e.known:
			e.logf("trunk: exit epoch %x", epoch[:])
		case epoch != e.epoch:
			// The exit restarted: what it held of our streams is gone.
			e.logf("trunk: exit epoch %x after %x: streams reset", epoch[:], e.epoch[:])
			e.s.Reset()
		}
		e.epoch, e.known = epoch, true
		e.mu.Unlock()
		started := time.Now()
		err = e.s.Serve(conn)
		release()
		replace = true
		if err != nil && ctx.Err() == nil {
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
func exchangeHello(conn io.ReadWriteCloser, id SessionID) (Epoch, error) {
	var epoch Epoch
	timer := time.AfterFunc(helloTimeout, func() { conn.Close() })
	defer timer.Stop()
	if _, err := conn.Write(appendHello(nil, id, Epoch{})); err != nil {
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
