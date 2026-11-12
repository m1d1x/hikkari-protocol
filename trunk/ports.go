package trunk

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"
)

// PortBook hands out source ports for members and remembers the ones the
// path killed. A flow killed by source port dies again on that port (the
// same verdict 62 s later, plans/2026-11-02-tcp-flow-loss.md), so a dead port
// is not offered again for DeadFor.
//
// Members die about once a second on a bad hour, and in 1-3 h most of the
// range is dead (11457 of 12768 on 12.11). So every call is O(1): the free
// ports are a list, a take is one random index into it, and the dead come
// back in the order they died, from the head of a queue.
type PortBook struct {
	lo, hi  int
	deadFor time.Duration

	mu    sync.Mutex
	free  []int32 // ports neither dead nor in use, in no order
	pos   []int32 // pos[port-lo]: index in free, or -1
	inUse []bool
	until []time.Time // until[port-lo]: dead until then; zero when not dead
	queue []deadPort  // kills in time order; an entry is stale once until moved on
	head  int
	dead  int
	kills int64
	now   func() time.Time
}

type deadPort struct {
	port  int32
	until time.Time
}

// DefaultDeadFor is how long a killed port stays out of use.
const DefaultDeadFor = time.Hour

// ErrNoPorts is Take's answer when every port is dead or in use.
var ErrNoPorts = errors.New("trunk: no source port free")

// NewPortBook offers ports in [lo, hi].
func NewPortBook(lo, hi int, deadFor time.Duration) (*PortBook, error) {
	if lo < 1024 || hi > 65535 || hi-lo < 256 {
		return nil, fmt.Errorf("trunk: source ports %d-%d: need at least 256 above 1023", lo, hi)
	}
	if deadFor <= 0 {
		deadFor = DefaultDeadFor
	}
	span := hi - lo + 1
	b := &PortBook{
		lo: lo, hi: hi, deadFor: deadFor,
		free:  make([]int32, span),
		pos:   make([]int32, span),
		inUse: make([]bool, span),
		until: make([]time.Time, span),
		now:   time.Now,
	}
	for i := range span {
		b.free[i] = int32(lo + i)
		b.pos[i] = int32(i)
	}
	return b, nil
}

// Take picks a port neither dead nor in use; release gives it back. With no
// such port it says ErrNoPorts and the caller waits like on any failed dial.
func (b *PortBook) Take() (int, func(), error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.expire(b.now())
	if len(b.free) == 0 {
		return 0, nil, fmt.Errorf("%w: %d dead, %d in use", ErrNoPorts, b.dead, b.hi-b.lo+1-b.dead)
	}
	port := int(b.free[rand.IntN(len(b.free))])
	b.unfree(port)
	b.inUse[port-b.lo] = true
	var once sync.Once
	return port, func() {
		once.Do(func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			i := port - b.lo
			b.inUse[i] = false
			if b.until[i].IsZero() {
				b.addFree(port)
			}
		})
	}, nil
}

// Dead marks a port the path killed. A port killed again stays out for
// DeadFor from the last kill.
func (b *PortBook) Dead(port int) {
	if port < b.lo || port > b.hi {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	b.expire(now)
	i := port - b.lo
	if b.until[i].IsZero() {
		b.dead++
		b.unfree(port)
	}
	b.until[i] = now.Add(b.deadFor)
	b.queue = append(b.queue, deadPort{int32(port), b.until[i]})
	b.kills++
}

// Counts says how many ports are out of use now and how many kills it saw.
func (b *PortBook) Counts() (dead int, kills int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.expire(b.now())
	return b.dead, b.kills
}

// expire brings back the ports whose time is up, from the head of the queue.
func (b *PortBook) expire(now time.Time) {
	for b.head < len(b.queue) && !b.queue[b.head].until.After(now) {
		d := b.queue[b.head]
		b.head++
		i := int(d.port) - b.lo
		if !b.until[i].Equal(d.until) {
			continue // killed again later: a later entry brings it back
		}
		b.until[i] = time.Time{}
		b.dead--
		if !b.inUse[i] {
			b.addFree(int(d.port))
		}
	}
	// Drop the spent head once it is most of the queue, so the queue holds
	// about one entry per kill of the last DeadFor.
	if b.head > 1024 && b.head*2 > len(b.queue) {
		b.queue = append(b.queue[:0], b.queue[b.head:]...)
		b.head = 0
	}
}

func (b *PortBook) unfree(port int) {
	i := port - b.lo
	p := b.pos[i]
	if p < 0 {
		return
	}
	last := len(b.free) - 1
	moved := b.free[last]
	b.free[p] = moved
	b.pos[int(moved)-b.lo] = p
	b.free = b.free[:last]
	b.pos[i] = -1
}

func (b *PortBook) addFree(port int) {
	i := port - b.lo
	if b.pos[i] >= 0 {
		return
	}
	b.pos[i] = int32(len(b.free))
	b.free = append(b.free, int32(port))
}
