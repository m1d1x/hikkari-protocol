package datagram

import (
	"sync"
	"time"
)

// Ceiling is a relay's limit on one access key's datagrams down, shared by
// every datagram connection of the key (v1.05). Over it a frame waits in its
// connection's scheduler, where it ages and is counted stale like any other:
// one key's bulk over UDP without a controller of its own takes no more than
// its ceiling of the relay. A token bucket of reservations: a sender takes
// the bytes it sends at once and waits for the debt it made.
type Ceiling struct {
	mu   sync.Mutex
	rate float64 // bytes a second; 0: none
	have float64 // bytes; below 0 a debt
	at   time.Time
}

// ceilingBurst is how much of the ceiling may go at once.
const ceilingBurst = 20 * time.Millisecond

// NewCeiling is a ceiling of bitsPerSecond; 0 or less is none.
func NewCeiling(bitsPerSecond int64) *Ceiling {
	c := &Ceiling{}
	c.SetRate(bitsPerSecond)
	return c
}

// SetRate changes the ceiling now; 0 or less lifts it.
func (c *Ceiling) SetRate(bitsPerSecond int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rate = max(0, float64(bitsPerSecond)/8)
	c.have, c.at = 0, time.Time{}
}

// take reserves n bytes and says how long the sender must wait for them.
func (c *Ceiling) take(n int) time.Duration {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rate <= 0 {
		return 0
	}
	now := time.Now()
	if !c.at.IsZero() {
		c.have = min(c.rate*ceilingBurst.Seconds(), c.have+c.rate*now.Sub(c.at).Seconds())
	}
	c.at = now
	c.have -= float64(n)
	if c.have >= 0 {
		return 0
	}
	return time.Duration(-c.have / c.rate * float64(time.Second))
}
