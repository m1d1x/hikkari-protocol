package observe

import (
	"sort"
	"sync"
)

// Period is what one end saw in one period, for one key on a relay or for the
// whole client. Fields a side does not count stay empty.
type Period struct {
	// TCP is the stream channel by the relay's TCP_INFO (the relay fills it,
	// the protocol has no socket of its own there).
	TCP *TCP `json:"tcp,omitempty"`
	// QUIC is the datagram channel's connections by name: "datagram" on a
	// relay; "datagram" and "voice" on a client.
	QUIC map[string]*QUIC `json:"quic,omitempty"`
	// Tunnels are the stream channel's CONNECT tunnels by how they ended.
	Tunnels *Ends `json:"tunnels,omitempty"`
	// Dup is the duplicated UDP of v1.02: the up direction on a relay, the
	// down direction on a client.
	Dup *Dup `json:"dup,omitempty"`
	// Calls are the client's call detector's calls that ended in the period.
	Calls *Calls `json:"calls,omitempty"`
}

// Ends counts ends by reason (EndEOF and the rest).
type Ends map[string]int64

// Ends of a connection, a tunnel or a session.
const (
	EndEOF     = "eof"        // the peer closed it
	EndReset   = "reset"      // reset or refused by the peer or the path
	EndIdle    = "idle"       // nothing came for the idle limit
	EndRevoked = "revoked"    // the key was taken off the roster
	EndStop    = "relay_stop" // this end stopped (shutdown, restart)
	EndGone    = "gone"       // a dup session's carriers all left
	EndError   = "error"      // anything else
)

func (e *Ends) add(reason string, n int64) {
	if *e == nil {
		*e = Ends{}
	}
	(*e)[reason] += n
}

// Add counts one end.
func (e *Ends) Add(reason string) { e.add(reason, 1) }

func (e Ends) merge(o Ends) Ends {
	for k, v := range o {
		e.add(k, v)
	}
	return e
}

// TCP is the stream channel's TCP connections in a period, sampled by the
// relay. RTT is the kernel's smoothed estimate in ms, Retrans the segments
// sent again per 1000 sent in the period, both one value per connection per
// sample.
type TCP struct {
	Conns    int64 `json:"conns"`     // connections seen in the period
	Opened   int64 `json:"opened"`    // of them new
	Ended    int64 `json:"ended"`     // of them closed
	BytesOut int64 `json:"bytes_out"` // acked by the client
	BytesIn  int64 `json:"bytes_in"`
	SegsOut  int64 `json:"segs_out"`
	Retrans  int64 `json:"retrans"` // segments sent again
	RTT      Dist  `json:"rtt"`
	RTTVar   Dist  `json:"rttvar"`
	Share    Dist  `json:"retrans_pm"`
	Cwnd     Dist  `json:"cwnd"`
}

func (t *TCP) merge(o *TCP) {
	t.Conns += o.Conns
	t.Opened += o.Opened
	t.Ended += o.Ended
	t.BytesOut += o.BytesOut
	t.BytesIn += o.BytesIn
	t.SegsOut += o.SegsOut
	t.Retrans += o.Retrans
	t.RTT.Merge(&o.RTT)
	t.RTTVar.Merge(&o.RTTVar)
	t.Share.Merge(&o.Share)
	t.Cwnd.Merge(&o.Cwnd)
}

// QUIC is one kind of QUIC connection in a period.
type QUIC struct {
	Conns     int64 `json:"conns"`
	Opened    int64 `json:"opened"`
	Ends      Ends  `json:"ends,omitempty"`
	PktsOut   int64 `json:"pkts_out"`
	PktsLost  int64 `json:"pkts_lost"`
	BytesOut  int64 `json:"bytes_out"`
	BytesLost int64 `json:"bytes_lost"`
	// RTT is the smoothed RTT, RTTMin the path's minimum, in ms, one value per
	// connection per sample; Loss the packets lost per 1000 sent in the
	// period, per connection that sent any.
	RTT    Dist `json:"rtt"`
	RTTMin Dist `json:"rtt_min"`
	Loss   Dist `json:"loss_pm"`
}

func (q *QUIC) merge(o *QUIC) {
	q.Conns += o.Conns
	q.Opened += o.Opened
	q.Ends = q.Ends.merge(o.Ends)
	q.PktsOut += o.PktsOut
	q.PktsLost += o.PktsLost
	q.BytesOut += o.BytesOut
	q.BytesLost += o.BytesLost
	q.RTT.Merge(&o.RTT)
	q.RTTMin.Merge(&o.RTTMin)
	q.Loss.Merge(&o.Loss)
}

// Dup is one direction of duplicated sessions in a period. A packet is
// settled once its number leaves the dup window: then it is known which
// carriers brought it.
type Dup struct {
	Sessions int64 `json:"sessions"` // sessions seen in the period
	Opened   int64 `json:"opened"`
	Ends     Ends  `json:"ends,omitempty"`
	Fresh    int64 `json:"fresh"` // packets delivered
	// FirstDatagram and FirstStream: which channel brought the delivered copy.
	FirstDatagram int64 `json:"first_dgram"`
	FirstStream   int64 `json:"first_stream"`
	// Settled packets by the carriers that brought them: OnlyStream is a
	// packet the stream copy saved (or carried alone while the datagram
	// channel was down).
	OnlyDatagram int64 `json:"only_dgram"`
	OnlyStream   int64 `json:"only_stream"`
	Both         int64 `json:"both"`
	// Late are copies that came after their number left the window.
	Late int64 `json:"late"`
	// FullDatagram and FullStream are copies this end never sent: the
	// carrier's queue had no room, its channel was behind (v1.04, the sending
	// side's count; the far end sees them as only_stream or missing).
	FullDatagram int64 `json:"full_dgram,omitempty"`
	FullStream   int64 `json:"full_stream,omitempty"`
	// LeadDatagram and LeadStream: by how many ms the first copy beat the
	// second, by the first copy's channel.
	LeadDatagram Dist `json:"lead_dgram"`
	LeadStream   Dist `json:"lead_stream"`
}

func (d *Dup) merge(o *Dup) {
	d.Sessions += o.Sessions
	d.Opened += o.Opened
	d.Ends = d.Ends.merge(o.Ends)
	d.Fresh += o.Fresh
	d.FirstDatagram += o.FirstDatagram
	d.FirstStream += o.FirstStream
	d.OnlyDatagram += o.OnlyDatagram
	d.OnlyStream += o.OnlyStream
	d.Both += o.Both
	d.Late += o.Late
	d.FullDatagram += o.FullDatagram
	d.FullStream += o.FullStream
	d.LeadDatagram.Merge(&o.LeadDatagram)
	d.LeadStream.Merge(&o.LeadStream)
}

// Calls are the call detector's calls that ended in a period.
type Calls struct {
	N int64 `json:"n"`
	// Short are calls under ShortCall, OneSided calls whose answers were
	// under a third of what was sent: likely not calls (a game, a burst).
	Short    int64 `json:"short"`
	OneSided int64 `json:"one_sided"`
	Seconds  Dist  `json:"seconds"`
	PPSUp    Dist  `json:"pps_up"`
	PPSDown  Dist  `json:"pps_down"`
	BytesUp  Dist  `json:"bytes_mean"`  // mean voice-sized payload sent
	Voice    Dist  `json:"voice_share"` // voice-sized share of what was sent, per cent
}

// Merge adds o's calls.
func (c *Calls) Merge(o *Calls) {
	c.N += o.N
	c.Short += o.Short
	c.OneSided += o.OneSided
	c.Seconds.Merge(&o.Seconds)
	c.PPSUp.Merge(&o.PPSUp)
	c.PPSDown.Merge(&o.PPSDown)
	c.BytesUp.Merge(&o.BytesUp)
	c.Voice.Merge(&o.Voice)
}

func (p *Period) merge(o *Period) {
	if o.TCP != nil {
		if p.TCP == nil {
			p.TCP = &TCP{}
		}
		p.TCP.merge(o.TCP)
	}
	for name, q := range o.QUIC {
		if p.QUIC == nil {
			p.QUIC = map[string]*QUIC{}
		}
		if p.QUIC[name] == nil {
			p.QUIC[name] = &QUIC{}
		}
		p.QUIC[name].merge(q)
	}
	if o.Tunnels != nil {
		if p.Tunnels == nil {
			p.Tunnels = &Ends{}
		}
		*p.Tunnels = p.Tunnels.merge(*o.Tunnels)
	}
	if o.Dup != nil {
		if p.Dup == nil {
			p.Dup = &Dup{}
		}
		p.Dup.merge(o.Dup)
	}
	if o.Calls != nil {
		if p.Calls == nil {
			p.Calls = &Calls{}
		}
		p.Calls.Merge(o.Calls)
	}
}

// Empty reports whether the period counted nothing.
func (p *Period) Empty() bool {
	return p.TCP == nil && len(p.QUIC) == 0 && p.Tunnels == nil && p.Dup == nil && p.Calls == nil
}

// A Source adds what it counted since its last take to p. It is called with
// the Book's lock held and must not call the Book.
type Source func(p *Period)

// Book gathers the sources of one end by group (an access key on a relay, one
// group on a client) and hands out their periods.
type Book struct {
	mu      sync.Mutex
	sources map[*source]struct{}
	left    map[string]*Period // what removed sources counted since the last take
}

type source struct {
	group string
	take  Source
}

// NewBook returns an empty book.
func NewBook() *Book {
	return &Book{sources: map[*source]struct{}{}, left: map[string]*Period{}}
}

// Add registers take under group. remove takes one last time and forgets it;
// call it once, when what it counts has ended.
func (b *Book) Add(group string, take Source) (remove func()) {
	if b == nil {
		return func() {}
	}
	s := &source{group: group, take: take}
	b.mu.Lock()
	b.sources[s] = struct{}{}
	b.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			delete(b.sources, s)
			p := b.left[group]
			if p == nil {
				p = &Period{}
				b.left[group] = p
			}
			s.take(p)
		})
	}
}

// Record adds a one-off count, such as a tunnel's end, to group's period.
func (b *Book) Record(group string, f func(p *Period)) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	p := b.left[group]
	if p == nil {
		p = &Period{}
		b.left[group] = p
	}
	f(p)
}

// Take hands out each group's period since the last Take and starts the next.
// Groups that counted nothing are left out.
func (b *Book) Take() map[string]*Period {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	out := b.left
	b.left = map[string]*Period{}
	for s := range b.sources {
		p := out[s.group]
		if p == nil {
			p = &Period{}
			out[s.group] = p
		}
		s.take(p)
	}
	for group, p := range out {
		if p.Empty() {
			delete(out, group)
		}
	}
	return out
}

// Merge sums periods into one, as a relay's total over its keys.
func Merge(periods map[string]*Period) *Period {
	keys := make([]string, 0, len(periods))
	for k := range periods {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	total := &Period{}
	for _, k := range keys {
		total.merge(periods[k])
	}
	return total
}
