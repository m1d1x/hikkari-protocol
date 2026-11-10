package observe

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
)

// WatchQUIC adds a QUIC connection to b under group, named name ("datagram",
// "voice"), until it closes. stopping reports whether this end is shutting
// down, so a close of ours reads as EndStop and not as an error.
func WatchQUIC(b *Book, group, name string, conn *quic.Conn, stopping func() bool) {
	if b == nil || conn == nil {
		return
	}
	w := &quicWatch{conn: conn, name: name, fresh: true}
	remove := b.Add(group, w.take)
	go func() {
		<-conn.Context().Done()
		reason := QUICEnd(context.Cause(conn.Context()))
		if stopping != nil && stopping() {
			reason = EndStop
		}
		w.end.Store(&reason)
		remove()
	}()
}

type quicWatch struct {
	conn  *quic.Conn
	name  string
	fresh bool
	end   atomic.Pointer[string] // set before the last take
	last  quic.ConnectionStats
}

func (w *quicWatch) take(p *Period) {
	if p.QUIC == nil {
		p.QUIC = map[string]*QUIC{}
	}
	q := p.QUIC[w.name]
	if q == nil {
		q = &QUIC{}
		p.QUIC[w.name] = q
	}
	s := w.conn.ConnectionStats()
	q.Conns++
	if w.fresh {
		q.Opened++
		w.fresh = false
	}
	if end := w.end.Load(); end != nil {
		q.Ends.Add(*end)
	}
	out := delta(s.PacketsSent, w.last.PacketsSent)
	lost := delta(s.PacketsLost, w.last.PacketsLost)
	q.PktsOut += out
	q.PktsLost += lost
	q.BytesOut += delta(s.BytesSent, w.last.BytesSent)
	q.BytesLost += delta(s.BytesLost, w.last.BytesLost)
	if s.SmoothedRTT > 0 {
		q.RTT.Add(ms(s.SmoothedRTT))
		q.RTTMin.Add(ms(s.MinRTT))
	}
	if out > 0 {
		q.Loss.Add(float64(lost) * 1000 / float64(out))
	}
	w.last = s
}

// delta is cur - prev, 0 when a counter went down (QUIC's lost counters do,
// when a packet declared lost arrives after all).
func delta(cur, prev uint64) int64 {
	if cur < prev {
		return 0
	}
	return int64(cur - prev)
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// Ms is a duration as a Dist value.
func Ms(d time.Duration) float64 { return ms(d) }

// QUICEnd names why a QUIC connection closed.
func QUICEnd(err error) string {
	var idle *quic.IdleTimeoutError
	var hs *quic.HandshakeTimeoutError
	var app *quic.ApplicationError
	var tr *quic.TransportError
	var reset *quic.StatelessResetError
	switch {
	case err == nil, errors.Is(err, context.Canceled), errors.Is(err, net.ErrClosed):
		return EndEOF
	case errors.As(err, &idle), errors.As(err, &hs):
		return EndIdle
	case errors.As(err, &reset):
		return EndReset
	case errors.As(err, &app):
		return EndEOF
	case errors.As(err, &tr):
		if tr.Remote {
			return EndReset
		}
		return EndError
	default:
		return EndError
	}
}
