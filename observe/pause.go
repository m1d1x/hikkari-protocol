package observe

import "time"

// Pauses of live UDP (v1.06, spec/v1.md): what a call hears is not how many
// packets came but whether they came on time. Each end of a duplicated
// session counts the pauses between packets of one lane at two points: where
// packets enter the tunnel at this end (In: from the application on a client,
// from the service on a relay) and where they leave it (Out: to the
// application on a client, to the service on a relay). The far end's In is
// this end's Out of the same packets, so a pause one end hands out that the
// other did not take in was made on the way: the application's own silences
// are at both points and cancel.
type Pauses struct {
	In  Lanes `json:"in"`
	Out Lanes `json:"out"`
}

// Lanes splits a point's pauses by the v1.03 lane: voice-sized packets and
// the rest (video, screen share).
type Lanes struct {
	Voice Gaps `json:"voice"`
	Video Gaps `json:"video"`
}

// Gaps are the pauses of one lane at one point in a period. A pause is the
// time from one packet of the lane to the next; one longer than PauseIdle is
// a lane at rest (a muted voice, a stopped share), not a pause, and counts
// only in Idle.
type Gaps struct {
	Packets  int64 `json:"packets"`
	Over40   int64 `json:"over40"`
	Over60   int64 `json:"over60"`
	Over150  int64 `json:"over150"`
	Over300  int64 `json:"over300"`
	Over1000 int64 `json:"over1000"`
	// MSOver150 is the length of the pauses over 150 ms put together.
	MSOver150 int64 `json:"ms_over150"`
	Idle      int64 `json:"idle,omitempty"`
	// Stream are pauses over 60 ms that a copy by the stream channel ended:
	// the datagram channel was behind or down, and TCP held the packet.
	Stream int64 `json:"stream,omitempty"`
}

// PauseIdle is the longest pause counted as one; a lane quiet for longer is
// at rest.
const PauseIdle = 5 * time.Second

func (g *Gaps) merge(o *Gaps) {
	g.Packets += o.Packets
	g.Over40 += o.Over40
	g.Over60 += o.Over60
	g.Over150 += o.Over150
	g.Over300 += o.Over300
	g.Over1000 += o.Over1000
	g.MSOver150 += o.MSOver150
	g.Idle += o.Idle
	g.Stream += o.Stream
}

func (l *Lanes) merge(o *Lanes) {
	l.Voice.merge(&o.Voice)
	l.Video.merge(&o.Video)
}

func (p *Pauses) merge(o *Pauses) {
	p.In.merge(&o.In)
	p.Out.merge(&o.Out)
}

func (p *Pauses) empty() bool {
	return p.In.Voice.Packets+p.In.Video.Packets+p.Out.Voice.Packets+p.Out.Video.Packets == 0
}

// add counts a packet that came pause after the lane's previous one.
func (g *Gaps) add(pause time.Duration, first, stream bool) {
	g.Packets++
	if first {
		return
	}
	if pause > PauseIdle {
		g.Idle++
		return
	}
	ms := pause.Milliseconds()
	if ms > 40 {
		g.Over40++
	}
	if ms > 60 {
		g.Over60++
		if stream {
			g.Stream++
		}
	}
	if ms > 150 {
		g.Over150++
		g.MSOver150 += ms
	}
	if ms > 300 {
		g.Over300++
	}
	if ms > 1000 {
		g.Over1000++
	}
}

// PauseMeter counts one session's pauses. Not safe for concurrent use: the
// session's lock guards it.
type PauseMeter struct {
	in, out [2]time.Time // the last packet by lane: voice, video
	n       Pauses
}

func lane(l *Lanes, voice bool) (*Gaps, int) {
	if voice {
		return &l.Voice, 0
	}
	return &l.Video, 1
}

// In counts a packet entering the tunnel at this end at now.
func (m *PauseMeter) In(now time.Time, voice bool) {
	g, i := lane(&m.n.In, voice)
	g.add(now.Sub(m.in[i]), m.in[i].IsZero(), false)
	m.in[i] = now
}

// Out counts a packet this end hands out at now; stream says the stream
// channel brought it.
func (m *PauseMeter) Out(now time.Time, voice, stream bool) {
	g, i := lane(&m.n.Out, voice)
	g.add(now.Sub(m.out[i]), m.out[i].IsZero(), stream)
	m.out[i] = now
}

// Take adds what the meter counted since the last Take to p.
func (m *PauseMeter) Take(p *Period) {
	if m.n.empty() {
		return
	}
	if p.Pauses == nil {
		p.Pauses = &Pauses{}
	}
	p.Pauses.merge(&m.n)
	m.n = Pauses{}
}
