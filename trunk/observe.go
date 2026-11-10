package trunk

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"time"
)

// Observation of a tester's streams and flows, leg by leg
// (hikkari-client plans/2026-11-10-hikkari-observability-plan.md, этап 1б;
// owner's decision 10.11: testers are observed in full, other users not at
// all).
//
// Neither end knows whose a stream is: the client's TLS crosses the entry to
// the exit's relay. The relay knows the key, and when it is a tester's, the
// exit marks the stream (Session.Observe): it draws an observation id, reports
// the stream itself and tells the entry, which reports it too. Both ends then
// report it once more when it ends. The hub joins the ends by the id; only
// the exit's report, through its relay, can say whose it was.
//
// A stream nobody marked is never reported: the counters every stream keeps
// in memory for its own sake go nowhere.

// ObsKind tells a stream from a datagram flow.
type ObsKind byte

const (
	ObsStream ObsKind = 1
	ObsFlow   ObsKind = 2
)

func (k ObsKind) String() string {
	if k == ObsFlow {
		return "flow"
	}
	return "stream"
}

// Phases of a report.
const (
	// PhaseMark is the report at the mark: what the stream did so far.
	PhaseMark = "mark"
	// PhaseEnd is the report at its end.
	PhaseEnd = "end"
)

// Ends of a stream or flow, as a report says them.
const (
	EndFin      = "fin"       // both directions finished
	EndLocal    = "local"     // this end's local connection failed
	EndPeer     = "peer"      // the other end reset it
	EndEpoch    = "epoch"     // the exit lost its streams (a restart)
	EndSession  = "session"   // the session closed
	EndIdle     = "idle"      // a flow nobody used
	EndOpenFail = "open_fail" // the exit could not reach its port
)

// Report is what one end saw of one observed stream or flow.
type Report struct {
	ID    uint64 // the observation's, the same at both ends
	Kind  ObsKind
	Phase string
	Port  uint16
	Age   time.Duration // since this end opened it
	// Streams: bytes read from this end's local connection and sent (Up),
	// received and written to it (Down); chunks this end sent, how many of
	// them were sent again after their member died, on how many members,
	// how many members died owing its chunks, and the longest a chunk waited
	// for its confirmation.
	Up, Down       int64
	Chunks, Resent int64
	Carriers       int
	Deaths         int
	MaxWait        time.Duration
	// Flows: datagrams read from the local socket and sent (Out), received
	// and delivered (In), copies dropped.
	DgramsOut, DgramsIn, DgramsCopy int64
	End                             string // PhaseEnd only
	// Local is this end's local connection of a stream: on the entry the
	// client's, whose TCP the entry's report measures. Nil for flows.
	Local net.Conn
	// Tag is what the exit marked it with (its relay's key for it); it
	// never crosses the trunk, so the entry's reports have none.
	Tag string
}

// obsQueue bounds the reports waiting for Config.Observe; past it they are
// dropped, never the session held up.
const obsQueue = 1024

// reportLocked queues r for Config.Observe.
func (s *Session) reportLocked(r Report) {
	if s.cfg.Observe == nil {
		return
	}
	if s.reports == nil {
		s.reports = make(chan Report, obsQueue)
		go func() {
			for {
				select {
				case r := <-s.reports:
					s.cfg.Observe(r)
				case <-s.ctx.Done():
					// What was queued is still told: an end at close.
					for {
						select {
						case r := <-s.reports:
							s.cfg.Observe(r)
						default:
							return
						}
					}
				}
			}
		}()
	}
	select {
	case s.reports <- r:
	default:
		s.obsDropped.Add(1)
	}
}

func (s *Session) streamReportLocked(st *stream, phase string) Report {
	return Report{
		ID: st.obs, Kind: ObsStream, Phase: phase, Port: st.port, Age: time.Since(st.opened),
		Up: int64(st.sent), Down: int64(st.written), Chunks: st.chunks, Resent: st.resent,
		Carriers: len(st.carriers), Deaths: st.deaths, MaxWait: st.maxWait, End: st.endWhy, Local: st.local, Tag: st.tag,
	}
}

func (s *Session) flowReportLocked(f *flow, phase string) Report {
	return Report{
		ID: f.obs, Kind: ObsFlow, Phase: phase, Port: f.port, Age: time.Since(f.opened),
		DgramsOut: f.out, DgramsIn: f.in, DgramsCopy: f.copied, End: f.endWhy, Tag: f.tag,
	}
}

// Observe marks a stream or flow of this session for both ends to report,
// and returns the observation's id. tag goes into this end's reports only. Exit only: it is the end whose relay
// knows the key. A stream or flow already ended or already marked is not
// marked again (ok false, or its id). The entry hears of it only if its
// hello said it reads observe frames; the exit reports it either way.
func (s *Session) Observe(kind ObsKind, id uint32, tag string) (obs uint64, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.shutdown {
		return 0, false
	}
	var have *uint64
	var report func() Report
	switch kind {
	case ObsStream:
		st := s.streams[id]
		if st == nil || st.ended {
			return 0, false
		}
		have, report = &st.obs, func() Report { st.tag = tag; return s.streamReportLocked(st, PhaseMark) }
	case ObsFlow:
		f := s.flows[id]
		if f == nil || f.ended {
			return 0, false
		}
		have, report = &f.obs, func() Report { f.tag = tag; return s.flowReportLocked(f, PhaseMark) }
	default:
		return 0, false
	}
	if *have != 0 {
		return *have, true
	}
	*have = newObsID()
	s.reportLocked(report())
	if s.peerObserve {
		// On two members, as a reset goes: one that dies with it would
		// leave the entry blind to this stream for good.
		sent := 0
		for m := range s.members {
			m.send(appendObserve(nil, kind, id, *have), true)
			if sent++; sent == 2 {
				break
			}
		}
	}
	return *have, true
}

// observedLocked: the exit marked one of ours (entry).
func (s *Session) observedLocked(f frame) {
	if f.token == 0 {
		return
	}
	switch ObsKind(f.flags) {
	case ObsStream:
		if st := s.streams[f.stream]; st != nil && !st.ended && st.obs == 0 {
			st.obs = f.token
			s.reportLocked(s.streamReportLocked(st, PhaseMark))
		}
	case ObsFlow:
		if fl := s.flows[f.stream]; fl != nil && !fl.ended && fl.obs == 0 {
			fl.obs = f.token
			s.reportLocked(s.flowReportLocked(fl, PhaseMark))
		}
	}
}

func newObsID() uint64 {
	var b [8]byte
	for {
		_, _ = rand.Read(b[:])
		if id := binary.BigEndian.Uint64(b[:]); id != 0 {
			return id
		}
	}
}

// Target is the stream or flow a Local dial is for: the exit's relay will
// see the dial's connection, and its key tells whether to Observe it.
type Target struct {
	Session *Session
	Kind    ObsKind
	ID      uint32
}

type targetKey struct{}

func withTarget(ctx context.Context, t Target) context.Context {
	return context.WithValue(ctx, targetKey{}, t)
}

// TargetFrom is the stream or flow a Local.DialStream or DialFlow is called
// for.
func TargetFrom(ctx context.Context) (Target, bool) {
	t, ok := ctx.Value(targetKey{}).(Target)
	return t, ok
}
