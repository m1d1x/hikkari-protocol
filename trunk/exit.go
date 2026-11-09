package trunk

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"sync"
	"time"
)

// Exit holds the sessions of every entry that reaches this exit, one per
// entry, its members joining it by the session id in their hello.
type Exit struct {
	cfg   Config
	local Local

	mu       sync.Mutex
	sessions map[SessionID]*exitSession
}

type exitSession struct {
	s     *Session
	epoch Epoch
}

// SessionIdle ends an exit's session that has had no member this long: the
// entry is gone, and so are its clients.
const SessionIdle = 2 * time.Minute

// NewExit makes an exit whose streams and flows reach local.
func NewExit(cfg Config, local Local) *Exit {
	return &Exit{cfg: cfg, local: local, sessions: map[SessionID]*exitSession{}}
}

// ServeMember reads conn's hello, answers with the session's epoch and
// carries the member until it dies.
func (x *Exit) ServeMember(conn io.ReadWriteCloser) error {
	timer := time.AfterFunc(helloTimeout, func() { conn.Close() })
	var b [29]byte
	_, err := io.ReadFull(conn, b[:])
	if !timer.Stop() {
		return ErrSilent
	}
	if err != nil {
		conn.Close()
		return err
	}
	if b[0] != fHello || string(b[1:5]) != magic {
		conn.Close()
		return errMagic
	}
	id := SessionID(b[5:21])
	x.mu.Lock()
	es := x.sessions[id]
	if es == nil {
		es = &exitSession{s: NewSession(x.cfg, x.local)}
		if _, err := rand.Read(es.epoch[:]); err != nil {
			x.mu.Unlock()
			conn.Close()
			return err
		}
		x.sessions[id] = es
	}
	x.mu.Unlock()
	if _, err := conn.Write(appendHello(nil, id, es.epoch)); err != nil {
		conn.Close()
		return err
	}
	err = es.s.Serve(conn)
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return err
}

// Run ends sessions left without members until ctx ends, then all of them.
func (x *Exit) Run(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			x.mu.Lock()
			for id, es := range x.sessions {
				es.s.Close()
				delete(x.sessions, id)
			}
			x.mu.Unlock()
			return
		case <-t.C:
			x.mu.Lock()
			for id, es := range x.sessions {
				if es.s.IdleFor() > SessionIdle {
					es.s.Close()
					delete(x.sessions, id)
				}
			}
			x.mu.Unlock()
		}
	}
}

// Stats sums the counters of the sessions up now.
func (x *Exit) Stats() (sessions int, total Stats) {
	x.mu.Lock()
	list := make([]*Session, 0, len(x.sessions))
	for _, es := range x.sessions {
		list = append(list, es.s)
	}
	x.mu.Unlock()
	for _, s := range list {
		total = total.add(s.Stats())
	}
	return len(list), total
}

func (a Stats) add(b Stats) Stats {
	a.Members += b.Members
	a.MembersJoined += b.MembersJoined
	a.MembersStall += b.MembersStall
	a.MembersBroken += b.MembersBroken
	a.Resent += b.Resent
	a.Streams += b.Streams
	a.StreamsOpened += b.StreamsOpened
	a.StreamsReset += b.StreamsReset
	a.Up += b.Up
	a.Down += b.Down
	a.Flows += b.Flows
	a.DgramsOut += b.DgramsOut
	a.DgramsIn += b.DgramsIn
	a.DgramsCopy += b.DgramsCopy
	return a
}
