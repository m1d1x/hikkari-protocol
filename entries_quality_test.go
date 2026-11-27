package hikkari_test

// The best entry (v1.08, spec/v1.md "Moving to a better entry") through a
// real relay and real carriers: entry 0 turns slow the way aezamsk1 did on
// 26.11, nothing lost and a share of everything late, and the client moves
// new connections to entry 1 while a call goes on.

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/client"
	M "github.com/sagernet/sing/common/metadata"
)

func TestASlowEntryGivesWayToTheOtherUnderACall(t *testing.T) {
	if testing.Short() {
		t.Skip("minutes of pings")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := newEntriesStand(t, ctx, [2]string{"127.0.0.1:0", "127.0.0.1:0"})
	defer func() {
		if t.Failed() {
			s.log.dump(t)
		}
	}()
	time.Sleep(time.Second)
	if s.client.Active() != 0 {
		t.Fatalf("active entry %d before entry 0 turned slow, want 0", s.client.Active())
	}
	conn, err := s.client.ListenPacket(ctx, M.Socksaddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	const callFor = 4 * time.Minute
	type callResult struct {
		got, dups int
		worst     time.Duration
	}
	callDone := make(chan callResult, 1)
	go func() {
		got, dups, worst := callStats(conn, s.udpEcho.LocalAddr(), int(callFor/(20*time.Millisecond)), 160, 20*time.Millisecond)
		callDone <- callResult{got, dups, worst}
	}()

	s.entries[0].slow.Store(true)
	took, ok := waitActive(s.client, 1, 3*time.Minute)
	if !ok {
		t.Fatalf("the client stayed on the slow entry for %v", took)
	}
	// New TCP goes by entry 1 now.
	before := s.entries[1].conns.Load()
	fresh, err := s.client.DialContext(ctx, "tcp", M.ParseSocksaddr(s.tcpEcho))
	if err != nil {
		t.Fatal(err)
	}
	_ = fresh.SetDeadline(time.Now().Add(5 * time.Second))
	echo := make([]byte, 1024)
	if _, err := fresh.Write(echo); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(fresh, echo); err != nil {
		t.Fatalf("new TCP after the move got no echo: %v", err)
	}
	fresh.Close()
	if s.entries[1].conns.Load() <= before {
		t.Errorf("new TCP did not go by entry 1 after the move")
	}
	// It stays there while entry 0 is slow.
	if back, ok := waitActive(s.client, 0, 30*time.Second); ok {
		t.Errorf("the client went back to the slow entry %v after it left", back)
	}
	call := <-callDone

	p := s.book.Take()[client.Group]
	if p == nil || p.Entries["0"] == nil || p.Entries["1"] == nil {
		t.Fatalf("no entries in the period: %+v", p)
	}
	e0, e1 := p.Entries["0"], p.Entries["1"]
	t.Logf("moved %v after entry 0 turned slow; call %d echoed, longest pause %v", took.Round(time.Second), call.got, call.worst.Round(time.Millisecond))
	t.Logf("entry 0: pings %d, late %d, score p50 %.0f ms, datagram ping p50 %.1f ms; entry 1: pings %d, late %d, score p50 %.0f ms",
		e0.Pings, e0.Late, e0.ScoreMS.Quantile(0.5), e0.DgramPingMS.Quantile(0.5), e1.Pings, e1.Late, e1.ScoreMS.Quantile(0.5))
	if e1.MovesQuality != 1 || e0.Silences != 0 || e1.Now != 1 {
		t.Errorf("period: entry 0 %+v, entry 1 %+v; want one move by quality, no silence", *e0, *e1)
	}
	if call.worst > 150*time.Millisecond {
		t.Errorf("call through the move: longest pause %v, want under 150 ms", call.worst)
	}
	if e0.DgramPingMS.Quantile(0.5) == 0 {
		t.Errorf("no answers on entry 0's datagram probe")
	}
}
