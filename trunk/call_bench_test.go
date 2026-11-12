package trunk

import (
	"encoding/binary"
	"testing"
	"time"
)

// benchCall is a call in its steady state: a minute and its grace of
// datagrams sent every 20 ms, each answered 45 ms later, as on the entry.
func benchCall(b *testing.B) (*call, time.Time, uint64) {
	cfg := CallConfig{Copies: 1}.withDefaults()
	start := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	c := newCall(cfg, start)
	now := start
	var seq uint64
	p := make([]byte, 8)
	for i := 0; i < 4000; i++ {
		seq++
		c.sent(seq, now, nil)
		binary.BigEndian.PutUint64(p, seq)
		c.answerAt(now.Add(45*time.Millisecond), p)
		c.due(now)
		now = now.Add(cfg.Every)
	}
	return c, now, seq
}

// BenchmarkCallTick: one tick of the call's sender, its send noted and the
// windows due taken, with a full window outstanding.
func BenchmarkCallTick(b *testing.B) {
	c, now, seq := benchCall(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		seq++
		c.sent(seq, now, nil)
		c.due(now)
		now = now.Add(c.cfg.Every)
	}
}

// BenchmarkCallAnswer: one answer taken back.
func BenchmarkCallAnswer(b *testing.B) {
	c, now, seq := benchCall(b)
	p := make([]byte, 8)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		seq++
		c.sent(seq, now, nil)
		binary.BigEndian.PutUint64(p, seq)
		b.StartTimer()
		c.answerAt(now.Add(45*time.Millisecond), p)
		b.StopTimer()
		c.due(now)
		now = now.Add(c.cfg.Every)
		b.StartTimer()
	}
}
