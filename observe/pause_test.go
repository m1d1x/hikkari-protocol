package observe

import (
	"testing"
	"time"
)

// TestAPauseCountsByItsLengthAndARestDoesNot feeds one lane packets 20 ms
// apart with one pause of 400 ms and one rest of 6 s, and checks each bound.
func TestAPauseCountsByItsLengthAndARestDoesNot(t *testing.T) {
	var m PauseMeter
	at := time.Unix(1_800_000_000, 0)
	step := func(d time.Duration, stream bool) {
		at = at.Add(d)
		m.Out(at, true, stream)
	}
	m.Out(at, true, false)
	for i := 0; i < 10; i++ {
		step(20*time.Millisecond, false)
	}
	step(400*time.Millisecond, true)
	step(20*time.Millisecond, false)
	step(6*time.Second, false)
	m.In(at, false)
	var p Period
	m.Take(&p)
	v := p.Pauses.Out.Voice
	want := Gaps{Packets: 14, Over40: 1, Over60: 1, Over150: 1, Over300: 1, MSOver150: 400, Idle: 1, Stream: 1}
	if v != want {
		t.Fatalf("voice out: %+v, want %+v", v, want)
	}
	if p.Pauses.In.Video.Packets != 1 || p.Pauses.In.Video.Over40 != 0 {
		t.Fatalf("video in: %+v", p.Pauses.In.Video)
	}
	var again Period
	m.Take(&again)
	if again.Pauses != nil {
		t.Fatalf("a second take counted again: %+v", again.Pauses)
	}
}
