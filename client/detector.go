package client

// The call detector of duplicated sessions (v1.02, v1.03; spec/v1.md
// "v1.02: duplicated UDP"): a flow is a call while its last whole second was
// voice-shaped.

import (
	"time"

	"github.com/m1d1x/hikkari-protocol/dup"
	"github.com/m1d1x/hikkari-protocol/observe"
)

// A call is a flow of small packets at a steady rate (Opus: 20 ms frames, 50
// per second, tens to a few hundred bytes). A second of it turns the call's
// carriers on; VoiceOff seconds without it turn the stream copy off.
//
// v1.02 relays see the flow whole: a flow is a call only while all of it is
// voice-shaped (at most VoiceMaxBytes on average), because such a relay sends
// every answer by every carrier. With a relay that keeps lanes (v1.03) only
// the voice-sized packets count, so a call with video in the same socket, as
// Discord and browsers send it, is still a call; its video stays on the
// datagram channel's whole lane.
const (
	VoiceMinPPS   = 15
	VoiceMaxPPS   = 120
	VoiceMaxBytes = 500
	VoiceOff      = 5 * time.Second
)

// detector tells a call from other UDP by the last whole second of packets
// the application sent.
type detector struct {
	second    time.Time // start of the current second
	packets   int
	bytes     int
	small     int // voice-sized packets
	smallLen  int // their bytes
	answers   int // packets delivered to the application in this second
	voiceTill time.Time
	// The call now, from its first voice-shaped second (v1.04).
	in                      bool
	start, last             time.Time // first and last voice-shaped second
	up, upSmall, upSmallLen int
	down                    int
	done                    observe.Calls // calls ended since the book's last take
}

// ShortCall is the shortest call a person makes: a call detected for less is
// likely something else (a game, a burst of small packets).
const ShortCall = 10 * time.Second

// add counts one packet and reports whether the flow is a call now. lanes
// counts only voice-sized packets (v1.03), otherwise the whole flow must be
// voice-shaped (v1.02).
func (t *detector) add(now time.Time, size int, lanes bool) bool {
	if t.second.IsZero() {
		t.second = now
	}
	if now.Sub(t.second) >= time.Second {
		t.settle(now)
		if now.Sub(t.second) < 2*time.Second && t.call(lanes) {
			t.voiceTill = now.Add(VoiceOff)
			if !t.in {
				// The call began with the second that showed it.
				t.in, t.start = true, t.second
				t.up, t.upSmall, t.upSmallLen, t.down = t.packets, t.small, t.smallLen, t.answers
			}
			t.last = t.second
		}
		t.second, t.packets, t.bytes, t.small, t.smallLen, t.answers = now, 0, 0, 0, 0, 0
	}
	t.packets++
	t.bytes += size
	small := dup.IsVoiceSized(size)
	if small {
		t.small++
		t.smallLen += size
	}
	if t.in {
		t.up++
		if small {
			t.upSmall++
			t.upSmallLen += size
		}
	}
	return now.Before(t.voiceTill)
}

// answer counts a packet delivered to the application during a call.
func (t *detector) answer() {
	t.answers++
	if t.in {
		t.down++
	}
}

// settle ends the call when it is over by now.
func (t *detector) settle(now time.Time) {
	if t.in && !now.Before(t.voiceTill) {
		t.finish()
	}
}

// finish ends the call now, if there is one. A call lasts from its first
// voice-shaped second to the end of its last one.
func (t *detector) finish() {
	if !t.in {
		return
	}
	c := &t.done
	t.in = false
	length := t.last.Sub(t.start) + time.Second
	secs := length.Seconds()
	c.N++
	if length < ShortCall {
		c.Short++
	}
	if t.down*3 < t.up {
		c.OneSided++
	}
	c.Seconds.Add(secs)
	c.PPSUp.Add(float64(t.up) / secs)
	c.PPSDown.Add(float64(t.down) / secs)
	if t.upSmall > 0 {
		c.BytesUp.Add(float64(t.upSmallLen) / float64(t.upSmall))
	}
	if t.up > 0 {
		c.Voice.Add(float64(t.upSmall) * 100 / float64(t.up))
	}
}

func (t *detector) call(lanes bool) bool {
	if lanes {
		return t.small >= VoiceMinPPS && t.small <= VoiceMaxPPS
	}
	return t.packets >= VoiceMinPPS && t.packets <= VoiceMaxPPS && t.bytes <= VoiceMaxBytes*t.packets
}

// on reports whether the flow is a call at now.
func (t *detector) on(now time.Time) bool { return now.Before(t.voiceTill) }
