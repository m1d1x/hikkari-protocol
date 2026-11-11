package datagram

import (
	"context"
	"sync"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/monotime"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
)

// VoiceWindow is the least a voice connection may have in flight: two
// seconds of a call with its small video beside it (400 packets a second of
// 300 B), so a round trip that a download on the user's line has stretched
// to two seconds still carries the whole call.
const VoiceWindow congestion.ByteCount = 256 << 10

// voiceSender is BBR that never holds a call back. A call is a few kilobytes
// a second that the application paces itself. BBR sizes its window by the
// shortest round trip it saw and the rate it delivered: when the line's queue
// grows under a download, the call no longer fits that window, the rate it
// delivers falls, the window falls with it, down to four packets, and the
// call waits seconds in the queues before the connection (and the newest
// frames are lost there). Every ten seconds PROBE_RTT also cuts it to four
// packets for a round trip. The voice connection carries nothing but calls,
// so it keeps at least VoiceWindow in flight and no pacing.
type voiceSender struct {
	congestion.CongestionControlEx
}

func newVoiceSender(initialPacketSize congestion.ByteCount) *voiceSender {
	return &voiceSender{congestion_meta2.NewBbrSenderWithProfile(initialPacketSize, congestion_meta2.ProfileStandard)}
}

func (v *voiceSender) GetCongestionWindow() congestion.ByteCount {
	return max(v.CongestionControlEx.GetCongestionWindow(), VoiceWindow)
}

func (v *voiceSender) CanSend(bytesInFlight congestion.ByteCount) bool {
	return bytesInFlight < v.GetCongestionWindow()
}

func (v *voiceSender) HasPacingBudget(monotime.Time) bool { return true }

func (v *voiceSender) TimeUntilSend(congestion.ByteCount) monotime.Time { return 0 }

var voiceConns sync.Map // *quic.Conn -> struct{}

// carryVoice gives conn the voice sender, once.
func carryVoice(conn *quic.Conn) {
	if _, loaded := voiceConns.LoadOrStore(conn, struct{}{}); loaded {
		return
	}
	context.AfterFunc(conn.Context(), func() { voiceConns.Delete(conn) })
	conn.SetCongestionControl(newVoiceSender(conn.InitialPacketSize()))
}

// CarryVoice says that the QUIC connection under this association carries
// calls' voice and nothing else (v1.03 voice lane): it gets a sender that
// never holds a call back for a long round trip (voiceSender). Each end calls
// it for its own sending: the client when it opens its voice carrier, the
// relay when a carrier attaches to the voice lane.
func (c *udpPacketConn) CarryVoice() { carryVoice(c.quicConn) }

// IsVoice reports whether conn has the voice sender.
func IsVoice(conn *quic.Conn) bool {
	_, ok := voiceConns.Load(conn)
	return ok
}
