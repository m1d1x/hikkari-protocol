// Package dup is the duplicated UDP association of Hikkari v1.02: one UDP
// flow carried by both channels at once, so a call does not stall when one of
// them does.
//
//	client ─┬─ datagram channel: one QUIC DATAGRAM per frame ─┬─ relay: one session,
//	        └─ stream channel: CONNECT Host, length-prefixed ─┘  one exit socket
//
// Every packet is numbered per direction; each end delivers the first copy of
// a number and drops the rest. The relay keeps one exit socket per session, so
// the far end sees one address whichever channel a packet came by, and a
// carrier that dies and comes back (a new QUIC connection after a network
// change) re-attaches to the same socket.
//
// A frame:
//
//	version  uint8   1
//	kind     uint8   0 packet, 1 attach
//	session  [16]byte, random, chosen by the client
//	seq      uint64  big endian, from 1 per direction; 0 in an attach
//	address  SOCKS address and port (packet only): the destination going up,
//	         the source coming down
//	payload  the rest (packet only)
//	lane     uint8 (attach only, v1.03, optional): which packets the carrier
//	         takes, LaneAll when absent
//
// v1.03 lanes: a carrier attaches to the lane of every packet (LaneAll) or to
// the voice lane, which takes only packets of at most VoicePacketMax bytes, so
// a call's voice never waits behind its own video or anyone's bulk. A relay
// that knows lanes answers every attach with an attach naming the carrier's
// lane; a v1.02 relay never sends an attach, and v1.02 ends ignore the lane
// byte, so the frame keeps version 1.
//
// On the datagram channel a frame is one UDP message addressed to Host; on the
// stream channel frames follow a CONNECT to Host:0, each after a uint16 big
// endian length.
package dup

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// Host is the magic destination of a carrier on either channel.
const Host = "dup.hikkari.arpa"

// Version is the frame version this package speaks.
const Version = 1

const (
	KindPacket uint8 = 0
	KindAttach uint8 = 1
)

// Lanes of a carrier (v1.03).
const (
	LaneAll   uint8 = 0
	LaneVoice uint8 = 1
)

// VoicePacketMax is the largest UDP payload the voice lane takes. A voice
// frame (Opus in RTP and SRTP) is 60 to 300 bytes; a video packet fills the
// path MTU, about 1100 to 1200 bytes.
const VoicePacketMax = 400

// IsVoiceSized reports whether a payload of n bytes belongs to the voice lane.
func IsVoiceSized(n int) bool { return n <= VoicePacketMax }

// headerLen is version, kind, session and seq.
const headerLen = 1 + 1 + 16 + 8

// MaxFrame bounds one frame: a UDP payload plus the header and the longest
// address. The stream channel's uint16 length holds it.
const MaxFrame = 65535

// Session names one duplicated association.
type Session [16]byte

// Frame is one decoded frame. Payload aliases the decoded buffer.
type Frame struct {
	Kind    uint8
	Session Session
	Seq     uint64
	Addr    M.Socksaddr
	Payload []byte
	// Lane is the carrier's lane in an attach (v1.03).
	Lane uint8
}

var (
	ErrVersion = errors.New("dup: unknown frame version")
	ErrFrame   = errors.New("dup: malformed frame")
)

// HostAddr is Host as a destination.
func HostAddr() M.Socksaddr { return M.ParseSocksaddrHostPort(Host, 0) }

// IsHost reports whether a CONNECT target or a datagram destination names a
// carrier.
func IsHost(host string) bool { return host == Host }

// Append encodes f after dst.
func Append(dst []byte, f Frame) ([]byte, error) {
	dst = append(dst, Version, f.Kind)
	dst = append(dst, f.Session[:]...)
	dst = binary.BigEndian.AppendUint64(dst, f.Seq)
	if f.Kind == KindAttach {
		return append(dst, f.Lane), nil
	}
	b := buf.NewSize(M.SocksaddrSerializer.AddrPortLen(f.Addr))
	defer b.Release()
	if err := M.SocksaddrSerializer.WriteAddrPort(b, f.Addr); err != nil {
		return nil, err
	}
	dst = append(dst, b.Bytes()...)
	dst = append(dst, f.Payload...)
	if len(dst) > MaxFrame {
		return nil, ErrFrame
	}
	return dst, nil
}

// Decode reads one frame from data; Payload aliases data.
func Decode(data []byte) (Frame, error) {
	var f Frame
	if len(data) < headerLen {
		return f, ErrFrame
	}
	if data[0] != Version {
		return f, ErrVersion
	}
	f.Kind = data[1]
	copy(f.Session[:], data[2:18])
	f.Seq = binary.BigEndian.Uint64(data[18:26])
	rest := data[headerLen:]
	switch f.Kind {
	case KindAttach:
		if len(rest) > 0 {
			f.Lane = rest[0]
		}
		return f, nil
	case KindPacket:
		if f.Seq == 0 {
			return f, ErrFrame
		}
		r := bytes.NewReader(rest)
		addr, err := M.SocksaddrSerializer.ReadAddrPort(r)
		if err != nil {
			return f, ErrFrame
		}
		f.Addr = addr
		f.Payload = rest[len(rest)-r.Len():]
		return f, nil
	default:
		return f, ErrFrame
	}
}

// WriteStream writes one length-prefixed frame to a stream carrier.
func WriteStream(w io.Writer, frame []byte) error {
	if len(frame) > MaxFrame {
		return ErrFrame
	}
	out := make([]byte, 2+len(frame))
	binary.BigEndian.PutUint16(out, uint16(len(frame)))
	copy(out[2:], frame)
	_, err := w.Write(out)
	return err
}

// ReadStream reads one length-prefixed frame into b (at least MaxFrame long)
// and returns it.
func ReadStream(r io.Reader, b []byte) ([]byte, error) {
	var size [2]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(size[:]))
	if n > len(b) {
		return nil, ErrFrame
	}
	if _, err := io.ReadFull(r, b[:n]); err != nil {
		return nil, err
	}
	return b[:n], nil
}

// WindowSize is how far behind the newest number a copy still counts: 1024
// packets is 20 s of a 50 pps call, longer than any stream channel stall a
// call would sit through.
const WindowSize = 1024

// Window accepts each sequence number once. Not safe for concurrent use.
type Window struct {
	top  uint64
	bits [WindowSize / 64]uint64
}

// Accept reports whether seq is new: not seen, and not older than the window.
func (w *Window) Accept(seq uint64) bool {
	if seq == 0 {
		return false
	}
	if seq > w.top {
		shift := seq - w.top
		if shift >= WindowSize {
			w.bits = [WindowSize / 64]uint64{}
		} else {
			for i := w.top + 1; i <= seq; i++ {
				w.clear(i)
			}
		}
		w.top = seq
		w.set(seq)
		return true
	}
	if w.top-seq >= WindowSize {
		return false
	}
	if w.has(seq) {
		return false
	}
	w.set(seq)
	return true
}

func (w *Window) slot(seq uint64) (int, uint64) {
	i := seq % WindowSize
	return int(i / 64), 1 << (i % 64)
}
func (w *Window) set(seq uint64)      { i, m := w.slot(seq); w.bits[i] |= m }
func (w *Window) clear(seq uint64)    { i, m := w.slot(seq); w.bits[i] &^= m }
func (w *Window) has(seq uint64) bool { i, m := w.slot(seq); return w.bits[i]&m != 0 }
