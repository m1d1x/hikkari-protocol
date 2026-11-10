package trunk

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// The wire of one member: a sequence of frames, both ways, over one long
// TLS + HTTP/2 CONNECT tunnel. Every integer is big-endian.
//
//	hello  1 | magic "HKT1" | session [16] | epoch [8]
//	open   2 | stream u32 | port u16
//	data   3 | stream u32 | offset u64 | n u16 | n bytes
//	ack    4 | stream u32 | received u64 | credit u64 | flags u8 (1: FIN received) | got u64
//	fin    5 | stream u32 | offset u64
//	rst    6 | stream u32
//	dgram  7 | stream u32 | seq u32 | port u16 | n u16 | n bytes
//	ping   8 | token u64
//	pong   9 | token u64
//	drain  10
//
// A stream is one client TCP connection: its bytes are numbered by offset, so
// a chunk sent again on another member lands in the same place, and an ack
// says how far the receiver has everything (received), how far the sender may
// go (credit), and which chunk it answers (got, the chunk's offset; all ones
// for none). got confirms a chunk past a hole: the member that carried it did
// its job, whatever happened to the chunk before it. A dgram is one client UDP packet with its own sequence: no
// ack, no resend, the receiver drops copies. A drain (exit to entry) says the
// exit's process is being replaced: it keeps what it has, and the entry opens
// a new session for everything new (Entry), whose members reach the new
// process.

const (
	fHello byte = 1 + iota
	fOpen
	fData
	fAck
	fFin
	fRst
	fDgram
	fPing
	fPong
	fDrain
)

const (
	magic = "HKT1"
	// MaxPayload bounds a data or dgram frame's bytes (n is u16).
	MaxPayload = 65535
	ackFin     = 1
)

// SessionID names one entry's trunk to one exit; every member of the pool
// says it in its hello, so the exit puts them in one session.
type SessionID [16]byte

// Epoch names one life of a session on the exit. An entry that sees it change
// knows the exit lost its streams (a restart) and resets its own.
type Epoch [8]byte

type frame struct {
	typ     byte
	stream  uint32
	off     uint64 // data, fin: offset; ack: received
	credit  uint64
	flags   byte
	port    uint16
	seq     uint32
	got     uint64
	token   uint64
	session SessionID
	epoch   Epoch
	payload []byte
}

func appendHello(b []byte, id SessionID, epoch Epoch) []byte {
	b = append(b, fHello)
	b = append(b, magic...)
	b = append(b, id[:]...)
	return append(b, epoch[:]...)
}

func appendOpen(b []byte, stream uint32, port uint16) []byte {
	b = append(b, fOpen)
	b = binary.BigEndian.AppendUint32(b, stream)
	return binary.BigEndian.AppendUint16(b, port)
}

func appendData(b []byte, stream uint32, off uint64, p []byte) []byte {
	b = append(b, fData)
	b = binary.BigEndian.AppendUint32(b, stream)
	b = binary.BigEndian.AppendUint64(b, off)
	b = binary.BigEndian.AppendUint16(b, uint16(len(p)))
	return append(b, p...)
}

// noGot is an ack that answers no particular chunk.
const noGot = ^uint64(0)

func appendAck(b []byte, stream uint32, received, credit uint64, flags byte, got uint64) []byte {
	b = append(b, fAck)
	b = binary.BigEndian.AppendUint32(b, stream)
	b = binary.BigEndian.AppendUint64(b, received)
	b = binary.BigEndian.AppendUint64(b, credit)
	b = append(b, flags)
	return binary.BigEndian.AppendUint64(b, got)
}

func appendFin(b []byte, stream uint32, off uint64) []byte {
	b = append(b, fFin)
	b = binary.BigEndian.AppendUint32(b, stream)
	return binary.BigEndian.AppendUint64(b, off)
}

func appendRst(b []byte, stream uint32) []byte {
	b = append(b, fRst)
	return binary.BigEndian.AppendUint32(b, stream)
}

func appendDgram(b []byte, stream, seq uint32, port uint16, p []byte) []byte {
	b = append(b, fDgram)
	b = binary.BigEndian.AppendUint32(b, stream)
	b = binary.BigEndian.AppendUint32(b, seq)
	b = binary.BigEndian.AppendUint16(b, port)
	b = binary.BigEndian.AppendUint16(b, uint16(len(p)))
	return append(b, p...)
}

func appendDrain(b []byte) []byte { return append(b, fDrain) }

func appendPing(b []byte, typ byte, token uint64) []byte {
	b = append(b, typ)
	return binary.BigEndian.AppendUint64(b, token)
}

var errMagic = errors.New("trunk: not a trunk hello")

// readFrame reads one frame. The payload is a fresh slice the caller owns.
func readFrame(r *bufio.Reader) (frame, error) {
	var f frame
	typ, err := r.ReadByte()
	if err != nil {
		return f, err
	}
	f.typ = typ
	if typ == fDrain {
		return f, nil
	}
	var head [29]byte
	need := map[byte]int{fHello: 28, fOpen: 6, fData: 14, fAck: 29, fFin: 12, fRst: 4, fDgram: 12, fPing: 8, fPong: 8}[typ]
	if need == 0 {
		return f, fmt.Errorf("trunk: unknown frame %d", typ)
	}
	if typ == fHello {
		var h [28]byte
		if _, err := io.ReadFull(r, h[:]); err != nil {
			return f, err
		}
		if string(h[:4]) != magic {
			return f, errMagic
		}
		copy(f.session[:], h[4:20])
		copy(f.epoch[:], h[20:28])
		return f, nil
	}
	if _, err := io.ReadFull(r, head[:need]); err != nil {
		return f, err
	}
	h := head[:need]
	switch typ {
	case fPing, fPong:
		f.token = binary.BigEndian.Uint64(h)
		return f, nil
	}
	f.stream = binary.BigEndian.Uint32(h)
	var n int
	switch typ {
	case fOpen:
		f.port = binary.BigEndian.Uint16(h[4:])
	case fData:
		f.off = binary.BigEndian.Uint64(h[4:])
		n = int(binary.BigEndian.Uint16(h[12:]))
	case fAck:
		f.off = binary.BigEndian.Uint64(h[4:])
		f.credit = binary.BigEndian.Uint64(h[12:])
		f.flags = h[20]
		f.got = binary.BigEndian.Uint64(h[21:])
	case fFin:
		f.off = binary.BigEndian.Uint64(h[4:])
	case fDgram:
		f.seq = binary.BigEndian.Uint32(h[4:])
		f.port = binary.BigEndian.Uint16(h[8:])
		n = int(binary.BigEndian.Uint16(h[10:]))
	}
	if n > 0 {
		f.payload = make([]byte, n)
		if _, err := io.ReadFull(r, f.payload); err != nil {
			return f, err
		}
	}
	return f, nil
}
