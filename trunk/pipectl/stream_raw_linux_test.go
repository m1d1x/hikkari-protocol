package pipectl

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// What the exit answers frame by frame (R1.7): a stream member the test
// speaks for itself, on the Go exit (the reference) and the Rust exit
// alike (stream_exit_linux_test.go has the exits).

// rawMember is a stream member the test speaks for itself: frames as
// spec/trunk.md writes them, to see what the exit answers.
type rawMember struct {
	c  net.Conn
	in []byte
}

func dialRaw(t *testing.T, pool string) *rawMember {
	c, err := net.Dial("tcp", pool)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	var session [16]byte
	_, _ = rand.Read(session[:])
	hello := append([]byte{1}, "HKT1"...)
	hello = append(hello, session[:]...)
	hello = append(hello, make([]byte, 8)...)
	m := &rawMember{c: c}
	m.send(t, hello)
	if f := m.next(t); f[0] != 1 {
		t.Fatalf("the exit's first frame is %d, want its hello", f[0])
	}
	return m
}

func (m *rawMember) send(t *testing.T, frames ...[]byte) {
	for _, f := range frames {
		if _, err := m.c.Write(f); err != nil {
			t.Fatal(err)
		}
	}
}

// frame lengths by type, past the type byte: hello t1, open, ack, fin,
// rst, dgram (head), ping, pong; data is 14 and its n bytes.
func rawLen(p []byte) int {
	be := binary.BigEndian
	switch p[0] {
	case 1:
		if len(p) >= 5 && string(p[1:5]) == "HKT2" {
			return 31
		}
		return 29
	case 2:
		return 7
	case 3:
		if len(p) < 15 {
			return 1 << 30
		}
		return 15 + int(be.Uint16(p[13:]))
	case 4:
		return 30
	case 5:
		return 13
	case 6:
		return 5
	case 8, 9:
		return 9
	}
	return 1
}

// next is the exit's next frame, pongs answered by none (the test is done
// long before a ping is owed).
func (m *rawMember) next(t *testing.T) []byte {
	_ = m.c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64<<10)
	for {
		if len(m.in) > 0 {
			if n := rawLen(m.in); n <= len(m.in) {
				f := m.in[:n:n]
				m.in = m.in[n:]
				return f
			}
		}
		n, err := m.c.Read(buf)
		if err != nil {
			t.Fatalf("the exit's next frame: %v", err)
		}
		m.in = append(m.in, buf[:n]...)
	}
}

// echo is what the exit sends back on stream id up to its FIN: chunks in
// any order put by their offsets, the FIN wherever it comes (the Go exit
// sends it urgent, ahead of chunks still queued). A reset fails the test.
func (m *rawMember) echo(t *testing.T, id uint32) []byte {
	var got []byte
	fin := -1
	for fin < 0 || len(got) < fin {
		f := m.next(t)
		if len(f) < 5 || binary.BigEndian.Uint32(f[1:]) != id {
			continue
		}
		switch f[0] {
		case 3:
			off := int(binary.BigEndian.Uint64(f[5:]))
			if end := off + len(f) - 15; end > len(got) {
				got = append(got, make([]byte, end-len(got))...)
			}
			copy(got[off:], f[15:])
		case 5:
			fin = int(binary.BigEndian.Uint64(f[5:]))
		case 6:
			t.Fatalf("stream %d was reset", id)
		}
	}
	return got
}

func rawOpen(id uint32, port uint16) []byte {
	b := binary.BigEndian.AppendUint32([]byte{2}, id)
	return binary.BigEndian.AppendUint16(b, port)
}

func rawData(id uint32, off uint64, p []byte) []byte {
	b := binary.BigEndian.AppendUint32([]byte{3}, id)
	b = binary.BigEndian.AppendUint64(b, off)
	b = binary.BigEndian.AppendUint16(b, uint16(len(p)))
	return append(b, p...)
}

func rawFin(id uint32, off uint64) []byte {
	b := binary.BigEndian.AppendUint32([]byte{5}, id)
	return binary.BigEndian.AppendUint64(b, off)
}

// TestAChunkBeforeItsOpenIsHeld: a stream's chunk and FIN come before its
// open (another member carried the open and is slow): the exit holds them,
// and with the open the stream gets them in order; the echo comes back
// whole with its FIN.
func TestAChunkBeforeItsOpenIsHeld(t *testing.T) {
	onEachStreamExit(t, func(t *testing.T, mk func(*testing.T, context.Context, ...uint16) *streamExit) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		echo := tcpEcho(t)
		x := mk(t, ctx, echo)
		m := dialRaw(t, x.pool)
		m.send(t, rawData(1, 5, []byte(" world")), rawFin(1, 11), rawData(1, 0, []byte("hello")), rawOpen(1, echo))
		got := m.echo(t, 1)
		if string(got) != "hello world" {
			t.Errorf("echo %q, want %q", got, "hello world")
		}
		if x.rust != nil {
			tk := x.rust.fresh()
			if tk.Early != 3 || tk.EarlyDropped != 0 {
				t.Errorf("rust exit held %d early frames, dropped %d; want 3, 0", tk.Early, tk.EarlyDropped)
			}
		}
	})
}

// TestAStreamToAShutPortIsReset: an open to a port that refuses (on the
// Rust exit also one not open to the trunk) is reset back to the entry,
// and the next stream to the open port goes.
func TestAStreamToAShutPortIsReset(t *testing.T) {
	onEachStreamExit(t, func(t *testing.T, mk func(*testing.T, context.Context, ...uint16) *streamExit) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		echo := tcpEcho(t)
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		shut := uint16(l.Addr().(*net.TCPAddr).Port)
		l.Close()
		x := mk(t, ctx, echo)
		m := dialRaw(t, x.pool)
		m.send(t, rawOpen(1, shut), rawData(1, 0, []byte("x")))
		for {
			f := m.next(t)
			if f[0] == 6 {
				if id := binary.BigEndian.Uint32(f[1:]); id != 1 {
					t.Fatalf("reset of stream %d, want 1", id)
				}
				break
			}
		}
		m.send(t, rawOpen(2, echo), rawData(2, 0, []byte("ok")), rawFin(2, 2))
		got := m.echo(t, 2)
		if string(got) != "ok" {
			t.Errorf("stream 2 echoed %q", got)
		}
		_, reset, _ := x.stats()
		if reset != 1 {
			t.Errorf("exit reset %d streams, want 1", reset)
		}
		if x.rust != nil {
			if tk := x.rust.fresh(); tk.RefusedStreams != 1 {
				t.Errorf("rust exit refused %d opens, want 1", tk.RefusedStreams)
			}
		}
	})
}
