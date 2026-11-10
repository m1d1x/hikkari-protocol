package server

// Generations: the processes of one relay that share its UDP socket during a
// hitless rollout (hikkari-control edge/handoff.go). The newest process
// serves new connections; an older one finishes the connections it has.
//
// All of them hold the same socket (inherited, not bound again), and only one
// of them reads it at a time: the newest. A QUIC packet says whose it is:
//
//   - Initial and 0-RTT carry a connection ID the client chose: a new
//     connection, the newest process's;
//   - Handshake and short-header packets carry an ID this server issued, and
//     every ID a generation issues says which generation it is (cid[0] ^
//     cid[1], so the first byte on the wire is as random as the rest).
//
// A packet of another generation is handed to that process's mailbox, a
// unixgram socket gen-<g>.sock in the relay's runtime directory. A mailbox
// that is gone (the process finished) means the packet is ours to answer:
// quic-go tells the client with a stateless reset. Every process writes its
// answers straight into the shared socket.
//
// The cost: quic-go gets a plain net.PacketConn, not a *net.UDPConn, so no
// GSO and no ECN on this channel. It carries datagrams (voice, games); the
// volume goes over the Naive channel.

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
)

// GenerationCIDLen is the length of every connection ID a generation issues.
const GenerationCIDLen = 8

// GenerationIDs issues connection IDs that name generation gen.
type GenerationIDs struct{ Gen byte }

// GenerateConnectionID implements quic.ConnectionIDGenerator.
func (g GenerationIDs) GenerateConnectionID() (quic.ConnectionID, error) {
	var b [GenerationCIDLen]byte
	if _, err := rand.Read(b[:]); err != nil {
		return quic.ConnectionID{}, err
	}
	b[0] = b[1] ^ g.Gen
	return quic.ConnectionIDFromBytes(b[:]), nil
}

// ConnectionIDLen implements quic.ConnectionIDGenerator.
func (GenerationIDs) ConnectionIDLen() int { return GenerationCIDLen }

const (
	quicV1 = 0x00000001
	quicV2 = 0x6b3343cf
)

// packetOwner says whose a QUIC packet is: newest is a new connection's (or
// one this cannot read), otherwise gen issued its destination ID.
func packetOwner(b []byte) (gen byte, newest bool) {
	if len(b) == 0 {
		return 0, true
	}
	if b[0]&0x80 == 0 { // short header: flags, then the destination ID
		if len(b) < 1+GenerationCIDLen {
			return 0, true
		}
		return b[1] ^ b[2], false
	}
	if len(b) < 6+GenerationCIDLen {
		return 0, true
	}
	typ := b[0] >> 4 & 3
	handshake := false
	switch binary.BigEndian.Uint32(b[1:5]) {
	case quicV1:
		handshake = typ == 2
	case quicV2:
		handshake = typ == 3
	}
	if !handshake || b[5] != GenerationCIDLen {
		return 0, true
	}
	return b[6] ^ b[7], false
}

// GenerationConn is one generation's view of the shared UDP socket.
type GenerationConn struct {
	sock *net.UDPConn
	gen  byte
	dir  string
	box  *net.UnixConn // our mailbox; nil when alone (no dir)

	outMu sync.Mutex
	out   map[byte]*net.UnixConn // connected to other generations' mailboxes

	in        chan packet
	closed    chan struct{}
	closeOnce sync.Once
	draining  atomic.Bool
	successor atomic.Int32 // generation that takes new connections, -1 none
	deadline  atomic.Pointer[time.Time]
}

type packet struct {
	b    []byte
	from netip.AddrPort
}

const maxPacket = 1500 + 100

var packetPool = sync.Pool{New: func() any { b := make([]byte, maxPacket); return &b }}

// MailboxPath is generation gen's mailbox in dir.
func MailboxPath(dir string, gen byte) string {
	return filepath.Join(dir, fmt.Sprintf("gen-%d.sock", gen))
}

// NewGenerationConn makes generation gen's view of sock. dir is where the
// generations' mailboxes live; empty means this process is alone and never
// hands over (the socket is read as it is).
func NewGenerationConn(sock *net.UDPConn, gen byte, dir string) (*GenerationConn, error) {
	c := &GenerationConn{sock: sock, gen: gen, dir: dir, in: make(chan packet, 1024), closed: make(chan struct{})}
	c.successor.Store(-1)
	if dir != "" {
		path := MailboxPath(dir, gen)
		_ = os.Remove(path) // a mailbox left by a crashed process of the same number
		box, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
		if err != nil {
			return nil, fmt.Errorf("generation %d mailbox: %w", gen, err)
		}
		_ = box.SetReadBuffer(4 << 20)
		c.box = box
		c.out = map[byte]*net.UnixConn{}
		go c.readMailbox()
	}
	go c.readSocket()
	return c, nil
}

// Generation is this view's generation.
func (c *GenerationConn) Generation() byte { return c.gen }

// Drain hands the socket to generation successor: this process stops reading
// it, new connections go to successor's mailbox, and our own connections'
// packets come to ours.
func (c *GenerationConn) Drain(successor byte) {
	c.successor.Store(int32(successor))
	c.draining.Store(true)
	_ = c.sock.SetReadDeadline(time.Now()) // wakes the reader, which then stops
}

func (c *GenerationConn) readSocket() {
	for !c.draining.Load() {
		bp := packetPool.Get().(*[]byte)
		n, from, err := c.sock.ReadFromUDPAddrPort(*bp)
		if err != nil {
			packetPool.Put(bp)
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue // Drain woke us; the loop condition decides
			}
			select {
			case <-c.closed:
			default:
				c.fail()
			}
			return
		}
		c.route(packet{(*bp)[:n], from})
	}
}

// route keeps p or hands it to the generation it belongs to.
func (c *GenerationConn) route(p packet) {
	if c.box != nil {
		gen, newest := packetOwner(p.b)
		target := -1
		switch {
		case newest && c.draining.Load():
			target = int(c.successor.Load())
		case !newest && gen != c.gen:
			target = int(gen)
		}
		if target >= 0 && c.hand(byte(target), p) {
			c.put(p)
			return
		}
	}
	c.deliver(p)
}

// hand writes p into generation gen's mailbox: the source address, then the
// packet. False when there is no such mailbox.
func (c *GenerationConn) hand(gen byte, p packet) bool {
	var buf [maxPacket + 19]byte
	addr, _ := p.from.MarshalBinary()
	buf[0] = byte(len(addr))
	n := 1 + copy(buf[1:], addr)
	n += copy(buf[n:], p.b)
	c.outMu.Lock()
	defer c.outMu.Unlock()
	out := c.out[gen]
	if out == nil {
		var err error
		if out, err = net.DialUnix("unixgram", nil, &net.UnixAddr{Name: MailboxPath(c.dir, gen), Net: "unixgram"}); err != nil {
			return false
		}
		_ = out.SetWriteBuffer(4 << 20)
		c.out[gen] = out
	}
	if _, err := out.Write(buf[:n]); err != nil {
		// The generation is gone (or its mailbox is full, which a dropped
		// datagram would also be): this packet is ours to answer.
		_ = out.Close()
		delete(c.out, gen)
		return false
	}
	return true
}

func (c *GenerationConn) readMailbox() {
	var buf [maxPacket + 19]byte
	for {
		n, _, err := c.box.ReadFromUnix(buf[:])
		if err != nil {
			return
		}
		if n < 1 || n < 1+int(buf[0]) {
			continue
		}
		var from netip.AddrPort
		if from.UnmarshalBinary(buf[1:1+int(buf[0])]) != nil {
			continue
		}
		bp := packetPool.Get().(*[]byte)
		m := copy(*bp, buf[1+int(buf[0]):n])
		// Handed packets are ours: never handed on again, so no loops.
		c.deliver(packet{(*bp)[:m], from})
	}
}

func (c *GenerationConn) deliver(p packet) {
	select {
	case c.in <- p:
	case <-c.closed:
		c.put(p)
	default:
		c.put(p) // quic-go is behind: a dropped datagram, as the socket would
	}
}

func (c *GenerationConn) put(p packet) {
	b := p.b[:cap(p.b)]
	packetPool.Put(&b)
}

func (c *GenerationConn) fail() { c.Close() }

var errDeadline = deadlineError{}

type deadlineError struct{}

func (deadlineError) Error() string   { return "i/o timeout" }
func (deadlineError) Timeout() bool   { return true }
func (deadlineError) Temporary() bool { return true }

// ReadFrom implements net.PacketConn.
func (c *GenerationConn) ReadFrom(b []byte) (int, net.Addr, error) {
	var timer <-chan time.Time
	if d := c.deadline.Load(); d != nil && !d.IsZero() {
		wait := time.Until(*d)
		if wait <= 0 {
			return 0, nil, errDeadline
		}
		t := time.NewTimer(wait)
		defer t.Stop()
		timer = t.C
	}
	select {
	case p := <-c.in:
		n := copy(b, p.b)
		from := net.UDPAddrFromAddrPort(p.from)
		c.put(p)
		return n, from, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case <-timer:
		return 0, nil, errDeadline
	}
}

// WriteTo implements net.PacketConn: straight into the shared socket.
func (c *GenerationConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.sock.WriteTo(b, addr)
}

// Close implements net.PacketConn: our copy of the socket and our mailbox.
func (c *GenerationConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		_ = c.sock.Close()
		if c.box != nil {
			_ = c.box.Close()
			_ = os.Remove(MailboxPath(c.dir, c.gen))
			c.outMu.Lock()
			for _, out := range c.out {
				_ = out.Close()
			}
			c.out = map[byte]*net.UnixConn{}
			c.outMu.Unlock()
		}
	})
	return nil
}

// LocalAddr implements net.PacketConn.
func (c *GenerationConn) LocalAddr() net.Addr { return c.sock.LocalAddr() }

// SetDeadline implements net.PacketConn.
func (c *GenerationConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.sock.SetWriteDeadline(t)
}

// SetReadDeadline implements net.PacketConn.
func (c *GenerationConn) SetReadDeadline(t time.Time) error {
	c.deadline.Store(&t)
	return nil
}

// SetWriteDeadline implements net.PacketConn.
func (c *GenerationConn) SetWriteDeadline(t time.Time) error { return c.sock.SetWriteDeadline(t) }

// SetReadBuffer sizes the shared socket's receive buffer.
func (c *GenerationConn) SetReadBuffer(n int) error { return c.sock.SetReadBuffer(n) }

// SetWriteBuffer sizes the shared socket's send buffer.
func (c *GenerationConn) SetWriteBuffer(n int) error { return c.sock.SetWriteBuffer(n) }
