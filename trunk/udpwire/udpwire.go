// Package udpwire is the trunk's bare UDP wire (hikkari-client
// plans/2026-11-11-trunk-wires-stage4.md): packet members over one
// encrypted datagram each way, and nothing else. It is the stand's `udp`
// (hikkari-control edge/wirestand.go), the wire that had no red minute of
// its call in the bench hour of 11.11, and it carries no streams: no
// congestion control, no order (trunk.Wire with Packet and without Streams).
//
// A datagram is a 12-byte random nonce and, sealed with AES-256-GCM, the
// frames of one write of the member. The key is derived from the trunk key
// both ends already hold, so the wire adds no secret to deploy. What an
// observer sees is random bytes of the frames' sizes between two addresses.
//
// A forged or foreign datagram does not open; the exit answers nothing to
// it. A copy of a recorded datagram does open: the trunk drops copies of
// datagrams by their sequence and copies of a hello create no session that
// is not there already, and the exit's answers go only to the address that
// sent them, which learns nothing it cannot read.
package udpwire

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// MaxDatagram bounds a datagram on the wire: the IPv4 UDP payload limit.
// A write that would seal to more is dropped, as the path would drop it.
const MaxDatagram = 65507

const overhead = 12 + 16

// AEAD is the wire's cipher for a trunk key.
func AEAD(trunkKey string) (cipher.AEAD, error) {
	k, err := hkdf.Key(sha256.New, []byte(trunkKey), nil, "hikkari trunk udp wire", 32)
	if err != nil {
		return nil, err
	}
	b, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func seal(a cipher.AEAD, p []byte) []byte {
	out := make([]byte, 12, overhead+len(p))
	_, _ = rand.Read(out)
	return a.Seal(out, out, p, nil)
}

func open(a cipher.AEAD, p []byte) ([]byte, bool) {
	if len(p) < overhead {
		return nil, false
	}
	plain, err := a.Open(nil, p[:12], p[12:], nil)
	return plain, err == nil
}

// Dialer opens the entry's members of the wire.
type Dialer struct {
	Exit netip.AddrPort
	Key  string // the trunk key
}

// Dial opens one member from localPort (0: any): a UDP socket of its own.
func (d Dialer) Dial(ctx context.Context, localPort int) (io.ReadWriteCloser, error) {
	a, err := AEAD(d.Key)
	if err != nil {
		return nil, err
	}
	c, err := net.DialUDP("udp", &net.UDPAddr{Port: localPort}, net.UDPAddrFromAddrPort(d.Exit))
	if err != nil {
		return nil, err
	}
	return &entryConn{c: c, a: a}, nil
}

type entryConn struct {
	c *net.UDPConn
	a cipher.AEAD
}

func (e *entryConn) Write(p []byte) (int, error) {
	if len(p)+overhead > MaxDatagram {
		return len(p), nil
	}
	if _, err := e.c.Write(seal(e.a, p)); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (e *entryConn) Read(p []byte) (int, error) {
	buf := make([]byte, MaxDatagram)
	for {
		n, err := e.c.Read(buf)
		if err != nil {
			return 0, err
		}
		if plain, ok := open(e.a, buf[:n]); ok {
			return copy(p, plain), nil
		}
	}
}

func (e *entryConn) Close() error { return e.c.Close() }

// Listener is the exit's end: one socket, a member per entry address.
type Listener struct {
	c     *net.UDPConn
	keys  []cipher.AEAD
	serve func(io.ReadWriteCloser)

	mu    sync.Mutex
	peers map[netip.AddrPort]*peer
	done  bool
}

// MaxPeers bounds the members one listener serves at once.
const MaxPeers = 1024

// PeerIdle closes a member that got nothing for this long.
var PeerIdle = 2 * time.Minute

// Listen serves the wire on addr: every entry address whose first datagram
// opens under one of keys (trunk keys) becomes a member, given to serve
// (trunk.Exit.ServeMember) on a goroutine of its own.
func Listen(addr string, keys []string, serve func(io.ReadWriteCloser)) (*Listener, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, err
	}
	l, err := Serve(c, keys, serve)
	if err != nil {
		c.Close()
	}
	return l, err
}

// Serve is Listen on a socket already bound (one the caller shares with a
// process it hands over to, say); Close closes it.
func Serve(c *net.UDPConn, keys []string, serve func(io.ReadWriteCloser)) (*Listener, error) {
	if len(keys) == 0 {
		return nil, errors.New("udpwire: no trunk key")
	}
	l := &Listener{c: c, serve: serve, peers: map[netip.AddrPort]*peer{}}
	for _, k := range keys {
		a, err := AEAD(k)
		if err != nil {
			return nil, err
		}
		l.keys = append(l.keys, a)
	}
	go l.read()
	go l.reap()
	return l, nil
}

// Addr is where the listener is.
func (l *Listener) Addr() netip.AddrPort { return l.c.LocalAddr().(*net.UDPAddr).AddrPort() }

// Peers is how many members it serves now.
func (l *Listener) Peers() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.peers)
}

// Close ends the socket and every member.
func (l *Listener) Close() error {
	l.mu.Lock()
	l.done = true
	peers := l.peers
	l.peers = map[netip.AddrPort]*peer{}
	l.mu.Unlock()
	for _, p := range peers {
		p.shut()
	}
	return l.c.Close()
}

func (l *Listener) read() {
	buf := make([]byte, MaxDatagram)
	for {
		n, from, err := l.c.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		l.mu.Lock()
		p := l.peers[from]
		l.mu.Unlock()
		if p != nil {
			if plain, ok := open(p.a, buf[:n]); ok {
				p.push(plain)
			}
			continue
		}
		for _, a := range l.keys {
			plain, ok := open(a, buf[:n])
			if !ok {
				continue
			}
			l.mu.Lock()
			if l.done || len(l.peers) >= MaxPeers {
				l.mu.Unlock()
				break
			}
			p = &peer{l: l, to: from, a: a, in: make(chan []byte, 256), gone: make(chan struct{})}
			p.last.Store(time.Now().UnixNano())
			l.peers[from] = p
			l.mu.Unlock()
			p.push(plain)
			go l.serve(p)
			break
		}
	}
}

func (l *Listener) reap() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for range t.C {
		l.mu.Lock()
		if l.done {
			l.mu.Unlock()
			return
		}
		var idle []*peer
		for _, p := range l.peers {
			if time.Since(time.Unix(0, p.last.Load())) > PeerIdle {
				idle = append(idle, p)
			}
		}
		l.mu.Unlock()
		for _, p := range idle {
			p.Close()
		}
	}
}

// peer is one entry address: a member's conn on the exit.
type peer struct {
	l    *Listener
	to   netip.AddrPort
	a    cipher.AEAD
	in   chan []byte
	gone chan struct{}
	once sync.Once
	last atomic.Int64 // unix ns of the last datagram
}

func (p *peer) push(plain []byte) {
	p.last.Store(time.Now().UnixNano())
	select {
	case p.in <- plain:
	default: // the member reads too slowly: dropped, as a socket's buffer drops
	}
}

func (p *peer) Read(b []byte) (int, error) {
	select {
	case d := <-p.in:
		return copy(b, d), nil
	case <-p.gone:
		return 0, net.ErrClosed
	}
}

func (p *peer) Write(b []byte) (int, error) {
	select {
	case <-p.gone:
		return 0, net.ErrClosed
	default:
	}
	if len(b)+overhead > MaxDatagram {
		return len(b), nil
	}
	if _, err := p.l.c.WriteToUDPAddrPort(seal(p.a, b), p.to); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (p *peer) shut() { p.once.Do(func() { close(p.gone) }) }

// Close ends the member; a datagram from its address later is a new one.
func (p *peer) Close() error {
	p.shut()
	p.l.mu.Lock()
	if p.l.peers[p.to] == p {
		delete(p.l.peers, p.to)
	}
	p.l.mu.Unlock()
	return nil
}
