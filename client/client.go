// Package client is the client side of Hikkari: one outbound, two channels.
//
//	TCP ─► the stream channel (Naive: HTTP/2 CONNECT through Chromium's stack)
//	UDP ─► the datagram channel (QUIC DATAGRAM on the same host, wire/datagram)
//	    └► when that does not connect: UDP-over-TCP inside the stream channel
//
// The channels keep their own health: a dead datagram channel never touches
// TCP, and UDP tries the datagram channel again after RetryAfter. The stream
// channel is whatever the host engine provides (sing-box builds Naive with
// cronet); this package owns the choice between channels and the datagram
// client.
//
// A cascade's client may reach the relay through several entries (v1.07,
// spec/v1.md): a path per entry, each with its own channels. New connections
// go by the active path, the first one not silent (paths.go); a call goes by
// every path at once (dup.go).
package client

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/m1d1x/hikkari-protocol/dup"
	"github.com/m1d1x/hikkari-protocol/observe"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	DefaultConnectTimeout = 4 * time.Second
	DefaultRetryAfter     = 60 * time.Second
)

// Channel carries connections and packets, as sing's dialers do.
type Channel interface {
	DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)
	ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error)
}

// Path is one way to the relay: an entry of the cascade with its own channels
// (v1.07). Every path leads to the same relay under the same key.
type Path struct {
	// Stream carries TCP, and UDP as UDP-over-TCP when the datagram channel
	// is off or failed.
	Stream Channel
	// Datagram carries UDP; nil sends UDP over Stream only.
	Datagram Channel
	// VoiceDatagram is a second datagram channel to the same relay, a QUIC
	// connection of its own, for calls' voice (v1.03): in one connection
	// voice waits in the same queue as the video and bulk beside it. Used
	// only with Dup and a relay that keeps lanes; nil keeps voice on Datagram.
	VoiceDatagram Channel
}

type Options struct {
	// Stream, Datagram and VoiceDatagram are the first path (Path).
	Stream        Channel
	Datagram      Channel
	VoiceDatagram Channel
	// Paths are the further entries, in the link's order (v1.07). With any,
	// the client pings every entry and Context must be set.
	Paths []Path
	// Context owns the entries' probes; nil with one path.
	Context context.Context
	// ConnectTimeout bounds one attempt on the datagram channel.
	ConnectTimeout time.Duration
	// RetryAfter is how long UDP stays on Stream after the datagram channel
	// failed.
	RetryAfter time.Duration
	// Dup carries every UDP association as a duplicated session (v1.02,
	// package dup): by the datagram channel, and by the stream channel too
	// while the flow looks like a call or the datagram channel is down. The
	// relay must serve dup.Host; the link says so.
	Dup    bool
	Logger logger.ContextLogger
	// Book, when set, counts the client's duplicated sessions and calls
	// (v1.04 observability) under Group; give the same book to the datagram
	// channels (DatagramOptions.Book) for their QUIC connections.
	Book *observe.Book
}

// Group is the one group a client's book counts under: a client is one user,
// it needs no key.
const Group = ""

type Client struct {
	opts   Options
	paths  []*path
	health *health // nil with one path
}

// path is a Path and its datagram channel's failure.
type path struct {
	Path
	access   sync.Mutex
	badUntil time.Time
}

func New(opts Options) *Client {
	if opts.ConnectTimeout <= 0 {
		opts.ConnectTimeout = DefaultConnectTimeout
	}
	if opts.RetryAfter <= 0 {
		opts.RetryAfter = DefaultRetryAfter
	}
	if opts.Logger == nil {
		opts.Logger = logger.NOP()
	}
	c := &Client{opts: opts}
	c.paths = append(c.paths, &path{Path: Path{Stream: opts.Stream, Datagram: opts.Datagram, VoiceDatagram: opts.VoiceDatagram}})
	for _, p := range opts.Paths {
		c.paths = append(c.paths, &path{Path: p})
	}
	if len(c.paths) > 1 {
		c.health = startHealth(opts.Context, c)
	}
	return c
}

// Active is the number of the entry new connections take now (v1.07).
func (c *Client) Active() int {
	if c.health == nil {
		return 0
	}
	return c.health.active(time.Now())
}

func (c *Client) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	at := c.Active()
	p := c.paths[at]
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		return p.Stream.DialContext(ctx, network, destination)
	case N.NetworkUDP:
		if conn, ok := c.listenDup(ctx, at); ok {
			return bufio.NewBindPacketConn(conn, destination), nil
		}
		if c.datagramUp(at) {
			var conn net.Conn
			err := c.tryDatagram(ctx, at, func(ctx context.Context) (err error) {
				conn, err = p.Datagram.DialContext(ctx, network, destination)
				return
			})
			if err == nil {
				return conn, nil
			}
		}
		return p.Stream.DialContext(ctx, network, destination)
	default:
		return nil, N.ErrUnknownNetwork
	}
}

func (c *Client) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	at := c.Active()
	p := c.paths[at]
	if conn, ok := c.listenDup(ctx, at); ok {
		return conn, nil
	}
	if c.datagramUp(at) {
		var conn net.PacketConn
		err := c.tryDatagram(ctx, at, func(ctx context.Context) (err error) {
			conn, err = p.Datagram.ListenPacket(ctx, destination)
			return
		})
		if err == nil {
			return conn, nil
		}
	}
	return p.Stream.ListenPacket(ctx, destination)
}

// listenDup opens a duplicated session on path at when the link asks for one
// and its datagram channel connects; otherwise UDP takes the v1.01 path.
func (c *Client) listenDup(ctx context.Context, at int) (net.PacketConn, bool) {
	if !c.opts.Dup || !c.datagramUp(at) {
		return nil, false
	}
	var primary net.PacketConn
	err := c.tryDatagram(ctx, at, func(ctx context.Context) (err error) {
		primary, err = c.paths[at].Datagram.ListenPacket(ctx, dup.HostAddr())
		return
	})
	if err != nil {
		return nil, false
	}
	return newDupConn(ctx, c, at, primary), true
}

// NetworkChanged forgets failed datagram channels: a new network may pass
// what the old one blocked.
func (c *Client) NetworkChanged() {
	for _, p := range c.paths {
		p.access.Lock()
		p.badUntil = time.Time{}
		p.access.Unlock()
	}
}

// DatagramUp reports whether UDP would try the active path's datagram channel
// now.
func (c *Client) DatagramUp() bool { return c.datagramUp(c.Active()) }

func (c *Client) datagramUp(at int) bool {
	p := c.paths[at]
	if p.Datagram == nil {
		return false
	}
	p.access.Lock()
	defer p.access.Unlock()
	return time.Now().After(p.badUntil)
}

// tryDatagram runs one attempt on path at within ConnectTimeout. A failure
// keeps that path's UDP on its stream channel for RetryAfter; the caller's own
// cancellation is not the channel's fault.
func (c *Client) tryDatagram(ctx context.Context, at int, attempt func(context.Context) error) error {
	attemptCtx, cancel := context.WithTimeout(ctx, c.opts.ConnectTimeout)
	defer cancel()
	err := attempt(attemptCtx)
	if err == nil || ctx.Err() != nil {
		return err
	}
	p := c.paths[at]
	p.access.Lock()
	first := time.Now().After(p.badUntil)
	p.badUntil = time.Now().Add(c.opts.RetryAfter)
	p.access.Unlock()
	if first {
		c.opts.Logger.WarnContext(ctx, "entry ", at, ": datagram channel failed, UDP goes over the stream channel for ", c.opts.RetryAfter, ": ", err)
	}
	return err
}
