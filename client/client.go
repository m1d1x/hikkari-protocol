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
package client

import (
	"context"
	"net"
	"sync"
	"time"

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

type Options struct {
	// Stream carries TCP, and UDP as UDP-over-TCP when the datagram channel
	// is off or failed.
	Stream Channel
	// Datagram carries UDP; nil sends UDP over Stream only.
	Datagram Channel
	// ConnectTimeout bounds one attempt on the datagram channel.
	ConnectTimeout time.Duration
	// RetryAfter is how long UDP stays on Stream after the datagram channel
	// failed.
	RetryAfter time.Duration
	Logger     logger.ContextLogger
}

type Client struct {
	opts     Options
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
	return &Client{opts: opts}
}

func (c *Client) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		return c.opts.Stream.DialContext(ctx, network, destination)
	case N.NetworkUDP:
		if c.datagramUp() {
			var conn net.Conn
			err := c.tryDatagram(ctx, func(ctx context.Context) (err error) {
				conn, err = c.opts.Datagram.DialContext(ctx, network, destination)
				return
			})
			if err == nil {
				return conn, nil
			}
		}
		return c.opts.Stream.DialContext(ctx, network, destination)
	default:
		return nil, N.ErrUnknownNetwork
	}
}

func (c *Client) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if c.datagramUp() {
		var conn net.PacketConn
		err := c.tryDatagram(ctx, func(ctx context.Context) (err error) {
			conn, err = c.opts.Datagram.ListenPacket(ctx, destination)
			return
		})
		if err == nil {
			return conn, nil
		}
	}
	return c.opts.Stream.ListenPacket(ctx, destination)
}

// NetworkChanged forgets a failed datagram channel: a new network may pass
// what the old one blocked.
func (c *Client) NetworkChanged() {
	c.access.Lock()
	c.badUntil = time.Time{}
	c.access.Unlock()
}

// DatagramUp reports whether UDP would try the datagram channel now.
func (c *Client) DatagramUp() bool { return c.datagramUp() }

func (c *Client) datagramUp() bool {
	if c.opts.Datagram == nil {
		return false
	}
	c.access.Lock()
	defer c.access.Unlock()
	return time.Now().After(c.badUntil)
}

// tryDatagram runs one attempt within ConnectTimeout. A failure keeps UDP on
// the stream channel for RetryAfter; the caller's own cancellation is not the
// channel's fault.
func (c *Client) tryDatagram(ctx context.Context, attempt func(context.Context) error) error {
	attemptCtx, cancel := context.WithTimeout(ctx, c.opts.ConnectTimeout)
	defer cancel()
	err := attempt(attemptCtx)
	if err == nil || ctx.Err() != nil {
		return err
	}
	c.access.Lock()
	first := time.Now().After(c.badUntil)
	c.badUntil = time.Now().Add(c.opts.RetryAfter)
	c.access.Unlock()
	if first {
		c.opts.Logger.WarnContext(ctx, "datagram channel failed, UDP goes over the stream channel for ", c.opts.RetryAfter, ": ", err)
	}
	return err
}
