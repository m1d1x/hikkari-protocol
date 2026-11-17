package server

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"

	"github.com/m1d1x/hikkari-protocol/connect"
)

// ExitSocket is the UDP socket of one association toward the internet. A
// session without a source (connect.Source) gets one dual-stack socket, as a
// relay always had. A session with a source binds one socket per family of
// its source, since a socket bound to an IPv4 address cannot reach IPv6:
// packets to a family the source lacks are refused, never sent another way.
type ExitSocket struct {
	dual, v4, v6 *net.UDPConn
	// readMu runs one read handler at a time, so a caller sees the same
	// serial stream of answers it saw from a single socket.
	readMu sync.Mutex
}

// ListenExit opens the exit socket of a session from its context's source.
func ListenExit(ctx context.Context) (*ExitSocket, error) {
	src, ok := connect.SourceFrom(ctx)
	if !ok {
		sock, err := net.ListenUDP("udp", nil)
		if err != nil {
			return nil, err
		}
		return &ExitSocket{dual: sock}, nil
	}
	s := &ExitSocket{}
	var err error
	if src.V4.IsValid() {
		if s.v4, err = net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(src.V4, 0))); err != nil {
			return nil, err
		}
	}
	if src.V6.IsValid() {
		if s.v6, err = net.ListenUDP("udp6", net.UDPAddrFromAddrPort(netip.AddrPortFrom(src.V6, 0))); err != nil {
			s.Close()
			return nil, err
		}
	}
	return s, nil
}

// WriteTo sends b to ap from the socket of ap's family.
func (s *ExitSocket) WriteTo(b []byte, ap netip.AddrPort) (int, error) {
	if s.dual != nil {
		return s.dual.WriteToUDPAddrPort(b, ap)
	}
	sock := s.v6
	if ap.Addr().Unmap().Is4() {
		sock = s.v4
		ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	if sock == nil {
		return 0, connect.ErrNoSourceFamily
	}
	return sock.WriteToUDPAddrPort(b, ap)
}

// Read calls answer with every packet that arrives, the sender unmapped, one
// call at a time, until a socket fails or answer returns false; b is reused
// after answer returns. It returns when the socket it read from ends, so the
// owner closes the socket to stop it.
func (s *ExitSocket) Read(answer func(b []byte, from netip.AddrPort) bool) {
	socks := []*net.UDPConn{s.dual, s.v4, s.v6}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	var once sync.Once
	for _, sock := range socks {
		if sock == nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer once.Do(func() { close(stop) })
			b := make([]byte, 65535)
			for {
				n, from, err := sock.ReadFromUDPAddrPort(b)
				if err != nil {
					return
				}
				s.readMu.Lock()
				ok := answer(b[:n], netip.AddrPortFrom(from.Addr().Unmap(), from.Port()))
				s.readMu.Unlock()
				if !ok {
					return
				}
			}
		}()
	}
	<-stop
}

// Close closes every socket of the association.
func (s *ExitSocket) Close() error {
	var errs []error
	for _, sock := range []*net.UDPConn{s.dual, s.v4, s.v6} {
		if sock != nil {
			errs = append(errs, sock.Close())
		}
	}
	return errors.Join(errs...)
}
