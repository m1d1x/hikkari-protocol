package server

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

// UDPIdle is how long a forwarded UDP flow lives without a packet. Long on
// purpose: a muted call pauses its ICE consent checks.
const UDPIdle = 600 * time.Second

// maxResolved bounds the per-flow cache of resolved destinations.
const maxResolved = 4096

// RelayPackets carries one UDP association between a client channel and a
// socket of the relay until either side ends, ctx ends or the flow idles out.
// A connect request (UoT connect mode) sends every packet to its destination;
// otherwise each packet names its own. Answers carry the destination the
// client named, so a client that sent to a name sees the name back. count,
// when set, receives bytes up and down.
func RelayPackets(ctx context.Context, client N.PacketConn, request uot.Request, exit Exit, idle time.Duration, count func(up, down int)) error {
	if idle <= 0 {
		idle = UDPIdle
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sock, err := net.ListenUDP("udp", nil)
	if err != nil {
		return err
	}
	defer sock.Close()
	defer client.Close()
	context.AfterFunc(ctx, func() { _ = sock.Close(); _ = client.Close() })
	var names sync.Map // netip.AddrPort -> M.Socksaddr
	resolved := map[string]netip.AddrPort{}
	timer := time.AfterFunc(idle, cancel)
	defer timer.Stop()

	go func() {
		defer cancel()
		b := make([]byte, 65535)
		for {
			nr, from, err := sock.ReadFromUDPAddrPort(b)
			if err != nil {
				return
			}
			timer.Reset(idle)
			from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
			dest := M.SocksaddrFromNetIP(from)
			if name, ok := names.Load(from); ok {
				dest = name.(M.Socksaddr)
			}
			packet := buf.NewSize(nr)
			_, _ = packet.Write(b[:nr])
			if err := client.WritePacket(packet, dest); err != nil {
				return
			}
			if count != nil {
				count(0, nr)
			}
		}
	}()

	for {
		packet := buf.NewPacket()
		dest, err := client.ReadPacket(packet)
		if err != nil {
			packet.Release()
			return nil
		}
		timer.Reset(idle)
		if request.IsConnect {
			dest = request.Destination
		}
		key := dest.String()
		ap, ok := resolved[key]
		if !ok {
			ap, err = exit.Resolve(ctx, dest)
			if err != nil {
				packet.Release()
				continue
			}
			if len(resolved) < maxResolved {
				resolved[key] = ap
			}
			if dest.IsFqdn() {
				names.Store(ap, dest)
			}
		}
		size := packet.Len()
		_, err = sock.WriteToUDPAddrPort(packet.Bytes(), ap)
		packet.Release()
		if err == nil && count != nil {
			count(size, 0)
		}
	}
}
