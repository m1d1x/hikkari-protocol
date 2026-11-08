package server

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"

	M "github.com/sagernet/sing/common/metadata"
)

// Exit is where a relay sends traffic on a user's behalf: the datagram
// channel and the UDP-over-TCP fallback dial through it. The relay owns the
// policy (which networks, names and ports are refused); the protocol only asks.
type Exit interface {
	// Resolve returns the address a datagram to dest goes to, or an error when
	// dest is refused or does not resolve.
	Resolve(ctx context.Context, dest M.Socksaddr) (netip.AddrPort, error)
	// DialTCP opens a stream to dest, or refuses it.
	DialTCP(ctx context.Context, dest M.Socksaddr) (net.Conn, error)
}

// ErrRefused is a destination the exit policy refuses.
var ErrRefused = errors.New("hikkari: destination refused by exit policy")

// PolicyExit refuses networks, domain zones and TCP ports, and resolves names
// with the system resolver, refusing a name whose every address is refused.
type PolicyExit struct {
	nets    []netip.Prefix
	domains []string
	ports   []uint16
}

// NewPolicyExit builds an exit from refused CIDRs or addresses, refused domain
// zones ("ru" refuses ru and *.ru; a "domain:" prefix is accepted) and refused
// TCP ports. Entries that do not parse are skipped.
func NewPolicyExit(nets, domains []string, tcpPorts []uint16) *PolicyExit {
	e := &PolicyExit{ports: tcpPorts}
	for _, cidr := range nets {
		if p, err := netip.ParsePrefix(cidr); err == nil {
			e.nets = append(e.nets, p.Masked())
		} else if a, err := netip.ParseAddr(cidr); err == nil {
			a = a.Unmap()
			e.nets = append(e.nets, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	for _, d := range domains {
		d = strings.TrimSuffix(strings.ToLower(strings.TrimPrefix(d, "domain:")), ".")
		if d != "" {
			e.domains = append(e.domains, d)
		}
	}
	return e
}

// AllowAddr reports whether a is a destination the exit may reach.
func (e *PolicyExit) AllowAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsUnspecified() {
		return false
	}
	for _, p := range e.nets {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// AllowName reports whether a domain is outside every refused zone.
func (e *PolicyExit) AllowName(fqdn string) bool {
	fqdn = strings.TrimSuffix(strings.ToLower(fqdn), ".")
	for _, d := range e.domains {
		if fqdn == d || strings.HasSuffix(fqdn, "."+d) {
			return false
		}
	}
	return true
}

func (e *PolicyExit) Resolve(ctx context.Context, dest M.Socksaddr) (netip.AddrPort, error) {
	if dest.Port == 0 {
		return netip.AddrPort{}, ErrRefused
	}
	if dest.IsFqdn() {
		if !e.AllowName(dest.Fqdn) {
			return netip.AddrPort{}, ErrRefused
		}
		addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", dest.Fqdn)
		if err != nil {
			return netip.AddrPort{}, err
		}
		for _, a := range addrs {
			if e.AllowAddr(a) {
				return netip.AddrPortFrom(a.Unmap(), dest.Port), nil
			}
		}
		return netip.AddrPort{}, ErrRefused
	}
	if !e.AllowAddr(dest.Addr) {
		return netip.AddrPort{}, ErrRefused
	}
	return netip.AddrPortFrom(dest.Addr.Unmap(), dest.Port), nil
}

func (e *PolicyExit) DialTCP(ctx context.Context, dest M.Socksaddr) (net.Conn, error) {
	if slices.Contains(e.ports, dest.Port) {
		return nil, ErrRefused
	}
	ap, err := e.Resolve(ctx, dest)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", ap.String())
}
