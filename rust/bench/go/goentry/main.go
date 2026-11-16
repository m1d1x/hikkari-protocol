// Command goentry is the bench's Go entry: the UDP path of the production
// entry (hikkari-control trunkentry/handoff.go, udpPort: one read loop per
// listened port, a trunk.Flow per client address, answers written straight
// to the client socket) over trunk.Entry with the bare UDP wire, voice routed
// to it as the selector routes it; with -tcp-listen also its TCP path
// (trunkentry/handoff.go: each accepted connection carried by
// Session().Carry) over plain TCP pool members, or with -pool-chromium over
// the production pool's members (trunk/chromium: Chromium's CONNECT to the
// exit's relay channel, an engine each, from a source port of the book).
// With -members 0 there is no UDP wire and voice rides the pool, as the
// selector routes it when the pool is the only wire. What it leaves out: the
// trunk's own calls, the wire stand, the handoff between generations. Bench
// only (rust/README.md). Linux builds with -pool-chromium take -tags
// with_purego and load libcronet.so from the executable's directory.
package main

import (
	"context"
	"flag"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
	"github.com/m1d1x/hikkari-protocol/trunk/chromium"
	"github.com/m1d1x/hikkari-protocol/trunk/udpwire"
)

const udpWire trunk.WireID = 2

func main() {
	listen := flag.String("listen", "127.0.0.1:8443", "client UDP listen address")
	wire := flag.String("wire", "127.0.0.1:20447", "exit's udp wire")
	pool := flag.String("pool", "127.0.0.1:20446", "exit's plain TCP pool")
	key := flag.String("key", "bench-trunk-key-0123456789abcdef", "trunk key")
	members := flag.Int("members", 2, "udp wire members")
	to := flag.Uint("to", 0, "exit loopback port (0: the exit's echo)")
	tcpListen := flag.String("tcp-listen", "", "client TCP listen address (empty: none)")
	tcpTo := flag.Uint("tcp-to", 9000, "exit loopback port of the clients' streams")
	poolMembers := flag.Int("pool-members", 1, "pool members")
	poolChromium := flag.String("pool-chromium", "", "the relay's domain: pool members by Chromium's CONNECT to -pool (empty: plain TCP)")
	roots := flag.String("roots", "/bench/out/naive-roots.pem", "the relay certificate's PEM, with -pool-chromium")
	flag.Parse()

	exitWire, err := netip.ParseAddrPort(*wire)
	if err != nil {
		log.Fatal(err)
	}
	ports, err := trunk.NewPortBook(20000, 32767, time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	dialPool := func(ctx context.Context, port int) (io.ReadWriteCloser, error) {
		d := net.Dialer{LocalAddr: &net.TCPAddr{Port: port}}
		return d.DialContext(ctx, "tcp", *pool)
	}
	if *poolChromium != "" {
		if err := chromium.Load(); err != nil {
			log.Fatal(err)
		}
		pem, err := os.ReadFile(*roots)
		if err != nil {
			log.Fatal(err)
		}
		dialPool = chromium.Dialer{Exit: *pool, SNI: *poolChromium, Key: *key, Roots: string(pem)}.Dial
		log.Printf("goentry: pool members by Chromium %s", chromium.Version())
	}
	e, err := trunk.NewEntry(trunk.Config{}, *poolMembers, dialPool, ports, log.Printf)
	if err != nil {
		log.Fatal(err)
	}
	if *members > 0 {
		if err := e.AddWire(trunk.Wire{ID: udpWire, Name: "udp", Shape: "random", Members: *members, Packet: true,
			Dial: udpwire.Dialer{Exit: exitWire, Key: *key}.Dial}); err != nil {
			log.Fatal(err)
		}
		e.SetRoute(trunk.Route{Voice: udpWire, Bulk: trunk.PoolWire})
	} else {
		e.SetRoute(trunk.Route{Voice: trunk.PoolWire, Bulk: trunk.PoolWire})
	}
	ctx := context.Background()
	go e.Run(ctx)

	ua, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	pc, err := net.ListenUDP("udp", ua)
	if err != nil {
		log.Fatal(err)
	}
	p := &udpPort{entry: e, to: uint16(*to), pc: pc, flows: map[string]*trunk.Flow{}}
	go p.read()
	if *tcpListen != "" {
		tl, err := net.Listen("tcp", *tcpListen)
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			for {
				conn, err := tl.Accept()
				if err != nil {
					return
				}
				go e.Session().Carry(conn, uint16(*tcpTo))
			}
		}()
	}
	log.Printf("goentry: clients %s, wire %s x%d, tcp %q x%d", pc.LocalAddr(), exitWire, *members, *tcpListen, *poolMembers)
	for range time.Tick(10 * time.Second) {
		st := e.Session().Stats()
		log.Printf("goentry: members=%d flows=%d dgrams=%d/%d streams=%d opened=%d reset=%d up=%d down=%d",
			st.Members, st.Flows, st.DgramsOut, st.DgramsIn, st.Streams, st.StreamsOpened, st.StreamsReset, st.Up, st.Down)
	}
}

// udpPort is trunkentry's udpPort without generations: the same read loop,
// the same flow per client address, the same class for a one-copy port.
type udpPort struct {
	entry *trunk.Entry
	to    uint16
	pc    *net.UDPConn

	mu    sync.Mutex
	flows map[string]*trunk.Flow
}

func (p *udpPort) read() {
	buf := make([]byte, trunk.MaxPayload)
	for {
		size, from, err := p.pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			continue
		}
		p.datagram(from, buf[:size])
	}
}

func (p *udpPort) datagram(from netip.AddrPort, data []byte) {
	key := from.String()
	p.mu.Lock()
	f := p.flows[key]
	if f == nil {
		f = p.open(from, key)
	}
	p.mu.Unlock()
	if !f.Send(data) {
		p.mu.Lock()
		if p.flows[key] == f {
			delete(p.flows, key)
		}
		p.mu.Unlock()
	}
}

func (p *udpPort) open(client netip.AddrPort, key string) *trunk.Flow {
	var f *trunk.Flow
	f = p.entry.Session().OpenFlowWith(p.to, trunk.FlowOptions{Copies: 1, Class: trunk.ClassVoice, Pin: trunk.AnyWire},
		func(b []byte) { _, _ = p.pc.WriteToUDPAddrPort(b, client) },
		func() {
			p.mu.Lock()
			if p.flows[key] == f {
				delete(p.flows, key)
			}
			p.mu.Unlock()
		})
	p.flows[key] = f
	return f
}
