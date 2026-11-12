// Command goexit is the bench's exit: trunk.Exit as the relay box runs it,
// with the bare UDP wire (trunk/udpwire) and a plain TCP pool member for the
// Go entry (no TLS: the bench measures the entry's UDP path, not the pool).
// Flows to port 0 are the exit's echo (trunk.EchoPort), so no relay is
// needed behind it. Bench only (pipe-rs/README.md).
package main

import (
	"context"
	"flag"
	"io"
	"log"
	"net"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
	"github.com/m1d1x/hikkari-protocol/trunk/udpwire"
)

type local struct{}

func (local) DialStream(ctx context.Context, port uint16) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", itoa(port)))
}

func (local) DialFlow(ctx context.Context, port uint16) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "udp", net.JoinHostPort("127.0.0.1", itoa(port)))
}

func itoa(p uint16) string { return fmtUint(uint64(p)) }

func fmtUint(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

func main() {
	wire := flag.String("wire", "127.0.0.1:20447", "udp wire listen address")
	pool := flag.String("pool", "127.0.0.1:20446", "plain TCP pool member listen address")
	key := flag.String("key", "bench-trunk-key-0123456789abcdef", "trunk key")
	flag.Parse()

	x := trunk.NewExit(trunk.Config{}, local{})
	ctx := context.Background()
	go x.Run(ctx)
	l, err := udpwire.Listen(*wire, []string{*key}, func(c io.ReadWriteCloser) { _ = x.ServeMember(c) })
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	tl, err := net.Listen("tcp", *pool)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			go func() { _ = x.ServeMember(c) }()
		}
	}()
	log.Printf("goexit: wire %s pool %s", l.Addr(), tl.Addr())
	for range time.Tick(10 * time.Second) {
		n, st := x.Stats()
		log.Printf("goexit: sessions=%d peers=%d flows=%d dgrams=%d/%d", n, l.Peers(), st.Flows, st.DgramsOut, st.DgramsIn)
	}
}
