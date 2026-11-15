package pipectl

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

// TestAClientsQuicPacketCrossesTheQuicWireCutAndComesBackWhole is R6.5's
// (hikkari-client plans/2026-11-11-entry-hot-path-and-unit-economics.md,
// «Труба на Rust»; spec/trunk.md, `h3dgram`: a frame over the room is cut):
// a client's datagrams of QUIC's sizes (1200, 1250, 1350, 1472 B) through
// the pipe over Chromium's QUIC members of 1250 B packets, which hold 1194 B
// of frames, to the Rust exit and its relay's echo, and back. Each comes
// back byte for byte, the members stay up (Chromium resets a member's
// stream on a datagram over its room).
func TestAClientsQuicPacketCrossesTheQuicWireCutAndComesBackWhole(t *testing.T) {
	bin, xbin, lib := pipeBin(t), exitBin(t), cronetLib(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	certFile, keyFile, roots := selfSigned(t, t.TempDir())

	x, err := StartExit(ExitConfig{Bin: xbin, Stderr: os.Stderr, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	xc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if err := x.SetWire(ExitWire{ID: 6, Form: FormH3Dgram, Conn: xc, Keys: []string{testKey}, CertFile: certFile, KeyFile: keyFile}); err != nil {
		t.Fatal(err)
	}
	relay := udpEcho(t)
	if err := x.SetPorts([]uint16{relay}); err != nil {
		t.Fatal(err)
	}

	p, err := Start(Config{Bin: bin, Stderr: os.Stderr, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	err = p.SetWire(Wire{ID: 6, Name: "h3dgram", Exit: xc.LocalAddr().(*net.UDPAddr).AddrPort(), Key: testKey, Members: 4,
		H3: &H3Form{SNI: "hk.example", Cronet: lib, Roots: roots, Ports: [2]uint16{32000, 32999}}})
	if err != nil {
		t.Fatal(err)
	}
	lc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Listen(0, lc, trunk.ClassVoice, relay, 1); err != nil {
		t.Fatal(err)
	}
	sel := trunk.NewSelector(trunk.SelectorConfig{}, trunk.Wire{ID: 6, Name: "h3dgram", Shape: "browser"})
	go p.Run(ctx, sel, []trunk.WireID{6}, nil, nil, nil, t.Logf)
	waitFor(t, 10*time.Second, "the QUIC wire's four members up", func() bool { return wireUp(p, 6, 4) })
	waitFor(t, 5*time.Second, "voice routed on the QUIC wire", func() bool { return p.Route().Voice == 6 })

	c, err := net.DialUDP("udp", nil, lc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// The answers are read as they come: 250 of up to 1472 B overflow a
	// socket's default buffer if read after the last is sent.
	answers := make(chan []byte, 1024)
	go func() {
		for {
			b := make([]byte, 2048)
			n, err := c.Read(b)
			if err != nil {
				close(answers)
				return
			}
			answers <- b[:n]
		}
	}()
	// 1472 B is the most a UDP datagram carries on a 1500 B path unfragmented
	// (and this WSL2 kernel's loopback drops fragmented ones).
	sizes := []int{1200, 1250, 1350, 1472, 160}
	const rounds = 50
	want := map[string]bool{}
	for r := 0; r < rounds; r++ {
		for _, n := range sizes {
			d := make([]byte, n)
			for i := range d {
				d[i] = byte(i*31 + n + r)
			}
			want[string(d)] = true
			if _, err := c.Write(d); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	total := rounds * len(sizes)
	got, changed := 0, 0
	bySize := map[int]int{}
	wait := time.After(3 * time.Second)
read:
	for got+changed < total {
		select {
		case b := <-answers:
			if want[string(b)] {
				delete(want, string(b))
				got++
				bySize[len(b)]++
			} else {
				changed++
			}
		case <-wait:
			break read
		}
	}
	t.Logf("back whole %d of %d, changed %d; by size %v", got, total, changed, bySize)
	if changed > 0 || got < total*99/100 {
		t.Fatalf("back whole %d of %d (want 99%%), changed %d", got, total, changed)
	}
	tk, _ := p.Tick()
	for _, w := range tk.Wires {
		t.Logf("wire %d: up %d/%d, in %d, out %d, dgrams %d, dropped %d", w.ID, w.Up, w.Members, w.UpPkts, w.DownPkts, w.Dgrams, w.Dropped)
		if w.ID == 6 && w.Up != 4 {
			t.Errorf("wire 6: %d of 4 members up: a cut datagram hurt a member", w.Up)
		}
	}
}
