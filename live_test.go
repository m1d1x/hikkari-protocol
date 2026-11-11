package hikkari_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/client"
	"github.com/m1d1x/hikkari-protocol/internal/testcert"
	"github.com/m1d1x/hikkari-protocol/observe"
	"github.com/m1d1x/hikkari-protocol/server"
	M "github.com/sagernet/sing/common/metadata"
)

// Every packet of the live test carries its number and the time it was made
// (ns): an echo returns the client's, a generator writes its own. The test
// runs in one process, so both ends read one clock.
const liveHeader = 12

func stamp(p []byte, seq uint32) {
	binary.BigEndian.PutUint32(p, seq)
	binary.BigEndian.PutUint64(p[4:], uint64(time.Now().UnixNano()))
}

func unstamp(p []byte) (uint32, time.Time) {
	return binary.BigEndian.Uint32(p), time.Unix(0, int64(binary.BigEndian.Uint64(p[4:])))
}

// liveFlow is what one live stream saw: every answer's birth and arrival.
type liveFlow struct {
	name string
	mu   sync.Mutex
	seen map[uint32]bool
	got  []arrived
	born []time.Time // every answer the far end made (an echo: every packet sent)
}

type arrived struct{ born, at time.Time }

// made counts an answer the far end makes, p stamped.
func (f *liveFlow) made(p []byte) {
	_, born := unstamp(p)
	f.mu.Lock()
	f.born = append(f.born, born)
	f.mu.Unlock()
}

func newFlow(name string) *liveFlow { return &liveFlow{name: name, seen: map[uint32]bool{}} }

func (f *liveFlow) arrive(p []byte) {
	if len(p) < liveHeader {
		return
	}
	seq, born := unstamp(p)
	now := time.Now()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.seen[seq] {
		return
	}
	f.seen[seq] = true
	f.got = append(f.got, arrived{born, now})
}

// read takes answers off conn into f until conn closes; each answer also goes
// to also, when set.
func (f *liveFlow) read(conn net.PacketConn, also func([]byte)) {
	b := make([]byte, 2048)
	for {
		n, _, err := conn.ReadFrom(b)
		if err != nil {
			return
		}
		f.arrive(b[:n])
		if also != nil {
			also(b[:n])
		}
	}
}

// liveEcho answers every packet once, as it came: the far end of a voice call
// or of a game server's tick.
func liveEcho(t *testing.T) *net.UDPConn {
	return fanEcho(t, 1)
}

// sendEvery writes one packet of size() bytes every every until stop, counting
// each in f.want (the echo answers each once).
func sendEvery(conn net.PacketConn, to net.Addr, f *liveFlow, every time.Duration, size func() int, stop <-chan struct{}) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for seq := uint32(1); ; seq++ {
		select {
		case <-stop:
			return
		case <-tick.C:
		}
		p := make([]byte, size())
		stamp(p, seq)
		f.made(p)
		_, _ = conn.WriteTo(p, to)
	}
}

// generator is a far end that streams to whoever writes to it: a screen
// share's video, or a download. Its rate is bits a second; keyEvery and key,
// when set, add a key frame of key packets at once.
type generator struct {
	*net.UDPConn
	size     int
	keyEvery time.Duration
	key      int
	flow     *liveFlow
	// rate is the current bits a second; a responsive generator changes it by
	// what the client reports (acks), a deaf one never does.
	rate       atomic.Int64
	responsive bool
	ceiling    int64
}

func newGenerator(t *testing.T, flow *liveFlow, rate int64, size int) *generator {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	g := &generator{UDPConn: c, size: size, flow: flow, ceiling: rate}
	g.rate.Store(rate)
	return g
}

// serve waits for the client's first packet, then streams to it until stop;
// a responsive generator reads the client's acks the whole time.
func (g *generator) serve(stop <-chan struct{}) {
	b := make([]byte, 2048)
	_, to, err := g.ReadFromUDP(b)
	if err != nil {
		return
	}
	var seq atomic.Uint32
	if g.responsive {
		go g.listen(&seq)
	}
	start := time.Now()
	var sent float64 // packets owed by the rate so far
	nextKey := start.Add(g.keyEvery)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	last := start
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
		}
		now := time.Now()
		sent += float64(g.rate.Load()) / 8 / float64(g.size) * now.Sub(last).Seconds()
		last = now
		n := int(sent)
		sent -= float64(n)
		if g.key > 0 && !now.Before(nextKey) {
			n += g.key
			nextKey = nextKey.Add(g.keyEvery)
		}
		for i := 0; i < n; i++ {
			p := make([]byte, g.size)
			stamp(p, seq.Add(1))
			g.flow.made(p)
			_, _ = g.WriteToUDP(p, to)
		}
	}
}

// listen is a responsive sender's control, as a QUIC sender inside the
// tunnel has one: the client acks every 50 ms with how many packets came and
// the birth of the newest one. The rate falls by 15% (at most every 100 ms)
// when more than 2% of what was sent since the last ack is missing or the
// newest packet is 50 ms later than the least delay seen; otherwise it grows
// by 0.5 Mbit/s an ack up to the ceiling. No ack for 500 ms halves it.
func (g *generator) listen(seq *atomic.Uint32) {
	b := make([]byte, 64)
	least := time.Hour
	var lastSeq, lastGot uint32
	var lastCut time.Time
	cut := func(by float64) {
		if time.Since(lastCut) < 100*time.Millisecond {
			return
		}
		lastCut = time.Now()
		g.rate.Store(max(500_000, int64(float64(g.rate.Load())*by)))
	}
	for {
		_ = g.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _, err := g.ReadFromUDP(b)
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			cut(0.5)
			continue
		}
		if err != nil {
			return
		}
		if n < 12 {
			continue
		}
		got := binary.BigEndian.Uint32(b)
		newest := time.Unix(0, int64(binary.BigEndian.Uint64(b[4:])))
		delay := time.Since(newest)
		least = min(least, delay)
		sentNow := seq.Load()
		sentDelta, gotDelta := sentNow-lastSeq, got-lastGot
		lastSeq, lastGot = sentNow, got
		lossy := sentDelta > 50 && gotDelta < sentDelta*98/100
		if lossy || delay > least+50*time.Millisecond {
			cut(0.85)
			continue
		}
		g.rate.Store(min(g.ceiling, g.rate.Load()+500_000))
	}
}

// ackEvery reports to a responsive generator what came so far.
func ackEvery(conn net.PacketConn, to net.Addr, f *liveFlow, stop <-chan struct{}) {
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
		}
		f.mu.Lock()
		got := uint32(len(f.got))
		var newest time.Time
		if len(f.got) > 0 {
			newest = f.got[len(f.got)-1].born
		}
		f.mu.Unlock()
		p := make([]byte, 12)
		binary.BigEndian.PutUint32(p, got)
		binary.BigEndian.PutUint64(p[4:], uint64(newest.UnixNano()))
		_, _ = conn.WriteTo(p, to)
	}
}

// keepAlive writes a small packet a second: what a screen share's receiver
// or a download's client sends up beside the stream.
func keepAlive(conn net.PacketConn, to net.Addr, stop <-chan struct{}) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		_, _ = conn.WriteTo(make([]byte, 40), to)
		select {
		case <-stop:
			return
		case <-tick.C:
		}
	}
}

// liveVerdict is one live stream's answers measured against the line.
type liveVerdict struct {
	got, want      int
	late           int           // later than the line's delay then + 150 ms
	lateTail       int           // of them born 1 s or more after the bloat ended
	worst          time.Duration // the latest answer
	extraP50       time.Duration // answer delay over the line's delay
	extraP95       time.Duration
	extraMax       time.Duration
	lineAtWorst    time.Duration
	deliveredShare float64
}

func (v liveVerdict) String() string {
	return fmt.Sprintf("%d/%d (%.1f%%), late %d (tail %d), worst %v (line then %v), over the line p50 %v p95 %v max %v",
		v.got, v.want, v.deliveredShare*100, v.late, v.lateTail, v.worst.Round(time.Millisecond), v.lineAtWorst.Round(time.Millisecond),
		v.extraP50.Round(time.Millisecond), v.extraP95.Round(time.Millisecond), v.extraMax.Round(time.Millisecond))
}

// judge measures the answers born in [from, to] against the line's delay at
// their arrival; the tail is what was born from tail on.
func judge(f *liveFlow, line *bloatedLine, from, to, tail time.Time) liveVerdict {
	const slack = 150 * time.Millisecond
	f.mu.Lock()
	got := append([]arrived(nil), f.got...)
	f.mu.Unlock()
	var v liveVerdict
	var extra []time.Duration
	for _, a := range got {
		if a.born.Before(from) || a.born.After(to) {
			continue
		}
		v.got++
		d := a.at.Sub(a.born)
		lineThen := line.delayAt(a.at.Add(-50*time.Millisecond), a.at)
		extra = append(extra, d-lineThen)
		if d > lineThen+slack {
			v.late++
			if !a.born.Before(tail) {
				v.lateTail++
			}
		}
		if d > v.worst {
			v.worst, v.lineAtWorst = d, lineThen
		}
	}
	sort.Slice(extra, func(i, j int) bool { return extra[i] < extra[j] })
	if n := len(extra); n > 0 {
		v.extraP50, v.extraP95, v.extraMax = extra[n/2], extra[n*95/100], extra[n-1]
	}
	return v
}

// liveCase is one of the four line and bulk pairs.
type liveCase struct {
	name       string
	responsive bool          // the bulk sender backs off by loss and delay
	limit      time.Duration // the line drops what would wait longer; 0 keeps all
	peak       time.Duration // the download's bloat at the top of its sawtooth
}

// TestLiveTrafficOnABloatedLine is the datagram channel as a pipe
// (plans/2026-11-11-datagram-dumb-pipe-live-udp.md): one client, one home
// line, four UDP streams at once, their answers coming down the line another
// download bloats. A voice call (50 packets a second of 160 B, echoed), a game
// (60 a second of 100 to 300 B, echoed), a screen share (2.5 Mbit/s of 1200 B
// and a key frame of 40 packets every 2 s, streamed) and a bulk stream, either
// responsive (backs off by loss and delay, as QUIC inside the tunnel does, up
// to 20 Mbit/s) or deaf (50 Mbit/s, no reaction, more than the line carries).
// The line is bloated without loss (a sawtooth from nothing to 2 s every 4 s)
// or with loss (a sawtooth to 900 ms, the line's queue at most 1 s, the rest
// dropped). The stream copy is stalled, as in TestCallOnABloatedLine.
//
// The live streams (voice, game, screen) must each keep to the line: at most
// 1% of the answers later than the line's own delay at that moment + 150 ms,
// the worst no later than the line's peak + 300 ms, none late once the bloat
// has been gone 1 s; at least 97% delivered with a responsive bulk on the line
// without loss, at least 90% otherwise. What the relay did not send of a deaf
// bulk is counted (dup.stale_dgram), not left to grow the delay.
func TestLiveTrafficOnABloatedLine(t *testing.T) {
	for _, lc := range []liveCase{
		{name: "responsive bulk, line without loss", responsive: true, peak: 2 * time.Second},
		{name: "deaf bulk, line without loss", peak: 2 * time.Second},
		{name: "responsive bulk, line with loss", responsive: true, limit: time.Second, peak: 900 * time.Millisecond},
		{name: "deaf bulk, line with loss", limit: time.Second, peak: 900 * time.Millisecond},
	} {
		t.Run(lc.name, func(t *testing.T) { liveOnABloatedLine(t, lc) })
	}
}

func liveOnABloatedLine(t *testing.T, lc liveCase) {
	const key = "subscriber-key-0123456789abcdef"
	const (
		warm  = 3 * time.Second
		bloat = 16 * time.Second
		tail  = 3 * time.Second
	)
	cert, pool := testcert.New("hk.example")
	keys := &roster{keys: map[string]bool{key: true}, slots: map[int]context.CancelFunc{}}
	listen := freeUDP(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	book := observe.NewBook()
	hub := server.NewDupHub(loopbackExit{}, 0)
	hub.Observe(book)
	d, err := server.ListenDatagram(ctx, server.DatagramOptions{
		Listen:      listen,
		Certificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil },
		Admitter:    keys,
		Exit:        loopbackExit{},
		Dup:         hub,
		Book:        book,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	d.SetKeys([]string{key})
	line := &bloatedLine{limit: lc.limit, track: true}
	newDatagram := func(name string) *client.Datagram {
		dc, err := client.NewDatagram(client.DatagramOptions{
			Context: ctx, Dialer: line, Server: M.ParseSocksaddr(listen), Password: key, Name: name,
			TLS: &testcert.Client{Config: &tls.Config{ServerName: "hk.example", RootCAs: pool}},
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = dc.Close() })
		return dc
	}
	stream := &hubStream{hub: hub, key: key}
	stream.stall.Store(true)
	c := client.New(client.Options{
		Stream:        stream,
		Datagram:      newDatagram("datagram"),
		VoiceDatagram: newDatagram("voice"),
		Dup:           true,
	})
	listenLive := func() net.PacketConn {
		conn, err := c.ListenPacket(ctx, M.Socksaddr{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}

	voice, game, screen, bulk := newFlow("voice"), newFlow("game"), newFlow("screen"), newFlow("bulk")
	voiceFar, gameFar := liveEcho(t), liveEcho(t)
	defer voiceFar.Close()
	defer gameFar.Close()
	screenFar := newGenerator(t, screen, 2_500_000, 1200)
	screenFar.keyEvery, screenFar.key = 2*time.Second, 40
	defer screenFar.Close()
	bulkFar := newGenerator(t, bulk, 50_000_000, 1200)
	if lc.responsive {
		bulkFar.ceiling, bulkFar.responsive = 20_000_000, true
		bulkFar.rate.Store(5_000_000)
	}
	defer bulkFar.Close()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	run := func(f func()) {
		wg.Add(1)
		go func() { defer wg.Done(); f() }()
	}
	voiceConn, gameConn, screenConn, bulkConn := listenLive(), listenLive(), listenLive(), listenLive()
	go voice.read(voiceConn, nil)
	go game.read(gameConn, nil)
	go screen.read(screenConn, nil)
	go bulk.read(bulkConn, nil)
	run(func() {
		sendEvery(voiceConn, voiceFar.LocalAddr(), voice, 20*time.Millisecond, func() int { return 160 }, stop)
	})
	run(func() {
		sendEvery(gameConn, gameFar.LocalAddr(), game, time.Second/60, func() int { return 100 + rand.IntN(201) }, stop)
	})
	run(func() { screenFar.serve(stop) })
	run(func() { keepAlive(screenConn, screenFar.LocalAddr(), stop) })
	run(func() { bulkFar.serve(stop) })
	if lc.responsive {
		run(func() { ackEvery(bulkConn, bulkFar.LocalAddr(), bulk, stop) })
	} else {
		run(func() { keepAlive(bulkConn, bulkFar.LocalAddr(), stop) })
	}

	// The streams start on the idle line; the connections learn it.
	time.Sleep(warm)
	begin := time.Now()
	for time.Since(begin) < bloat {
		phase := time.Since(begin) % (4 * time.Second)
		line.bloat.Store(int64(lc.peak) * int64(phase) / int64(4*time.Second))
		time.Sleep(10 * time.Millisecond)
	}
	line.bloat.Store(0)
	ended := time.Now()
	time.Sleep(tail)
	close(stop)
	wg.Wait()
	born := time.Now()
	// What is still on its way comes, or never will: the line's queue drains
	// (a deaf bulk over the line's rate leaves seconds in it), then 3 s.
	time.Sleep(time.Until(line.empty()) + 3*time.Second)

	peak := line.peak(begin)
	minShare := 0.90
	if lc.responsive && lc.limit == 0 {
		minShare = 0.97
	}
	t.Logf("line: peak %v in its queue, %d dropped by the line", peak.Round(time.Millisecond), line.drops())
	for _, f := range []*liveFlow{voice, game, screen} {
		v := judge(f, line, begin, born, ended.Add(time.Second))
		v.want = int(wantBorn(f, begin, born))
		if v.want > 0 {
			v.deliveredShare = float64(v.got) / float64(v.want)
		}
		t.Logf("%s down: %v", f.name, v)
		switch {
		case v.deliveredShare < minShare:
			t.Errorf("%s: %.1f%% delivered, want at least %.0f%%", f.name, v.deliveredShare*100, minShare*100)
		case v.late > v.want/100:
			t.Errorf("%s: %d of %d answers later than the line's delay + 150 ms", f.name, v.late, v.want)
		case v.worst > peak+300*time.Millisecond:
			t.Errorf("%s: worst answer %v, the line's peak was %v", f.name, v.worst, peak)
		case v.lateTail > 0:
			t.Errorf("%s: %d answers late 1 s after the bloat ended", f.name, v.lateTail)
		}
	}
	bv := judge(bulk, line, begin, born, ended.Add(time.Second))
	bv.want = int(wantBorn(bulk, begin, born))
	if bv.want > 0 {
		bv.deliveredShare = float64(bv.got) / float64(bv.want)
	}
	t.Logf("bulk down: %v", bv)

	periods := book.Take()
	raw, _ := json.Marshal(periods)
	t.Logf("relay book: %s", raw)
	if !lc.responsive {
		if stale := staleDatagram(raw); stale == 0 {
			t.Errorf("the deaf bulk's undelivered %d packets are not counted as dup.stale_dgram on the relay", bv.want-bv.got)
		} else {
			t.Logf("relay dup.stale_dgram %d", stale)
		}
	}
}

// wantBorn is how many answers the far end made in [from, to].
func wantBorn(f *liveFlow, from, to time.Time) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	var n int64
	for _, b := range f.born {
		if !b.Before(from) && !b.After(to) {
			n++
		}
	}
	return n
}

// staleDatagram reads dup.stale_dgram from the relay's periods by name: the
// field is the plan's, a book without it counts zero.
func staleDatagram(raw []byte) int64 {
	var periods map[string]struct {
		Dup map[string]any `json:"dup"`
	}
	_ = json.Unmarshal(raw, &periods)
	var n int64
	for _, p := range periods {
		if v, ok := p.Dup["stale_dgram"].(float64); ok {
			n += int64(v)
		}
	}
	return n
}
