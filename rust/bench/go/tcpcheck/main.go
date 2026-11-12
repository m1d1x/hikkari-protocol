// Command tcpcheck is the bench of the entry's TCP path (rust/README.md):
// with -serve it is the service behind the exit, echoing every connection;
// otherwise it is the clients: -streams connections to the entry, each
// sending -bytes of a stream of its own (a PRNG by the stream's number) and
// reading the echo back, every byte compared. It prints the time, the speed
// and, with -pid, the entry's CPU per MiB sent (each MiB crosses the entry
// twice: up and echoed down).
//
// With -proxy it is a cutter between an entry's stream members and the exit
// (R1.4): every connection to -proxy is carried to -proxy-to, and every
// -cut-every, from -cut-after on, the connection that carried most since
// the last cut is cut: -cut rst closes both sides at once (the member's
// socket fails), -cut freeze stops carrying it either way (the member goes
// silent and dies by its stall; its sockets close a minute later).
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	serve := flag.String("serve", "", "echo on this address")
	to := flag.String("to", "127.0.0.1:8444", "the entry's client TCP port")
	size := flag.Int64("bytes", 1<<30, "bytes per stream")
	streams := flag.Int("streams", 1, "streams at once")
	pid := flag.Int("pid", 0, "the entry's pid, for its CPU")
	label := flag.String("label", "", "a label for the result line")
	proxy := flag.String("proxy", "", "cut members: listen here")
	proxyTo := flag.String("proxy-to", "127.0.0.1:20446", "cut members: the exit's member port")
	cutAfter := flag.Duration("cut-after", 2*time.Second, "cut members: the first cut after this")
	cutEvery := flag.Duration("cut-every", 3*time.Second, "cut members: a cut this often")
	cutHow := flag.String("cut", "rst", "cut members: rst or freeze")
	flag.Parse()
	if *serve != "" {
		echo(*serve)
		return
	}
	if *proxy != "" {
		cutter(*proxy, *proxyTo, *cutAfter, *cutEvery, *cutHow == "freeze")
		return
	}
	cpu0 := cpu(*pid)
	t0 := time.Now()
	var wg sync.WaitGroup
	errs := make([]error, *streams)
	for i := range *streams {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = check(*to, uint64(i+1), *size)
		}()
	}
	wg.Wait()
	dt := time.Since(t0)
	cpuNs := cpu(*pid) - cpu0
	bad := 0
	for i, err := range errs {
		if err != nil {
			bad++
			log.Printf("stream %d: %v", i+1, err)
		}
	}
	mib := float64(*size*int64(*streams)) / (1 << 20)
	fmt.Printf("%s streams=%d bytes=%d ok=%d bad=%d secs=%.2f MiB/s=%.1f cpu_ms=%.0f us_per_MiB=%.1f\n",
		*label, *streams, *size, *streams-bad, bad, dt.Seconds(), mib/dt.Seconds(), float64(cpuNs)/1e6, float64(cpuNs)/1e3/mib)
	if bad > 0 {
		os.Exit(1)
	}
}

func echo(addr string) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	for {
		c, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			defer c.Close()
			_, _ = io.Copy(c, c)
			_ = c.(*net.TCPConn).CloseWrite()
		}()
	}
}

// pair is one member's connection through the cutter.
type pair struct {
	in, out *net.TCPConn
	moved   atomic.Int64 // bytes carried since the last cut
	frozen  atomic.Bool
}

func cutter(addr, to string, after, every time.Duration, freeze bool) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	var mu sync.Mutex
	pairs := map[*pair]struct{}{}
	go func() {
		time.Sleep(after)
		for n := 1; ; n++ {
			mu.Lock()
			var best *pair
			for p := range pairs {
				if !p.frozen.Load() && (best == nil || p.moved.Load() > best.moved.Load()) {
					best = p
				}
			}
			for p := range pairs {
				p.moved.Store(0)
			}
			if best != nil {
				delete(pairs, best)
			}
			live := len(pairs)
			mu.Unlock()
			if best != nil {
				if freeze {
					best.frozen.Store(true)
					time.AfterFunc(time.Minute, func() { best.in.Close(); best.out.Close() })
				} else {
					best.in.SetLinger(0)
					best.out.SetLinger(0)
					best.in.Close()
					best.out.Close()
				}
				log.Printf("cut %d (%s), %d others", n, map[bool]string{true: "freeze", false: "rst"}[freeze], live)
			}
			time.Sleep(every)
		}
	}()
	for {
		c, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			x, err := net.Dial("tcp", to)
			if err != nil {
				c.Close()
				return
			}
			p := &pair{in: c.(*net.TCPConn), out: x.(*net.TCPConn)}
			mu.Lock()
			pairs[p] = struct{}{}
			mu.Unlock()
			done := func() {
				mu.Lock()
				delete(pairs, p)
				mu.Unlock()
				if !p.frozen.Load() {
					p.in.Close()
					p.out.Close()
				}
			}
			go func() { carry(p, p.out, p.in); done() }()
			carry(p, p.in, p.out)
			done()
		}()
	}
}

// carry copies src to dst until either fails or the pair is frozen.
func carry(p *pair, dst, src *net.TCPConn) {
	buf := make([]byte, 64<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 && !p.frozen.Load() {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
			p.moved.Add(int64(n))
		}
		if err != nil {
			return
		}
	}
}

// check sends size bytes of stream seed's PRNG, half-closes, and reads them
// back, comparing every byte and expecting the end right after.
func check(to string, seed uint64, size int64) error {
	c, err := net.Dial("tcp", to)
	if err != nil {
		return err
	}
	defer c.Close()
	werr := make(chan error, 1)
	go func() {
		w := bufio.NewWriterSize(c, 256<<10)
		r := rand.New(rand.NewPCG(seed, 1))
		buf := make([]byte, 64<<10)
		for left := size; left > 0; {
			n := int64(len(buf))
			if left < n {
				n = left
			}
			fill(r, buf[:n])
			if _, err := w.Write(buf[:n]); err != nil {
				werr <- err
				return
			}
			left -= n
		}
		if err := w.Flush(); err != nil {
			werr <- err
			return
		}
		werr <- c.(*net.TCPConn).CloseWrite()
	}()
	rd := bufio.NewReaderSize(c, 256<<10)
	r := rand.New(rand.NewPCG(seed, 1))
	want := make([]byte, 64<<10)
	got := make([]byte, 64<<10)
	var at int64
	for at < size {
		n := int64(len(want))
		if size-at < n {
			n = size - at
		}
		fill(r, want[:n])
		if _, err := io.ReadFull(rd, got[:n]); err != nil {
			return fmt.Errorf("read at %d of %d: %w", at, size, err)
		}
		for i := range n {
			if got[i] != want[i] {
				return fmt.Errorf("byte %d: got %#x, want %#x", at+i, got[i], want[i])
			}
		}
		at += n
	}
	if n, err := rd.Read(got[:1]); n != 0 || err != io.EOF {
		return fmt.Errorf("after %d bytes: %d more, %v (want the end)", size, n, err)
	}
	return <-werr
}

func fill(r *rand.Rand, b []byte) {
	for i := 0; i+8 <= len(b); i += 8 {
		v := r.Uint64()
		for k := range 8 {
			b[i+k] = byte(v >> (8 * k))
		}
	}
	for i := len(b) &^ 7; i < len(b); i++ {
		b[i] = byte(r.Uint64())
	}
}

// cpu is a process's CPU time in ns (/proc/<pid>/stat utime + stime), 0
// without one.
func cpu(pid int) int64 {
	if pid == 0 {
		return 0
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0
	}
	s := string(b)
	f := strings.Fields(s[strings.LastIndexByte(s, ')')+2:])
	u, _ := strconv.ParseInt(f[11], 10, 64)
	k, _ := strconv.ParseInt(f[12], 10, 64)
	return (u + k) * int64(time.Second/100) // clock ticks of 10 ms (USER_HZ 100)
}
