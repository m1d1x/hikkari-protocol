// Command tcpcheck is the bench of the entry's TCP path (rust/README.md):
// with -serve it is the service behind the exit, echoing every connection;
// otherwise it is the clients: -streams connections to the entry, each
// sending -bytes of a stream of its own (a PRNG by the stream's number) and
// reading the echo back, every byte compared. It prints the time, the speed
// and, with -pid, the entry's CPU per MiB sent (each MiB crosses the entry
// twice: up and echoed down); with -exit-pid, the exit's the same way (R1.7).
//
// With -for (R1.5) each stream sends for that long instead of -bytes, and
// with -rate no faster than that many bytes a second: a download beside the
// bench's UDP users. The line then has the bytes each stream moved, every one
// still compared.
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
	exitPid := flag.Int("exit-pid", 0, "the exit's pid, for its CPU")
	label := flag.String("label", "", "a label for the result line")
	proxy := flag.String("proxy", "", "cut members: listen here")
	proxyTo := flag.String("proxy-to", "127.0.0.1:20446", "cut members: the exit's member port")
	cutAfter := flag.Duration("cut-after", 2*time.Second, "cut members: the first cut after this")
	cutEvery := flag.Duration("cut-every", 3*time.Second, "cut members: a cut this often")
	cutHow := flag.String("cut", "rst", "cut members: rst or freeze")
	dur := flag.Duration("for", 0, "send for this long instead of -bytes")
	rate := flag.Int64("rate", 0, "bytes a second per stream (0: as fast as it goes)")
	flag.Parse()
	if *serve != "" {
		echo(*serve)
		return
	}
	if *proxy != "" {
		cutter(*proxy, *proxyTo, *cutAfter, *cutEvery, *cutHow == "freeze")
		return
	}
	cpu0, xcpu0 := cpu(*pid), cpu(*exitPid)
	t0 := time.Now()
	var wg sync.WaitGroup
	errs := make([]error, *streams)
	moved := make([]int64, *streams)
	for i := range *streams {
		wg.Add(1)
		go func() {
			defer wg.Done()
			moved[i], errs[i] = check(*to, uint64(i+1), *size, *dur, *rate)
		}()
	}
	wg.Wait()
	dt := time.Since(t0)
	cpuNs := cpu(*pid) - cpu0
	xcpuNs := cpu(*exitPid) - xcpu0
	bad := 0
	for i, err := range errs {
		if err != nil {
			bad++
			log.Printf("stream %d: %v", i+1, err)
		}
	}
	var all int64
	for _, n := range moved {
		all += n
	}
	mib := float64(all) / (1 << 20)
	fmt.Printf("%s streams=%d bytes=%d ok=%d bad=%d secs=%.2f MiB/s=%.1f cpu_ms=%.0f us_per_MiB=%.1f",
		*label, *streams, all, *streams-bad, bad, dt.Seconds(), mib/dt.Seconds(), float64(cpuNs)/1e6, float64(cpuNs)/1e3/mib)
	if *exitPid != 0 {
		fmt.Printf(" exit_cpu_ms=%.0f exit_us_per_MiB=%.1f", float64(xcpuNs)/1e6, float64(xcpuNs)/1e3/mib)
	}
	fmt.Println()
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
// check sends one stream's bytes and reads them echoed, every byte
// compared: size bytes, or with dur > 0 for that long; with rate > 0 no
// faster than rate bytes a second. It gives the bytes that came back.
func check(to string, seed uint64, size int64, dur time.Duration, rate int64) (int64, error) {
	c, err := net.Dial("tcp", to)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	type sent struct {
		n   int64
		err error
	}
	done := make(chan sent, 1)
	go func() {
		w := bufio.NewWriterSize(c, 256<<10)
		r := rand.New(rand.NewPCG(seed, 1))
		buf := make([]byte, 64<<10)
		t0 := time.Now()
		var n int64
		for {
			if dur > 0 && time.Since(t0) >= dur {
				break
			}
			step := int64(len(buf))
			if dur <= 0 {
				if n >= size {
					break
				}
				step = min(step, size-n)
			}
			fill(r, buf[:step])
			if _, err := w.Write(buf[:step]); err != nil {
				done <- sent{n, err}
				return
			}
			n += step
			if rate > 0 {
				if err := w.Flush(); err != nil {
					done <- sent{n, err}
					return
				}
				time.Sleep(time.Until(t0.Add(time.Duration(n * int64(time.Second) / rate))))
			}
		}
		if err := w.Flush(); err != nil {
			done <- sent{n, err}
			return
		}
		done <- sent{n, c.(*net.TCPConn).CloseWrite()}
	}()
	// The sender fills blocks of 64 KiB (the last one shorter with -bytes):
	// the expected bytes are made block by block the same way.
	rd := bufio.NewReaderSize(c, 256<<10)
	r := rand.New(rand.NewPCG(seed, 1))
	want := make([]byte, 64<<10)
	got := make([]byte, 64<<10)
	var at int64
	var block []byte // the rest of the expected block
	for {
		n, err := rd.Read(got)
		for i := 0; i < n; {
			if len(block) == 0 {
				step := int64(len(want))
				if dur <= 0 {
					step = min(step, size-at-int64(i))
				}
				if step <= 0 {
					return at, fmt.Errorf("after %d bytes: more (want the end)", size)
				}
				fill(r, want[:step])
				block = want[:step]
			}
			k := min(len(block), n-i)
			for j := range k {
				if got[i+j] != block[j] {
					return at, fmt.Errorf("byte %d: got %#x, want %#x", at+int64(i+j), got[i+j], block[j])
				}
			}
			block = block[k:]
			i += k
		}
		at += int64(n)
		if err == io.EOF {
			break
		}
		if err != nil {
			return at, fmt.Errorf("read at %d: %w", at, err)
		}
	}
	s := <-done
	if s.err != nil {
		return at, s.err
	}
	if at != s.n {
		return at, fmt.Errorf("%d bytes back of %d sent", at, s.n)
	}
	return at, nil
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
