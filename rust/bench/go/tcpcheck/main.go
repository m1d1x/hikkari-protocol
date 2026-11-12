// Command tcpcheck is the bench of the entry's TCP path (rust/README.md):
// with -serve it is the service behind the exit, echoing every connection;
// otherwise it is the clients: -streams connections to the entry, each
// sending -bytes of a stream of its own (a PRNG by the stream's number) and
// reading the echo back, every byte compared. It prints the time, the speed
// and, with -pid, the entry's CPU per MiB sent (each MiB crosses the entry
// twice: up and echoed down).
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
	"time"
)

func main() {
	serve := flag.String("serve", "", "echo on this address")
	to := flag.String("to", "127.0.0.1:8444", "the entry's client TCP port")
	size := flag.Int64("bytes", 1<<30, "bytes per stream")
	streams := flag.Int("streams", 1, "streams at once")
	pid := flag.Int("pid", 0, "the entry's pid, for its CPU")
	label := flag.String("label", "", "a label for the result line")
	flag.Parse()
	if *serve != "" {
		echo(*serve)
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
