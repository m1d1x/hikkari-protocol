// gomember opens Chromium pool members the way the Go entry does
// (trunk/chromium: one engine per member) to the bench's Go exit, holds
// them up for a moment and closes them: the reference hellos the Rust
// pipe's members are checked against (hellocheck). Linux builds take
// -tags with_purego and load libcronet.so from -cronet's directory.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"sync"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk/chromium"
)

func main() {
	exit := flag.String("exit", "127.0.0.1:20445", "the exit's relay channel, ip:port")
	sni := flag.String("sni", "hk.example", "the relay's domain")
	key := flag.String("key", "bench-trunk-key-0123456789abcdef", "the trunk key")
	roots := flag.String("roots", "/bench/out/naive-roots.pem", "the relay certificate's PEM")
	n := flag.Int("members", 4, "members to open")
	flag.Parse()
	if err := chromium.Load(); err != nil {
		log.Fatalf("gomember: %v", err)
	}
	pem, err := os.ReadFile(*roots)
	if err != nil {
		log.Fatalf("gomember: %v", err)
	}
	d := chromium.Dialer{Exit: *exit, SNI: *sni, Key: *key, Roots: string(pem)}
	log.Printf("gomember: Chromium %s, %d members to %s", chromium.Version(), *n, *exit)
	var wg sync.WaitGroup
	failed := 0
	var mu sync.Mutex
	for i := 0; i < *n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m, err := d.Dial(context.Background(), 0)
			if err != nil {
				mu.Lock()
				failed++
				mu.Unlock()
				log.Printf("gomember: %v", err)
				return
			}
			time.Sleep(500 * time.Millisecond)
			_ = m.Close()
		}()
	}
	wg.Wait()
	log.Printf("gomember: %d up, %d failed", *n-failed, failed)
	if failed > 0 {
		os.Exit(1)
	}
}
