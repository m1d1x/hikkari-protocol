// hellocheck names the ClientHellos the Go exit recorded (goexit
// -naive-hellos) by the client release test's fingerprints and checks two
// sets against each other: every hello of -got has the one hk of every
// hello of -ref, and -got has at least -want of them. It prints each set's
// hk and ja4 with their counts.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/m1d1x/hikkari-protocol/rust/bench/go/hello"
)

func main() {
	ref := flag.String("ref", "", "the reference hellos' directory")
	got := flag.String("got", "", "the hellos under check")
	want := flag.Int("want", 1, "hellos -got must have")
	flag.Parse()
	refs, err := names(*ref)
	if err != nil {
		fail(err)
	}
	gots, err := names(*got)
	if err != nil {
		fail(err)
	}
	show("ref", refs)
	show("got", gots)
	ok := len(refs) == 1 && len(gots) == 1 && count(gots) >= *want
	for k := range gots {
		if _, same := refs[k]; !same {
			ok = false
		}
	}
	if !ok {
		fail(fmt.Errorf("the hellos differ from the reference, or fewer than %d", *want))
	}
	fmt.Println("hellocheck: PASS")
}

// names counts a directory's hellos by "hk ja4".
func names(dir string) (map[string]int, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.bin"))
	if err != nil || len(files) == 0 {
		return nil, fmt.Errorf("no hellos in %s", dir)
	}
	out := map[string]int{}
	for _, f := range files {
		msg, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		hk, ja4, err := hello.Names(msg)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		out[hk+" "+ja4]++
	}
	return out, nil
}

func count(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

func show(label string, m map[string]int) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("hellocheck: %s %s x%d\n", label, k, m[k])
	}
}

func fail(err error) {
	fmt.Println("hellocheck: FAIL:", err)
	os.Exit(1)
}
