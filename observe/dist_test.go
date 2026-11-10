package observe

import (
	"encoding/json"
	"testing"
)

func TestDist(t *testing.T) {
	var d Dist
	if b, _ := json.Marshal(d); string(b) != "null" {
		t.Fatalf("empty: %s", b)
	}
	for v := 1; v <= 100; v++ {
		d.Add(float64(v))
	}
	s := d.Summary()
	// 50 sits in the bucket up to 50, 95 in the one up to 100; Max is exact.
	if s.N != 100 || s.P50 != 50 || s.P95 != 100 || s.Max != 100 {
		t.Fatalf("summary %+v", s)
	}
	var e Dist
	e.Add(7000)
	e.Merge(&d)
	if e.N() != 101 || e.Summary().Max != 7000 || e.Quantile(1) != 7000 {
		t.Fatalf("merge %+v", e.Summary())
	}
	var low Dist
	low.Add(0.4)
	if low.Quantile(0.5) != 0.4 {
		t.Fatalf("p50 above max: %v", low.Quantile(0.5))
	}
}

func TestBook(t *testing.T) {
	b := NewBook()
	n := 0
	remove := b.Add("k", func(p *Period) {
		if p.Dup == nil {
			p.Dup = &Dup{}
		}
		n++
		p.Dup.Fresh += int64(n)
	})
	b.Record("k", func(p *Period) { p.Tunnels = &Ends{}; p.Tunnels.Add(EndEOF) })
	got := b.Take()
	if got["k"].Dup.Fresh != 1 || (*got["k"].Tunnels)[EndEOF] != 1 {
		t.Fatalf("first take %+v", got["k"])
	}
	remove()
	remove()
	got = b.Take()
	if got["k"].Dup.Fresh != 2 || got["k"].Tunnels != nil {
		t.Fatalf("after remove %+v", got["k"])
	}
	if got := b.Take(); len(got) != 0 {
		t.Fatalf("empty book handed out %v", got)
	}
}
