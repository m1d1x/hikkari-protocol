// Package observe is Hikkari v1.04's observability: each end counts what it
// already sees of its sessions and hands out a summary of the period
// (spec/v1.md, v1.04). Nothing here touches the wire, and no summary holds an
// address, a destination or a key: a relay keys its summaries by the access
// key only to hand them to the hub, which knows the key's account.
package observe

import (
	"encoding/json"
	"math"
	"sort"
)

// bounds are the upper edges of Dist's buckets. They suit milliseconds and
// per-mille shares alike: fine at the bottom, where a call's pauses and a
// clean path's losses live, coarse at the top.
var bounds = [...]float64{
	0, 1, 2, 3, 4, 5, 6, 8, 10, 12, 15, 20, 25, 30, 40, 50, 60, 70, 80, 100, 120,
	150, 200, 250, 300, 400, 500, 600, 800, 1000, 1200, 1500, 2000, 2500, 3000,
	4000, 5000, 6000, 8000, 10000, 15000, 20000, 30000, 60000, math.Inf(1),
}

// Dist is a distribution of one period: fixed buckets, so two of them merge
// exactly and one costs the same whatever it counts. A percentile reads as
// the upper edge of its bucket; Max is exact.
type Dist struct {
	n       int64
	max     float64
	buckets [len(bounds)]int64
}

// Add counts one value; a negative one counts as 0.
func (d *Dist) Add(v float64) {
	if v < 0 || math.IsNaN(v) {
		v = 0
	}
	i := sort.SearchFloat64s(bounds[:], v)
	d.buckets[i]++
	if d.n == 0 || v > d.max {
		d.max = v
	}
	d.n++
}

// Merge adds o's values.
func (d *Dist) Merge(o *Dist) {
	if o.n == 0 {
		return
	}
	if d.n == 0 || o.max > d.max {
		d.max = o.max
	}
	d.n += o.n
	for i, c := range o.buckets {
		d.buckets[i] += c
	}
}

// N is how many values were added.
func (d *Dist) N() int64 { return d.n }

// Quantile is the upper edge of the bucket holding the q-th value, or Max
// when that is lower.
func (d *Dist) Quantile(q float64) float64 {
	if d.n == 0 {
		return 0
	}
	rank := int64(math.Ceil(q * float64(d.n)))
	if rank < 1 {
		rank = 1
	}
	var seen int64
	for i, c := range d.buckets {
		seen += c
		if seen >= rank {
			return math.Min(bounds[i], d.max)
		}
	}
	return d.max
}

// Summary is a Dist as it goes to the hub.
type Summary struct {
	N   int64   `json:"n"`
	P50 float64 `json:"p50"`
	P95 float64 `json:"p95"`
	Max float64 `json:"max"`
}

// Summary reads the distribution.
func (d *Dist) Summary() Summary {
	return Summary{N: d.n, P50: d.Quantile(0.5), P95: d.Quantile(0.95), Max: d.max}
}

// MarshalJSON writes the Summary; an empty Dist is null.
func (d Dist) MarshalJSON() ([]byte, error) {
	if d.n == 0 {
		return []byte("null"), nil
	}
	return json.Marshal(d.Summary())
}
