//go:build lab

package hikkari_test

// Several entries in the lab (entries_lab.sh): the stand of entries_test.go
// in a netns of its own, its loopback delayed by netem, and the cut of entry
// 0 made by the kernel, as a silent entry is: iptables drops every packet to
// and from entry 0's port, both TCP and UDP, so the client's TCP backs off
// and retransmits as it would on the way to aezamsk1.
//
// Run as root in the lab's netns (entries_lab.sh does it):
//
//	go test -c -tags lab -o /tmp/hkentries.test .
//	ip netns exec hkentries /tmp/hkentries.test -test.run TestLabAnEntryDroppedByTheKernel -test.v
//
// LAB_CUT_SECONDS is how long entry 0 is dropped (default 8: aezamsk1 goes
// silent for 6–10 s).

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

// The entries' ports the lab's rules know (entries_lab.sh).
const (
	labEntry0 = "47101"
	labEntry1 = "47102"
)

// labDrop adds (on) or deletes the rules that drop entry 0's packets both
// ways, TCP and UDP.
func labDrop(t *testing.T, on bool) {
	op := "-D"
	if on {
		op = "-I"
	}
	for _, proto := range []string{"tcp", "udp"} {
		for _, rule := range [][]string{
			{op, "INPUT", "-p", proto, "--dport", labEntry0, "-j", "DROP"},
			{op, "OUTPUT", "-p", proto, "--sport", labEntry0, "-j", "DROP"},
		} {
			args := append([]string{"-w"}, rule...)
			if out, err := exec.Command("iptables", args...).CombinedOutput(); err != nil {
				t.Errorf("iptables %v: %v: %s", args, err, out)
			}
		}
	}
}

func TestLabAnEntryDroppedByTheKernel(t *testing.T) {
	cutFor := 8 * time.Second
	if v, err := strconv.Atoi(os.Getenv("LAB_CUT_SECONDS")); err == nil && v > 0 {
		cutFor = time.Duration(v) * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := newEntriesStand(t, ctx, [2]string{"127.0.0.1:" + labEntry0, "127.0.0.1:" + labEntry1})
	dropped := false
	defer func() {
		if dropped {
			labDrop(t, false)
		}
	}()
	runEntryCut(t, ctx, s, func(on bool) {
		if on != dropped {
			labDrop(t, on)
			dropped = on
		}
	}, cutFor)
}
