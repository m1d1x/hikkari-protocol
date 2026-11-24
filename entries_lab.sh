#!/usr/bin/env bash
# Several entries in the lab (entries_lab_test.go): a netns of its own, its
# loopback delayed by netem, entry 0 dropped by iptables under a call and a
# 64 MiB stream.
#
#   DELAY=10ms            netem delay of every packet on loopback: each hop
#                         of the stand (client → entry → relay) gets 20 ms of
#                         round trip
#   LAB_CUT_SECONDS=8     how long entry 0 is dropped
#   LAB_COUNT=1           runs in a row
#
# Linux (WSL2 on the PC), sudo without a password, iptables.
set -euo pipefail
cd "$(dirname "$0")"
DELAY=${DELAY:-10ms}
NS=hkentries
export PATH=$PATH:/usr/local/go/bin

go test -c -tags lab -o /tmp/hkentries.test .

sudo ip netns del $NS 2>/dev/null || true
sudo ip netns add $NS
trap 'sudo ip netns del $NS' EXIT
run() { sudo ip netns exec $NS "$@"; }
run ip link set lo up
run ip link set lo mtu 1500
run tc qdisc add dev lo root netem delay $DELAY limit 100000
echo "delay $DELAY each packet; entry 0 dropped for ${LAB_CUT_SECONDS:-8} s"
run env LAB_CUT_SECONDS="${LAB_CUT_SECONDS:-8}" /tmp/hkentries.test -test.run TestLabAnEntryDroppedByTheKernel \
	-test.v -test.count "${LAB_COUNT:-1}" -test.timeout 30m
run tc -s qdisc show dev lo | grep -E "qdisc netem|Sent|dropped" || true
