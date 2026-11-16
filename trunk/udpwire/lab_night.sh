#!/usr/bin/env bash
# The night of 14.11 on the bench (lab_night_test.go): a netns of its own,
# its loopback shaped by netem by the exit's ports, the test run in it.
#
#   UDP_LOSS='random 18%'  netem loss of the udp wire's datagrams to the exit
#   TCP_LOSS='random 1%'   netem loss of the pool's segments to the exit
#   DELAY=21ms             each way, the path's half round trip
#   LAB_SECONDS=120 LAB_OUT=/tmp/night.json
#
# Linux (WSL2 on the PC), sudo without a password. Losses only on the way to
# the exit: the call's round trip loses what the night lost, one way.
set -euo pipefail
cd "$(dirname "$0")/.."
UDP_LOSS=${UDP_LOSS:-random 18%}
TCP_LOSS=${TCP_LOSS:-random 1%}
DELAY=${DELAY:-21ms}
NS=hklab
export PATH=$PATH:/usr/local/go/bin

go test -c -tags lab -o /tmp/hklab.test ./udpwire

sudo ip netns del $NS 2>/dev/null || true
sudo ip netns add $NS
trap 'sudo ip netns del $NS' EXIT
run() { sudo ip netns exec $NS "$@"; }
run ip link set lo up
run ip link set lo mtu 1500
run tc qdisc add dev lo root handle 1: prio bands 4 priomap 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3
# 1:1 the udp wire to the exit, 1:2 the pool to the exit, 1:3 back from it.
run tc qdisc add dev lo parent 1:1 handle 10: netem delay $DELAY loss $UDP_LOSS limit 10000
run tc qdisc add dev lo parent 1:2 handle 20: netem delay $DELAY loss $TCP_LOSS limit 10000
run tc qdisc add dev lo parent 1:3 handle 30: netem delay $DELAY limit 10000
run tc filter add dev lo parent 1: protocol ip prio 1 u32 match ip protocol 17 0xff match ip dport 47001 0xffff flowid 1:1
run tc filter add dev lo parent 1: protocol ip prio 2 u32 match ip protocol 6 0xff match ip dport 47002 0xffff flowid 1:2
run tc filter add dev lo parent 1: protocol ip prio 3 u32 match ip sport 47001 0xffff flowid 1:3
run tc filter add dev lo parent 1: protocol ip prio 4 u32 match ip sport 47002 0xffff flowid 1:3
echo "udp loss: $UDP_LOSS; tcp loss: $TCP_LOSS; delay $DELAY each way"
run env LAB_SECONDS="${LAB_SECONDS:-120}" LAB_OUT="${LAB_OUT:-}" /tmp/hklab.test -test.run TestNight -test.v -test.timeout 30m
run tc -s qdisc show dev lo | grep -E "qdisc netem|Sent|dropped" || true
