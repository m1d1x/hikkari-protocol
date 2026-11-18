#!/bin/sh
# Copies on the pool on demand (hikkari-client
# plans/2026-11-18-copies-on-demand.md): the same users as run.sh (hk-loadgen:
# voice, game, acks on one flow each, the voice class) through hk-pipe to
# hk-exit, the bare UDP wire and a plain TCP pool, under a Gilbert cut of the
# UDP wire. A mode is off (the UDP wire alone), always (two fates, a copy of
# every datagram on the pool, the people's route since 15.11) or od (two
# fates, the pool's copy only while an end lost datagrams on the UDP wire,
# held HOLD_MS after the last loss). A cut is none, up (entry to exit) or
# down: netem loss gemodel 14.7% 67% (the stand's cut of 15.11) on the UDP
# wire's port (trickle: 0.1% at random up, the wire's own loss on a day,
# which must start no copies)
# in two episodes of CUT_S seconds CUT_GAP_S apart, so that od
# turns its copies on twice from off. The exit lives in a network namespace
# of its own behind a veth pair, the cut on the veth: WSL2's loopback takes
# no qdisc (tc counts no packet on lo). The entry on CPUs 0-1, the exit on
# 4-5, the users on 2-3. Needs root (ip netns, tc).
#
#   fates-od.sh <reps> <secs> <users> "<modes>" "<cuts>"
#   e.g. fates-od.sh 2 90 8 "off always od" "none up down"
set -eu
OUT=${OUT:-/root/hk-od/target/release}
RES=${RES:-/root/hk-od/results-od.txt}
REPS=${1:-2}; SECS=${2:-90}; USERS=${3:-8}; MODES=${4:-"off always od"}; CUTS=${5:-"none up down"}
HOLD_MS=${HOLD_MS:-300000}
CUT_AT=${CUT_AT:-10}; CUT_S=${CUT_S:-15}; CUT_GAP_S=${CUT_GAP_S:-35}
EXIT_CPUS=${EXIT_CPUS:-4,5}; GEN_CPUS=${GEN_CPUS:-2,3}; ENTRY_CPUS=${ENTRY_CPUS:-0,1}
WIRE_PORT=20447; EXIT_IP=10.77.0.2; POOL=$EXIT_IP:20446

net_up() {
  net_down
  ip netns add hkx
  ip link add hkv0 type veth peer name hkv1
  ip link set hkv1 netns hkx
  ip addr add 10.77.0.1/24 dev hkv0; ip link set hkv0 up
  ip netns exec hkx ip addr add $EXIT_IP/24 dev hkv1
  ip netns exec hkx ip link set hkv1 up; ip netns exec hkx ip link set lo up
}

net_down() { ip netns del hkx 2>/dev/null || true; ip link del hkv0 2>/dev/null || true; }

cut_off() {
  tc qdisc del dev hkv0 root 2>/dev/null || true
  ip netns exec hkx tc qdisc del dev hkv1 root 2>/dev/null || true
}

# The cut on the wire's packets one way: to the exit's port on the entry's
# end of the veth (up) or from it on the exit's end (down); the pool's TCP
# untouched.
cut_on() {
  case $1 in
    up|trickle) ns=""; dev=hkv0; port=dport ;;
    down) ns="ip netns exec hkx"; dev=hkv1; port=sport ;;
  esac
  loss="gemodel 14.7% 67%"; [ "$1" != trickle ] || loss="random 0.1%"
  $ns tc qdisc add dev $dev root handle 1: prio bands 4 priomap 1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1
  $ns tc qdisc add dev $dev parent 1:4 handle 40: netem loss $loss
  $ns tc filter add dev $dev parent 1:0 protocol ip prio 1 u32 match ip protocol 17 0xff match ip $port $WIRE_PORT 0xffff flowid 1:4
}

episodes() {
  sleep "$CUT_AT"; cut_on "$1"; sleep "$CUT_S"; cut_off
  sleep "$CUT_GAP_S"; cut_on "$1"; sleep "$CUT_S"; cut_off
}

run_one() {
  mode=$1; cut=$2; rep=$3
  fates=""
  case $mode in
    always) fates="--two-fates 1" ;;
    od) fates="--two-fates 1 --copies-on-demand-ms $HOLD_MS" ;;
  esac
  cut_off
  ip netns exec hkx taskset -c "$EXIT_CPUS" "$OUT/hk-exit" --listen "$EXIT_IP:$WIRE_PORT" --pool "$POOL" --ports 9000 >/root/hk-od/exit.log 2>&1 &
  xpid=$!
  sleep 0.5
  taskset -c "$ENTRY_CPUS" "$OUT/hk-pipe" --members 2 --copies 1 --wire "$EXIT_IP:$WIRE_PORT" $fates \
    --tcp-wire "$POOL" --tcp-listen 127.0.0.1:8444 --tcp-to 9000 --tcp-members 8 >/root/hk-od/entry.log 2>&1 &
  epid=$!
  sleep 3
  cpid=
  if [ "$cut" != none ]; then
    episodes "$cut" &
    cpid=$!
  fi
  line=$(taskset -c "$GEN_CPUS" "$OUT/hk-loadgen" --users "$USERS" --secs "$SECS" --warm 0 --pid "$epid" --label "od-$mode-$cut#$rep") || true
  [ -z "$cpid" ] || wait "$cpid" 2>/dev/null || true
  cut_off
  sleep 11 # one stats line of each end past the run
  e=$(grep -o 'demand=[0-9/]*' /root/hk-od/entry.log | tail -n 1)
  x=$(grep -o 'demand=[0-9/]*' /root/hk-od/exit.log | tail -n 1)
  echo "$line entry_$e exit_$x" | tee -a "$RES"
  kill $epid $xpid 2>/dev/null || true
  wait $epid $xpid 2>/dev/null || true
}

net_up
trap net_down EXIT
for rep in $(seq 1 "$REPS"); do
  for cut in $CUTS; do
    for mode in $MODES; do
      run_one "$mode" "$cut" "$rep"
    done
  done
done
