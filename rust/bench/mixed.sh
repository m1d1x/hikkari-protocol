#!/bin/sh
# Bench of the entry's UDP and TCP paths at once (R1.5): the bench's UDP
# users (hk-loadgen, cascade-load-v1) through the entry while clients'
# streams download through the same entry (tcpcheck -for, echoed by the
# service behind the exit), the Go entry (bench/go/goentry) against hk-pipe,
# both to the same Go exit: UDP on the bare udp wire, streams on plain TCP
# members. Runs inside a Linux box (docker on the mac, README.md).
#
# Loads: none (users alone, the price per packet), rate (STREAMS streams at
# RATE bytes a second each, a line's download), flood (STREAMS streams as
# fast as they go). One line per run: hk-loadgen's (the entry's CPU over its
# window, voice gaps, rtt, losses) and tcpcheck's after it, prefixed tcp_.
#
# CPUs: the entry 0-1, the users 2-3, the exit 4-5, the stream clients 6-7,
# the echo 8-9, so neither load takes the other's CPU outside the entry.
#
#   mixed.sh <reps> <secs> "<users...>" "<impls>" "<loads>"
#   e.g. mixed.sh 3 30 "16 64" "go rust" "none rate flood"
set -eu
OUT=${OUT:-/bench/out}
REPS=${1:-3}; SECS=${2:-30}; USERS=${3:-"16 64"}; IMPLS=${4:-"go rust"}; LOADS=${5:-"none rate flood"}
RES=${RES:-$OUT/results-mixed.txt}
STREAMS=${STREAMS:-4}; RATE=${RATE:-3276800}; MEMBERS=${MEMBERS:-4}; WARM=${WARM:-5}
ENTRY_CPUS=${ENTRY_CPUS:-0,1}; GEN_CPUS=${GEN_CPUS:-2,3}; EXIT_CPUS=${EXIT_CPUS:-4,5}
TCP_CPUS=${TCP_CPUS:-6,7}; ECHO_CPUS=${ECHO_CPUS:-8,9}
# PIPE: the hk-pipe to run as rust (another build to compare).

run_one() {
  impl=$1; users=$2; load=$3; rep=$4
  taskset -c "$ECHO_CPUS" "$OUT/tcpcheck" -serve 127.0.0.1:9000 >"$OUT/echo.log" 2>&1 &
  echo_pid=$!
  taskset -c "$EXIT_CPUS" "$OUT/goexit" >"$OUT/exit.log" 2>&1 &
  xpid=$!
  sleep 0.5
  case $impl in
    go)   taskset -c "$ENTRY_CPUS" "$OUT/goentry" -tcp-listen 127.0.0.1:8444 -tcp-to 9000 -pool-members "$MEMBERS" >"$OUT/entry-mixed-$impl.log" 2>&1 & ;;
    rust) taskset -c "$ENTRY_CPUS" "${PIPE:-$OUT/hk-pipe}" --tcp-listen 127.0.0.1:8444 --tcp-to 9000 --tcp-members "$MEMBERS" >"$OUT/entry-mixed-$impl.log" 2>&1 & ;;
  esac
  epid=$!
  sleep 1.5
  label="$impl#$rep"
  tpid=
  case $load in
    rate)  taskset -c "$TCP_CPUS" "$OUT/tcpcheck" -to 127.0.0.1:8444 -streams "$STREAMS" -for "$((WARM + SECS + 2))s" -rate "$RATE" -pid "$epid" -label tcp >"$OUT/tcp.line" 2>"$OUT/tcp.err" & tpid=$! ;;
    flood) taskset -c "$TCP_CPUS" "$OUT/tcpcheck" -to 127.0.0.1:8444 -streams "$STREAMS" -for "$((WARM + SECS + 2))s" -pid "$epid" -label tcp >"$OUT/tcp.line" 2>"$OUT/tcp.err" & tpid=$! ;;
  esac
  line=$(taskset -c "$GEN_CPUS" "$OUT/hk-loadgen" --users "$users" --secs "$SECS" --warm "$WARM" --pid "$epid" --label "$label")
  tline=
  if [ -n "$tpid" ]; then
    wait $tpid || true
    tline=$(sed 's/^tcp //; s/\([^ ]*=\)/tcp_\1/g' "$OUT/tcp.line")
    [ -s "$OUT/tcp.err" ] && sed "s/^/  [$impl tcp] /" "$OUT/tcp.err"
  fi
  echo "$line load=$load $tline" | tee -a "$RES"
  kill $epid $xpid $echo_pid 2>/dev/null || true
  wait $epid $xpid $echo_pid 2>/dev/null || true
  tail -n 1 "$OUT/entry-mixed-$impl.log" | sed "s/^/  [$impl u$users $load] /"
}

for rep in $(seq 1 "$REPS"); do
  for u in $USERS; do
    for load in $LOADS; do
      for impl in $IMPLS; do
        run_one "$impl" "$u" "$load" "$rep"
      done
    done
  done
done
