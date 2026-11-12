#!/bin/sh
# Bench of the entry's UDP path: the same users through the Go entry
# (bench/go/goentry, trunk + udpwire as production) and through hk-pipe, to
# the same Go exit (bench/go/goexit). Runs inside a Linux box (docker on the
# mac, see README.md). The entry is held to 2 CPUs (taskset 0,1), the users
# and the exit to CPUs of their own, so the entry's CPU is its own.
#
#   run.sh <reps> <secs> "<users...>" [impls]    e.g. run.sh 3 30 "1 4 16 64" "go rust"
# EXIT=go|rust picks the exit under test: go (bench/go/goexit, a datagram per
# echo frame) or rust (hk-exit, frames glued down per tick, R1).
set -eu
OUT=${OUT:-/bench/out}
REPS=${1:-3}; SECS=${2:-30}; USERS=${3:-"1 4 16 64"}; IMPLS=${4:-"go rust"}
GLUE_US=${GLUE_US:-1000}
EXIT=${EXIT:-go}
RES=${RES:-$OUT/results.txt}
EXIT_CPUS=${EXIT_CPUS:-4,5}; GEN_CPUS=${GEN_CPUS:-2,3}; ENTRY_CPUS=${ENTRY_CPUS:-0,1}

run_one() {
  impl=$1; users=$2; rep=$3
  case $EXIT in
    go)   taskset -c "$EXIT_CPUS" "$OUT/goexit" >"$OUT/exit.log" 2>&1 & ;;
    rust) taskset -c "$EXIT_CPUS" "$OUT/hk-exit" --glue-us "$GLUE_US" >"$OUT/exit.log" 2>&1 & ;;
  esac
  xpid=$!
  sleep 0.5
  case $impl in
    go)   taskset -c "$ENTRY_CPUS" "$OUT/goentry" >"$OUT/entry-$impl.log" 2>&1 & ;;
    rust) taskset -c "$ENTRY_CPUS" "$OUT/hk-pipe" --glue-us "$GLUE_US" >"$OUT/entry-$impl.log" 2>&1 & ;;
    rust2) taskset -c "$ENTRY_CPUS" "$OUT/hk-pipe" --glue-us 2000 --tick-us 2000 >"$OUT/entry-$impl.log" 2>&1 & ;;
    rustev) taskset -c "$ENTRY_CPUS" "$OUT/hk-pipe" --glue-us "$GLUE_US" --tick-us 0 >"$OUT/entry-$impl.log" 2>&1 & ;;
  esac
  epid=$!
  sleep 1.5
  line=$(taskset -c "$GEN_CPUS" "$OUT/hk-loadgen" --users "$users" --secs "$SECS" --warm 5 --pid "$epid" --label "$impl#$rep")
  echo "$line" | tee -a "$RES"
  kill $epid $xpid 2>/dev/null || true
  wait $epid $xpid 2>/dev/null || true
  tail -n 2 "$OUT/entry-$impl.log" | sed "s/^/  [$impl u$users] /"
}

for rep in $(seq 1 "$REPS"); do
  for u in $USERS; do
    for impl in $IMPLS; do
      run_one "$impl" "$u" "$rep"
    done
  done
done
