#!/bin/sh
# Bench of the entry's TCP path (R1.3): clients' streams through the Go
# entry (bench/go/goentry, trunk.Session Carry as production) and through
# hk-pipe, both over plain TCP members to the same Go exit, whose streams
# reach an echo (bench/go/tcpcheck -serve). tcpcheck sends each stream's
# bytes, reads the echo and compares every byte; it reads the entry's CPU.
# Runs inside a Linux box (docker on the mac, README.md); the entry on CPUs
# 0-1, the exit and echo on 4-5, the clients on 2-3.
#
# With EXIT=rust (R1.7) the exit is hk-exit, its pool on the same port and
# its streams to the echo's port 9000 (its own UDP wire on 20447); the line
# then has the exit's CPU per MiB too (exit_us_per_MiB, either exit).
#
# Impl chromium (R2.1): hk-pipe's stream members are Chromium's CONNECT
# (hikkari-cronet, libcronet.so from $OUT) to the Go exit's relay channel
# (goexit -naive, its certificate trusted from $OUT/naive-roots.pem); the
# pipe is the glibc build (PIPE_GNU), since libcronet is a glibc library.
#
# With CUT=rst or CUT=freeze (R1.4) the members go through tcpcheck -proxy,
# which cuts the busiest member every CUT_EVERY (3s) from CUT_AFTER (2s);
# Chromium's members too (R2.2), the proxy in front of the relay channel.
#
#   tcp.sh <reps> "<impls>" <bytes> <streams> <members>    e.g. tcp.sh 3 "go rust" 1073741824 1 4
set -eu
OUT=${OUT:-/bench/out}
REPS=${1:-3}; IMPLS=${2:-"go rust"}; BYTES=${3:-1073741824}; STREAMS=${4:-1}; MEMBERS=${5:-4}
RES=${RES:-$OUT/results-tcp.txt}
EXIT_CPUS=${EXIT_CPUS:-4,5}; GEN_CPUS=${GEN_CPUS:-2,3}; ENTRY_CPUS=${ENTRY_CPUS:-0,1}
# PIPE: the hk-pipe to run as rust (another build to compare).
CUT=${CUT:-}; CUT_EVERY=${CUT_EVERY:-3s}; CUT_AFTER=${CUT_AFTER:-2s}
POOL=127.0.0.1:20446
NAIVE=127.0.0.1:20445
EXIT=${EXIT:-go}

run_one() {
  impl=$1; rep=$2
  taskset -c "$EXIT_CPUS" "$OUT/tcpcheck" -serve 127.0.0.1:9000 >"$OUT/echo.log" 2>&1 &
  epid_echo=$!
  case $EXIT in
    go)   taskset -c "$EXIT_CPUS" "$OUT/goexit" -naive "$NAIVE" >"$OUT/exit.log" 2>&1 & ;;
    rust) taskset -c "$EXIT_CPUS" "${HK_EXIT:-$OUT/hk-exit}" --pool "$POOL" --ports 9000 >"$OUT/exit.log" 2>&1 & ;;
  esac
  xpid=$!
  pool=$POOL; naive=$NAIVE; cpid=
  if [ -n "$CUT" ]; then
    to=$POOL; [ "$impl" = chromium ] && to=$NAIVE
    taskset -c "$EXIT_CPUS" "$OUT/tcpcheck" -proxy 127.0.0.1:20500 -proxy-to "$to" -cut "$CUT" -cut-every "$CUT_EVERY" -cut-after "$CUT_AFTER" >"$OUT/cut-$impl.log" 2>&1 &
    cpid=$!
    pool=127.0.0.1:20500; naive=127.0.0.1:20500
  fi
  sleep 0.5
  case $impl in
    go)   taskset -c "$ENTRY_CPUS" "$OUT/goentry" -pool "$pool" -tcp-listen 127.0.0.1:8444 -tcp-to 9000 -pool-members "$MEMBERS" >"$OUT/entry-tcp-$impl.log" 2>&1 & ;;
    rust) taskset -c "$ENTRY_CPUS" "${PIPE:-$OUT/hk-pipe}" --tcp-wire "$pool" --tcp-listen 127.0.0.1:8444 --tcp-to 9000 --tcp-members "$MEMBERS" >"$OUT/entry-tcp-$impl.log" 2>&1 & ;;
    chromium) taskset -c "$ENTRY_CPUS" "${PIPE_GNU:-$OUT/hk-pipe-gnu}" --tcp-wire "$naive" --tcp-chromium hk.example --tcp-roots "$OUT/naive-roots.pem" --cronet "$OUT/libcronet.so" \
        --tcp-listen 127.0.0.1:8444 --tcp-to 9000 --tcp-members "$MEMBERS" >"$OUT/entry-tcp-$impl.log" 2>&1 & ;;
  esac
  epid=$!
  sleep 1.5
  line=$(taskset -c "$GEN_CPUS" "$OUT/tcpcheck" -to 127.0.0.1:8444 -bytes "$BYTES" -streams "$STREAMS" -pid "$epid" -exit-pid "$xpid" -label "$impl-$EXIT#$rep m$MEMBERS s$STREAMS${CUT:+ cut=$CUT}") || true
  echo "$line" | tee -a "$RES"
  sleep 1
  echo "  [$impl] fds $(ls /proc/$epid/fd | wc -l), sockets $(ls -l /proc/$epid/fd | grep -c socket)"
  kill $epid $xpid $epid_echo $cpid 2>/dev/null || true
  wait $epid $xpid $epid_echo $cpid 2>/dev/null || true
  tail -n 2 "$OUT/entry-tcp-$impl.log" | sed "s/^/  [$impl] /"
  tail -n 2 "$OUT/exit.log" | sed "s/^/  [exit $EXIT] /"
  [ -z "$CUT" ] || echo "  [$impl] cuts: $(grep -c '^.*cut ' "$OUT/cut-$impl.log")"
}

for rep in $(seq 1 "$REPS"); do
  for impl in $IMPLS; do
    run_one "$impl" "$rep"
  done
done
