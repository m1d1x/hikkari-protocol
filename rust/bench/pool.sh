#!/bin/sh
# R2.3: the users' datagrams on the pool. The same users as run.sh
# (hk-loadgen: voice, game, acks) through an entry whose only wire is the
# pool of MEMBERS Chromium members (Chromium's CONNECT to the Go exit's
# relay channel, goexit -naive), voice routed on it as the selector routes
# it when the pool is the only wire: the part of the stand entry's price the
# 12.11 profile put at 69 us a packet. Go: goentry -members 0
# -pool-chromium (trunk/chromium, an engine each, ports from trunk's book);
# rust: hk-pipe-gnu --members 0 --tcp-chromium (one engine, ports from
# hikkari_trunk::ports). The entry on CPUs 0-1, the exit on 4-5, the users
# on 2-3.
#
# With CUT=rst or CUT=freeze the members go through tcpcheck -proxy, which
# cuts the busiest member every CUT_EVERY from CUT_AFTER: members die under
# the users' load and come back on new ports. The entry's log then says how
# many died and why, the line how the voice heard it.
#
#   pool.sh <reps> <secs> "<users...>" "<impls>" [members]   e.g. pool.sh 3 30 "4 16 64" "go rust" 32
set -eu
OUT=${OUT:-/bench/out}
REPS=${1:-3}; SECS=${2:-30}; USERS=${3:-"4 16 64"}; IMPLS=${4:-"go rust"}; MEMBERS=${5:-32}
RES=${RES:-$OUT/results-pool.txt}
EXIT_CPUS=${EXIT_CPUS:-4,5}; GEN_CPUS=${GEN_CPUS:-2,3}; ENTRY_CPUS=${ENTRY_CPUS:-0,1}
CUT=${CUT:-}; CUT_EVERY=${CUT_EVERY:-3s}; CUT_AFTER=${CUT_AFTER:-5s}
NAIVE=127.0.0.1:20445
UP_WAIT=${UP_WAIT:-4}

run_one() {
  impl=$1; users=$2; rep=$3
  taskset -c "$EXIT_CPUS" "$OUT/goexit" -naive "$NAIVE" >"$OUT/exit.log" 2>&1 &
  xpid=$!
  to=$NAIVE; cpid=
  if [ -n "$CUT" ]; then
    taskset -c "$EXIT_CPUS" "$OUT/tcpcheck" -proxy 127.0.0.1:20500 -proxy-to "$NAIVE" -cut "$CUT" -cut-every "$CUT_EVERY" -cut-after "$CUT_AFTER" >"$OUT/cut-$impl.log" 2>&1 &
    cpid=$!
    to=127.0.0.1:20500
  fi
  sleep 0.5
  case $impl in
    go) taskset -c "$ENTRY_CPUS" "$OUT/goentry" -members 0 -pool "$to" -pool-chromium hk.example -roots "$OUT/naive-roots.pem" \
          -pool-members "$MEMBERS" >"$OUT/entry-pool-$impl.log" 2>&1 & ;;
    rust) taskset -c "$ENTRY_CPUS" "${PIPE_GNU:-$OUT/hk-pipe-gnu}" --members 0 --tcp-wire "$to" --tcp-chromium hk.example \
          --tcp-roots "$OUT/naive-roots.pem" --cronet "$OUT/libcronet.so" --tcp-listen 127.0.0.1:8444 --tcp-to 9000 \
          --tcp-members "$MEMBERS" >"$OUT/entry-pool-$impl.log" 2>&1 & ;;
  esac
  epid=$!
  sleep "$UP_WAIT"
  label="$impl#$rep m$MEMBERS${CUT:+ cut=$CUT}"
  line=$(taskset -c "$GEN_CPUS" "$OUT/hk-loadgen" --users "$users" --secs "$SECS" --warm 5 --pid "$epid" --label "$label") || true
  echo "$line threads=$(ls /proc/$epid/task | wc -l) sockets=$(ls -l /proc/$epid/fd | grep -c socket)" | tee -a "$RES"
  kill $epid $xpid $cpid 2>/dev/null || true
  wait $epid $xpid $cpid 2>/dev/null || true
  case $impl in
    go) echo "  [go] down: $(grep -c 'down after' "$OUT/entry-pool-$impl.log" || true), stalled $(grep -c 'down after.*stalled' "$OUT/entry-pool-$impl.log" || true), dials failed $(grep -c ': dial:\|: hello:' "$OUT/entry-pool-$impl.log" || true)" ;;
    rust) echo "  [rust] down: $(grep -c 'member .* down' "$OUT/entry-pool-$impl.log" || true), stalled $(grep -c 'down (why [24])' "$OUT/entry-pool-$impl.log" || true); $(grep 'ports free' "$OUT/entry-pool-$impl.log" | tail -n 1 | sed 's/.*| swire/swire/')" ;;
  esac
  echo "  [exit] tunnels $(grep -c 'naive tunnel' "$OUT/exit.log")"
  [ -z "$CUT" ] || echo "  [$impl] cuts: $(grep -c ' cut ' "$OUT/cut-$impl.log" || true)"
}

for rep in $(seq 1 "$REPS"); do
  for u in $USERS; do
    for impl in $IMPLS; do
      run_one "$impl" "$u" "$rep"
    done
  done
done
