#!/bin/sh
# Copies on the pool (hikkari-client plans/2026-11-15-pool-copy-coalescing.md,
# step D): the same users as run.sh (hk-loadgen: voice, game, acks) through
# hk-pipe on the people's route of 15.11, voice on two fates: the bare UDP
# wire with the port's copies and one copy on the pool of MEMBERS Chromium
# members (Chromium's CONNECT to the Go exit's relay channel, goexit
# -naive), every datagram of the users on both. A config is
# <members of copies>:<window us>, or off for voice on the udp wire alone
# (the floor: no copy at all, and no flag a pipe before the copies lacks);
# 0:0 is the pool as at 15.11 08:55 UTC
# (copies round every member, each written at once), whose price on the box
# was 105-136 us a packet at u8 (two-fates-step-e-rollout). The entry on
# CPUs 0-1, the exit on 4-5, the users on 2-3.
#
#   fates.sh <reps> <secs> "<users...>" "<configs...>" [members]
#   e.g. fates.sh 3 20 "8 16" "0:0 4:2000 4:4000 4:6000 4:8000" 32
set -eu
OUT=${OUT:-/bench/out}
REPS=${1:-3}; SECS=${2:-20}; USERS=${3:-"8 16"}; CONFIGS=${4:-"0:0 4:4000"}; MEMBERS=${5:-32}
RES=${RES:-$OUT/results-fates.txt}
EXIT_CPUS=${EXIT_CPUS:-4,5}; GEN_CPUS=${GEN_CPUS:-2,3}; ENTRY_CPUS=${ENTRY_CPUS:-0,1}
NAIVE=127.0.0.1:20445
UP_WAIT=${UP_WAIT:-4}

run_one() {
  cfg=$1; users=$2; rep=$3
  k=${cfg%%:*}; w=${cfg##*:}
  fates="--two-fates 1 --copy-members $k --copy-window-us $w"
  [ "$cfg" != off ] || fates=""
  copies=1; [ "$cfg" != off ] || copies=${OFF_COPIES:-1}
  taskset -c "$EXIT_CPUS" "$OUT/goexit" -naive "$NAIVE" -naive-roots "$OUT/naive-roots.pem" >"$OUT/exit.log" 2>&1 &
  xpid=$!
  sleep 0.5
  taskset -c "$ENTRY_CPUS" "${PIPE_GNU:-$OUT/hk-pipe}" --members 2 --copies "$copies" $fates \
    --tcp-wire "$NAIVE" --tcp-chromium hk.example --tcp-roots "$OUT/naive-roots.pem" --cronet "$OUT/libcronet.so" \
    --tcp-listen 127.0.0.1:8444 --tcp-to 9000 --tcp-members "$MEMBERS" >"$OUT/entry-fates.log" 2>&1 &
  epid=$!
  sleep "$UP_WAIT"
  x0=$(awk '{print $14+$15}' /proc/$xpid/stat); t0=$(date +%s.%N)
  line=$(taskset -c "$GEN_CPUS" "$OUT/hk-loadgen" --users "$users" --secs "$SECS" --warm 5 --pid "$epid" --label "fates-$cfg${PIPE_GNU:+-base}#$rep m$MEMBERS") || true
  x1=$(awk '{print $14+$15}' /proc/$xpid/stat); t1=$(date +%s.%N)
  xcpu=$(awk -v a="$x0" -v b="$x1" -v s="$t0" -v e="$t1" -v hz="$(getconf CLK_TCK)" 'BEGIN{printf "%.1f", (b-a)/hz/(e-s)*100}')
  echo "$line exit_cpu_pct=$xcpu" | tee -a "$RES"
  kill $epid $xpid 2>/dev/null || true
  wait $epid $xpid 2>/dev/null || true
  echo "  [$cfg u$users] $(grep 'ports free' "$OUT/entry-fates.log" | tail -n 1 | sed 's/.*| swire/swire/')"
}

for rep in $(seq 1 "$REPS"); do
  for u in $USERS; do
    for cfg in $CONFIGS; do
      run_one "$cfg" "$u" "$rep"
    done
  done
done
