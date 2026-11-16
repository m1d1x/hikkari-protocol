#!/bin/sh
# Bench of the entry's UDP path: the same users through the Go entry
# (bench/go/goentry, trunk + udpwire as production) and through hk-pipe, to
# the same exit: the Go exit (bench/go/goexit) or, with EXIT=rust, hk-exit
# (R1.6). Runs inside a Linux box (docker on the mac, see README.md). The
# entry is held to 2 CPUs (taskset 0,1), the users and the exit to CPUs of
# their own, so the entry's CPU is its own; the exit's CPU over the users'
# whole run (warm-up too) is in the line as exit_cpu_pct.
#
#   run.sh <reps> <secs> "<users...>" [impls]    e.g. run.sh 3 30 "1 4 16 64" "go rust"
#   EXIT=rust run.sh 3 30 "16 64" rust      (HK_EXIT: another hk-exit build)
#   EXIT=rust run.sh 3 30 "1 4 16 64" "rust h3"
#
# The impl h3 is hk-pipe on the Chromium QUIC wire (R6.3: H3_MEMBERS members,
# CONNECT-UDP tunnels through $OUT/libcronet.so, sessions as USAGE says) to
# hk-exit's QUIC port, which the Rust exit then listens on too; it needs
# $OUT/cert.pem and $OUT/key.pem for hk.example. The entry's CPU is the whole
# process: the loop and Chromium's network thread.
set -eu
OUT=${OUT:-/bench/out}
REPS=${1:-3}; SECS=${2:-30}; USERS=${3:-"1 4 16 64"}; IMPLS=${4:-"go rust"}
GLUE_US=${GLUE_US:-1000}
H3_MEMBERS=${H3_MEMBERS:-4}; USAGE=${USAGE:-destination}
H3_EXIT=""
case " $IMPLS " in *" h3 "*)
  H3_EXIT="--h3 127.0.0.1:4433 --h3-wire-id 6 --cert $OUT/cert.pem --cert-key $OUT/key.pem" ;;
esac
RES=${RES:-$OUT/results.txt}
EXIT=${EXIT:-go}
EXIT_CPUS=${EXIT_CPUS:-4,5}; GEN_CPUS=${GEN_CPUS:-2,3}; ENTRY_CPUS=${ENTRY_CPUS:-0,1}

run_one() {
  impl=$1; users=$2; rep=$3
  case $EXIT in
    go)   taskset -c "$EXIT_CPUS" "$OUT/goexit" >"$OUT/exit.log" 2>&1 & ;;
    rust) taskset -c "$EXIT_CPUS" "${HK_EXIT:-$OUT/hk-exit}" --glue-us "$GLUE_US" $H3_EXIT >"$OUT/exit.log" 2>&1 & ;;
  esac
  xpid=$!
  sleep 0.5
  case $impl in
    go)   taskset -c "$ENTRY_CPUS" "$OUT/goentry" >"$OUT/entry-$impl.log" 2>&1 & ;;
    rust) taskset -c "$ENTRY_CPUS" "$OUT/hk-pipe" --glue-us "$GLUE_US" >"$OUT/entry-$impl.log" 2>&1 & ;;
    rustbase) taskset -c "$ENTRY_CPUS" "$OUT/hk-pipe-base" --glue-us "$GLUE_US" >"$OUT/entry-$impl.log" 2>&1 & ;;
    rust2) taskset -c "$ENTRY_CPUS" "$OUT/hk-pipe" --glue-us 2000 --tick-us 2000 >"$OUT/entry-$impl.log" 2>&1 & ;;
    h3) taskset -c "$ENTRY_CPUS" "$OUT/hk-pipe" --glue-us "$GLUE_US" --wire 127.0.0.1:4433 --wire-id 6 --members "$H3_MEMBERS" \
          --h3dgram hk.example --h3-roots "$OUT/cert.pem" --usage "$USAGE" --cronet "$OUT/libcronet.so" --ports 30000-30999 \
          >"$OUT/entry-$impl.log" 2>&1 & ;;
    rustev) taskset -c "$ENTRY_CPUS" "$OUT/hk-pipe" --glue-us "$GLUE_US" --tick-us 0 >"$OUT/entry-$impl.log" 2>&1 & ;;
  esac
  epid=$!
  # Chromium's QUIC handshakes come up on the first members' hellos.
  sleep 1.5
  x0=$(awk '{print $14+$15}' /proc/$xpid/stat); t0=$(date +%s.%N)
  line=$(taskset -c "$GEN_CPUS" "$OUT/hk-loadgen" --users "$users" --secs "$SECS" --warm 5 --pid "$epid" --label "$impl-$EXIT#$rep")
  x1=$(awk '{print $14+$15}' /proc/$xpid/stat); t1=$(date +%s.%N)
  xcpu=$(awk -v a="$x0" -v b="$x1" -v s="$t0" -v e="$t1" -v hz="$(getconf CLK_TCK)" 'BEGIN{printf "%.1f", (b-a)/hz/(e-s)*100}')
  echo "$line exit_cpu_pct=$xcpu" | tee -a "$RES"
  kill $epid $xpid 2>/dev/null || true
  wait $epid $xpid 2>/dev/null || true
  tail -n 2 "$OUT/entry-$impl.log" | sed "s/^/  [$impl u$users] /"
  grep -E "^hk-exit: (sessions|h3dgram)" "$OUT/exit.log" | tail -n 2 | sed "s/^/  [exit $EXIT u$users] /"
}

for rep in $(seq 1 "$REPS"); do
  for u in $USERS; do
    for impl in $IMPLS; do
      run_one "$impl" "$u" "$rep"
    done
  done
done
