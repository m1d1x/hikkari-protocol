#!/bin/sh
# R2.2: a wire's Chromium members on one engine. The Go exit (goexit -naive)
# records every member's ClientHello. First the Go entry's members
# (gomember, trunk/chromium: an engine each) give the reference hellos; then
# hk-pipe brings up MEMBERS members on one engine, carries BYTES through
# them, and the run checks:
#   - every member came up on a TCP connection of its own (tunnels and
#     source ports at the exit, threads of the pipe);
#   - every byte came back (tcpcheck);
#   - each member's hello is the reference's (hellocheck: the client release
#     test's hk and ja4).
#
#   members.sh <members> <bytes> <streams>    e.g. members.sh 32 1073741824 16
set -eu
OUT=${OUT:-/bench/out}
MEMBERS=${1:-32}; BYTES=${2:-1073741824}; STREAMS=${3:-16}
NAIVE=127.0.0.1:20445
REF=$OUT/hellos-ref; GOT=$OUT/hellos-pipe
rm -rf "$REF" "$GOT"

"$OUT/goexit" -naive "$NAIVE" -naive-hellos "$REF" >"$OUT/exit-ref.log" 2>&1 &
x=$!
sleep 0.5
"$OUT/gomember" -exit "$NAIVE" -members 4 2>&1 | sed 's/^/  [go] /'
kill $x; wait $x 2>/dev/null || true

"$OUT/tcpcheck" -serve 127.0.0.1:9000 >"$OUT/echo.log" 2>&1 &
e=$!
taskset -c 4,5 "$OUT/goexit" -naive "$NAIVE" -naive-hellos "$GOT" >"$OUT/exit.log" 2>&1 &
x=$!
sleep 0.5
taskset -c 0,1 "${PIPE_GNU:-$OUT/hk-pipe-gnu}" --tcp-wire "$NAIVE" --tcp-chromium hk.example --tcp-roots "$OUT/naive-roots.pem" \
  --cronet "$OUT/libcronet.so" --tcp-listen 127.0.0.1:8444 --tcp-to 9000 --tcp-members "$MEMBERS" >"$OUT/entry-members.log" 2>&1 &
p=$!
sleep 3
up=$(grep -c 'wire 0 member .* up' "$OUT/entry-members.log" || true)
echo "members up after 3 s: $up of $MEMBERS, pipe threads $(ls /proc/$p/task | wc -l)"
taskset -c 2,3 "$OUT/tcpcheck" -to 127.0.0.1:8444 -bytes "$BYTES" -streams "$STREAMS" -pid "$p" -exit-pid "$x" -label "members m$MEMBERS s$STREAMS"
echo "tunnels at the exit: $(grep -c 'naive tunnel' "$OUT/exit.log"), source ports $(grep 'naive tunnel' "$OUT/exit.log" | sed 's/.* from \([^ ]*\) .*/\1/' | sort -u | wc -l)"
echo "pipe threads after: $(ls /proc/$p/task | wc -l): $(cat /proc/$p/task/*/comm | sort | uniq -c | tr '\n' ' ')"
kill $p $x $e 2>/dev/null || true
wait $p $x $e 2>/dev/null || true
grep -v 'member .* up\|Chromium\|flows=' "$OUT/entry-members.log" | head -5 | sed 's/^/  [pipe] /'
"$OUT/hellocheck" -ref "$REF" -got "$GOT" -want "$MEMBERS"
