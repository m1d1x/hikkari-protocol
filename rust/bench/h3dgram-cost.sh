#!/bin/bash
# R6.2: what the Rust exit's CPU costs per datagram of the Chromium QUIC wire
# (spec/trunk.md, h3dgram). `members` calls at once, each its own member (a
# QUIC connection through the patched libcronet), each sending `pps`
# datagrams of `size` bytes a second to port 0 for `secs` seconds; the exit
# sends each straight back (glued for its tick). The exit's CPU is read from
# /proc/<pid>/schedstat around the calls; the line gives it per datagram the
# exit read and per QUIC packet both ways.
#
#   h3dgram-cost.sh [members] [pps] [secs] [size]
#
# Needs what h3dgram.sh needs in $OUT (default /bench/out).
set -u
members=${1:-4}
pps=${2:-2000}
secs=${3:-10}
size=${4:-160}
out=${OUT:-/bench/out}

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 \
  -subj /CN=hk.example -addext subjectAltName=DNS:hk.example \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=digitalSignature,keyCertSign \
  -addext extendedKeyUsage=serverAuth \
  -keyout "$out/h3dgram-key.pem" -out "$out/h3dgram-cert.pem" 2>/dev/null || { echo "h3dgram-cost.sh: openssl" >&2; exit 2; }

"$out/hk-exit" --listen 127.0.0.1:20447 --h3 127.0.0.1:4433 --h3-wire-id 6 \
  --cert "$out/h3dgram-cert.pem" --cert-key "$out/h3dgram-key.pem" >"$out/hk-exit.log" 2>&1 &
exit_pid=$!
trap 'kill $exit_pid 2>/dev/null' EXIT
sleep 0.3

cpu() { cut -d' ' -f1 "/proc/$exit_pid/schedstat"; }
packets() { awk '/Udp:/ && $2 ~ /^[0-9]+$/ {print $2 + $5; exit}' /proc/net/snmp; }
count=$((pps * secs))
every=$((1000000 / pps))
c0=$(cpu)
p0=$(packets)
pids=()
for i in $(seq "$members"); do
  "$out/hk-h3dgram-call" --cronet "$out/libcronet.so" --roots "$out/h3dgram-cert.pem" \
    --count "$count" --every-us "$every" --size "$size" >"$out/call-$i.log" 2>&1 &
  pids+=($!)
done
fail=0
for p in "${pids[@]}"; do wait "$p" || fail=1; done
c1=$(cpu)
p1=$(packets)
sleep 10.5
line=$(grep -E "^hk-exit: sessions" "$out/hk-exit.log" | tail -1)
w_in=$(sed -E 's/.* w_in=([0-9]+).*/\1/' <<<"$line")
w_out=$(sed -E 's/.* w_out=([0-9]+).*/\1/' <<<"$line")
lost=$(grep -ho "lost=[0-9]*" "$out"/call-*.log | awk -F= '{s += $2} END {print s}')
p99=$(grep -ho "p99=[0-9]*" "$out"/call-*.log | awk -F= '$2 > m {m = $2} END {print m}')
# Both ends are on loopback: each UDP packet is counted once received and
# once sent; half is the QUIC packets of the wire (and a little of the rest).
quic=$(((p1 - p0) / 2))
awk -v c=$((c1 - c0)) -v i="$w_in" -v o="$w_out" -v q="$quic" -v m="$members" -v r="$pps" -v s="$size" -v l="$lost" -v p="$p99" -v f="$fail" \
  'BEGIN { printf "h3dgram-cost members=%d pps=%d size=%d exit_cpu_ms=%.0f dgrams_in=%d dgrams_out=%d us_per_dgram_in=%.2f quic_packets=%d us_per_quic_packet=%.2f lost=%d rtt_p99_us=%d fail=%d\n", m, r, s, c / 1e6, i, o, c / 1e3 / i, q, c / 1e3 / q, l, p, f }'
exit $fail
