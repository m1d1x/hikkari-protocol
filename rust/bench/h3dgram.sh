#!/bin/bash
# R6.2: the trunk's call over the Chromium QUIC wire (spec/trunk.md,
# h3dgram) to the Rust exit. hk-exit serves the wire on loopback with a
# self-signed certificate made here; hk-h3dgram-call opens a member through
# the patched libcronet (CONNECT-UDP), says its hello and sends the call to
# port 0, which the exit sends straight back. Each run checks every datagram
# comes back intact; then one run with a wrong key must get no member.
#
#   h3dgram.sh [runs] [count]
#
# Needs in $OUT (default /bench/out): hk-exit, hk-h3dgram-call,
# libcronet.so (patched, rust/cronet/chromium/build.sh), and openssl.
set -u
runs=${1:-3}
count=${2:-1500}
out=${OUT:-/bench/out}
fail=0

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 \
  -subj /CN=hk.example -addext subjectAltName=DNS:hk.example \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=digitalSignature,keyCertSign \
  -addext extendedKeyUsage=serverAuth \
  -keyout "$out/h3dgram-key.pem" -out "$out/h3dgram-cert.pem" 2>/dev/null || { echo "h3dgram.sh: openssl" >&2; exit 2; }

"$out/hk-exit" --listen 127.0.0.1:20447 --h3 127.0.0.1:4433 --h3-wire-id 6 \
  --cert "$out/h3dgram-cert.pem" --cert-key "$out/h3dgram-key.pem" >"$out/hk-exit.log" 2>&1 &
exit_pid=$!
trap 'kill $exit_pid 2>/dev/null; exit $fail' EXIT
sleep 0.3

for r in $(seq "$runs"); do
  echo "run $r"
  "$out/hk-h3dgram-call" --cronet "$out/libcronet.so" --roots "$out/h3dgram-cert.pem" --count "$count" || fail=1
done

echo "wrong key"
if "$out/hk-h3dgram-call" --cronet "$out/libcronet.so" --roots "$out/h3dgram-cert.pem" --count 10 --key wrong; then
  echo "h3dgram.sh: a wrong key got a member" >&2
  fail=1
fi

sleep 10.5
grep -E "^hk-exit: (sessions|h3dgram)" "$out/hk-exit.log" | tail -2
exit $fail
