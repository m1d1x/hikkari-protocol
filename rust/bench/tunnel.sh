#!/bin/bash
# R6.1: datagrams out of Chromium through a CONNECT-UDP tunnel and back.
# The reference HTTP/3 proxy (go/connectudp, quic-go) echoes; hk-udp-tunnel
# opens the tunnel through the patched libcronet and sends a call: 160 B
# every 20 ms. Each run checks every datagram comes back intact, then one
# run more with a wrong key must be refused (407, no tunnel).
#
#   tunnel.sh [runs] [count]
#
# Needs in /bench/out: connectudp, hk-udp-tunnel, libcronet.so (patched,
# rust/cronet/chromium/build.sh), all for the container's architecture.
set -u
runs=${1:-3}
count=${2:-1500}
out=/bench/out
fail=0

# The proxy makes a new certificate each start: wait for this start's.
rm -f $out/connectudp-roots.pem
$out/connectudp -listen 127.0.0.1:4433 -roots $out/connectudp-roots.pem >$out/connectudp.log 2>&1 &
proxy=$!
trap 'kill $proxy 2>/dev/null; exit $fail' EXIT
for _ in $(seq 50); do [ -s $out/connectudp-roots.pem ] && break; sleep 0.1; done

for r in $(seq "$runs"); do
  echo "run $r"
  $out/hk-udp-tunnel --cronet $out/libcronet.so --roots $out/connectudp-roots.pem --count "$count" || fail=1
done

echo "wrong key"
if $out/hk-udp-tunnel --cronet $out/libcronet.so --roots $out/connectudp-roots.pem --count 10 --auth "basic d3Jvbmc="; then
  echo "tunnel.sh: a wrong key got a tunnel" >&2
  fail=1
fi

sleep 10.5
grep -E "^connectudp tunnels" $out/connectudp.log | tail -1
grep -E "tunnel to|refused" $out/connectudp.log | sort | uniq -c
exit $fail
