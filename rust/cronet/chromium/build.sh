#!/bin/bash
# Builds libcronet.so with the CONNECT-UDP tunnel (connect-udp.patch) from
# the same sources as the libcronet the pool's members load: cronet-go at
# the commit rust/bench/go/go.mod names (v0.0.0-20260912104727-0d28acc44093)
# and the naiveproxy (Chromium 150.0.7871.63) it pins. Chromium builds Linux
# targets on a linux/amd64 host only: WSL2 Debian on the PC (rust/README.md,
# "Chromium QUIC"). Needs Go, python3, python3-requests, ninja-build, curl,
# xz-utils, unzip, git, gpgv, file; about 25 GB, 7 minutes per target on 24
# threads the first time, seconds after a change to the patch.
#
#   build.sh <workdir> [targets]      targets: linux/amd64 (default), linux/arm64
#
# The library lands in <workdir>/out/<goos>_<goarch>/libcronet.so.
set -euo pipefail

work=$1
targets=${2:-linux/amd64}
here=$(cd "$(dirname "$0")" && pwd)
cronet_go=0d28acc44093df24b2526dea3d6ffefd6b0a54f0
naiveproxy=72a06c9fca0e2d228588c7f3074bf7efff3ff686

mkdir -p "$work"
cd "$work"
if [ ! -d cronet-go/.git ]; then
  git init -q cronet-go
  git -C cronet-go fetch -q --depth 1 https://github.com/SagerNet/cronet-go.git "$cronet_go"
  git -C cronet-go checkout -q FETCH_HEAD
  git init -q cronet-go/naiveproxy
  git -C cronet-go/naiveproxy fetch -q --depth 1 https://github.com/SagerNet/naiveproxy.git "$naiveproxy"
  git -C cronet-go/naiveproxy checkout -q FETCH_HEAD
fi
test "$(cat cronet-go/naiveproxy/CHROMIUM_VERSION)" = 150.0.7871.63

# The patch on a clean tree, so that a rerun builds exactly it.
git -C cronet-go/naiveproxy reset -q --hard
git -C cronet-go/naiveproxy clean -qfd -- src/components/cronet/native
git -C cronet-go/naiveproxy apply "$here/connect-udp.patch"

cd cronet-go
go run ./cmd/build-naive build -t "$targets"
for t in ${targets//,/ }; do
  goos=${t%/*}
  goarch=${t#*/}
  case $goarch in amd64) cpu=x64 ;; arm64) cpu=arm64 ;; *) echo "build.sh: no target $t" >&2; exit 1 ;; esac
  mkdir -p "$work/out/${goos}_$goarch"
  cp "naiveproxy/src/out/cronet-$goos-$cpu/libcronet.so" "$work/out/${goos}_$goarch/libcronet.so"
  echo "build.sh: $work/out/${goos}_$goarch/libcronet.so"
done
