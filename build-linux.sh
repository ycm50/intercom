#!/bin/bash
# 本地 WSL 交叉构建：输出各架构静态二进制到 dist/
set -e
cd "$(dirname "$0")"
OUT=${1:-dist}
mkdir -p "$OUT"

FLAGS='-Os -fno-asynchronous-unwind-tables -fno-unwind-tables -ffunction-sections -fdata-sections'
LDFLAGS='-static -Wl,--gc-sections -Wl,--build-id=none'

build_one() {
  local name="$1"
  echo "=== 构建 linux-$name"
  rm -rf "build-$name"
  cmake -S . -B "build-$name" -DCMAKE_BUILD_TYPE=MinSizeRel \
        -DCMAKE_CXX_FLAGS="$FLAGS" \
        -DCMAKE_EXE_LINKER_FLAGS="$LDFLAGS" >/dev/null
  cmake --build "build-$name" -j "$(nproc)" >/dev/null
  strip --strip-all "build-$name/intercom-server"
  gzip -9 -c "build-$name/intercom-server" > "$OUT/intercom-linux-$name.gz"
  printf "  %-28s %s 字节\n" "intercom-linux-$name.gz" "$(stat -c%s "$OUT/intercom-linux-$name.gz")"
}

# 本机架构
build_one "amd64"

# 交叉架构（若装了对应 g++-<arch>-linux-gnu）
for arch in aarch64 armv7; do
  if command -v "${arch}-linux-gnu-g++" >/dev/null 2>&1; then
    CXX="${arch}-linux-gnu-g++" build_one "$arch"
  else
    echo "=== 跳过 linux-$arch（未安装 ${arch}-linux-gnu-g++）"
  fi
done

echo
ls -lh "$OUT"
