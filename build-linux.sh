#!/bin/bash
# 本地 Linux 构建：产出 dist/ 下的静态二进制，供安装脚本分发
set -e
cd "$(dirname "$0")"
OUT=${1:-dist}
mkdir -p "$OUT"

FLAGS='-Os -fno-asynchronous-unwind-tables -fno-unwind-tables -ffunction-sections -fdata-sections'
LDFLAGS='-static -Wl,--gc-sections -Wl,--build-id=none'

build_one() {
  local asset="$1"   # 例如 cochat-linux-amd64
  local cxx="$2"
  local stripbin="$3"
  local sysname="$4"
  local sysproc="$5"

  echo "=== 构建 $asset"
  rm -rf "build-$asset"
  cmake -S . -B "build-$asset" -G Ninja \
        -DCMAKE_BUILD_TYPE=MinSizeRel \
        -DCMAKE_CXX_COMPILER="$cxx" \
        -DCMAKE_EXE_LINKER_FLAGS="$LDFLAGS" \
        -DCMAKE_CXX_FLAGS="$FLAGS" \
        ${sysname:+-DCMAKE_SYSTEM_NAME="$sysname"} \
        ${sysproc:+-DCMAKE_SYSTEM_PROCESSOR="$sysproc"} >/dev/null
  cmake --build "build-$asset" -j "$(nproc)" >/dev/null
  local bin="build-$asset/cochat"
  [ -f "$bin" ] || bin="build-$asset/cochat.exe"
  "$stripbin" --strip-all "$bin" 2>/dev/null || true
  cp "$bin" "$OUT/$asset"
  chmod +x "$OUT/$asset" 2>/dev/null || true
  printf "  %-26s %s 字节\n" "$asset" "$(stat -c%s "$OUT/$asset")"
}

# 本机架构
case "$(uname -m)" in
  x86_64)  build_one cochat-linux-amd64 g++ strip "" "" ;;
  aarch64) build_one cochat-linux-arm64 g++ strip "" "" ;;
  armv7l)  build_one cochat-linux-armv7 g++ strip "" "" ;;
  *) echo "未知本机架构 $(uname -m)，跳过" ;;
esac

# 交叉架构（需要对应工具链）
if command -v aarch64-linux-gnu-g++ >/dev/null 2>&1; then
  build_one cochat-linux-arm64 aarch64-linux-gnu-g++ aarch64-linux-gnu-strip Linux aarch64
else
  echo "=== 跳过 linux-arm64（未安装 aarch64-linux-gnu-g++）"
fi

if command -v arm-linux-gnueabihf-g++ >/dev/null 2>&1; then
  build_one cochat-linux-armv7 arm-linux-gnueabihf-g++ arm-linux-gnueabihf-strip Linux armv7
else
  echo "=== 跳过 linux-armv7（未安装 arm-linux-gnueabihf-g++）"
fi

if command -v x86_64-w64-mingw32-g++ >/dev/null 2>&1; then
  build_one cochat-windows-amd64.exe x86_64-w64-mingw32-g++ x86_64-w64-mingw32-strip Windows x86_64
else
  echo "=== 跳过 windows-amd64（未安装 x86_64-w64-mingw32-g++）"
fi

echo
ls -lh "$OUT"
