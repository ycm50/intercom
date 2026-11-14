#!/bin/bash
# 本地 Linux 构建：产出 dist/ 下的静态二进制，供安装脚本分发
set -e
cd "$(dirname "$0")"
OUT=${1:-dist}
mkdir -p "$OUT"

FLAGS='-Os -fno-asynchronous-unwind-tables -fno-unwind-tables -ffunction-sections -fdata-sections'

# 【不能整体 -static】主程序运行时要用 dlopen 加载隧道插件，而插件必然是一个
# 动态库（它自己还要链 libssl）。整体 -static 会把 libc 也编进可执行文件，
# 进程里于是同时存在两份 libc / libstdc++ —— 插件的 TLS、std::string、异常表
# 全部按另一份的布局来，一调用就崩。
#
# 实测：整体 -static 时 ./cochat --tunnel 立刻 Segmentation fault（信号 11，
# 崩在 glibc 内部 TLS 遍历）；换成下面的混合链接后正常输出「内建隧道 已启动」。
#
# 所以：libc / libm 走动态（系统里必然有，都是稳定 ABI），
# libstdc++ / libgcc 静态（目标机不装 libstdc++ 也能跑）。
# 代价是目标机需要 glibc，这在任何正常 Linux 发行版上都成立。
LDFLAGS='-static-libgcc -static-libstdc++ -Wl,--gc-sections -Wl,--build-id=none'

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

  # 隧道插件必须跟主程序一起发：loader 先找 exe 同目录，安装脚本也按
  # "二进制旁边躺着就一起装"的规则处理。少了它只是没有内建隧道，
  # 所以这里缺了只提示、不失败。
  local plug="build-$asset/libcochat-tunnel.so"
  [ -f "$plug" ] || plug="build-$asset/cochat-tunnel.dll"
  if [ -f "$plug" ]; then
    "$stripbin" --strip-all "$plug" 2>/dev/null || true
    cp "$plug" "$OUT/"
    printf "  %-26s %s 字节\n" "$(basename "$plug")" "$(stat -c%s "$OUT/$(basename "$plug")")"
  else
    echo "  （该架构没有隧道插件，可能缺 OpenSSL）"
  fi
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
