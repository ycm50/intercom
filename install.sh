#!/bin/sh
# cochat 安装脚本（Linux / macOS）
#
#   用法：
#     sh install.sh <二进制文件>
#
#   脚本先读取二进制文件头，判断它是哪个平台、哪个架构编译的，
#   与当前系统不符时直接报错退出，相符才安装成 ~/.local/bin/cochat。
#
#   可用环境变量：
#     COCHAT_PREFIX  指定安装目录（默认 ~/.local/bin）
#     COCHAT_FORCE=1 架构不匹配也强行安装（不推荐，仅供排障）
set -eu

BIN_NAME="cochat"
PREFIX="${COCHAT_PREFIX:-$HOME/.local/bin}"
FORCE="${COCHAT_FORCE:-0}"

usage() {
  echo "用法: sh install.sh <二进制文件>" >&2
  echo "" >&2
  echo "例如: sh install.sh ./cochat-linux-amd64" >&2
  exit 1
}

[ $# -ge 1 ] || usage
SRC=$1
[ -n "$SRC" ] || usage

if [ ! -f "$SRC" ]; then
  echo "错误：找不到文件 $SRC" >&2
  exit 1
fi
if [ ! -s "$SRC" ]; then
  echo "错误：$SRC 是空文件" >&2
  exit 1
fi

# ---------------- 读取文件头 ----------------

# 取第 N 个字节（十进制）
byte_at() {
  od -An -tu1 -j "$1" -N 1 "$2" 2>/dev/null | tr -d " \t\n"
}

# 小端 16 位，参数：偏移 文件
u16le() {
  lo=$(byte_at "$1" "$2")
  hi=$(byte_at $(($1 + 1)) "$2")
  [ -n "$lo" ] && [ -n "$hi" ] || return 1
  echo $((lo + hi * 256))
}

# 小端 32 位，参数：偏移 文件
u32le() {
  b0=$(byte_at "$1" "$2")
  b1=$(byte_at $(($1 + 1)) "$2")
  b2=$(byte_at $(($1 + 2)) "$2")
  b3=$(byte_at $(($1 + 3)) "$2")
  [ -n "$b0" ] && [ -n "$b1" ] && [ -n "$b2" ] && [ -n "$b3" ] || return 1
  echo $((b0 + b1 * 256 + b2 * 65536 + b3 * 16777216))
}

# 输出 "<系统>/<架构>"，无法识别时输出 unknown
detect_binary() {
  f=$1
  b0=$(byte_at 0 "$f")
  b1=$(byte_at 1 "$f")
  b2=$(byte_at 2 "$f")
  b3=$(byte_at 3 "$f")

  # ---- ELF：0x7F E L F
  if [ "$b0" = "127" ] && [ "$b1" = "69" ] && [ "$b2" = "76" ] && [ "$b3" = "70" ]; then
    cls=$(byte_at 4 "$f")
    dat=$(byte_at 5 "$f")
    if [ "$dat" != "1" ]; then
      echo "unknown"
      return
    fi
    mach=$(u16le 18 "$f") || { echo "unknown"; return; }
    case "$cls:$mach" in
      2:62)   echo "linux/amd64" ;;
      2:183)  echo "linux/arm64" ;;
      2:21)   echo "linux/ppc64le" ;;
      1:3)    echo "linux/x86" ;;
      1:40)   echo "linux/armv7" ;;
      *)      echo "unknown" ;;
    esac
    return
  fi

  # ---- PE：MZ 开头，PE 头偏移在 0x3C
  if [ "$b0" = "77" ] && [ "$b1" = "90" ]; then
    lfanew=$(u32le 60 "$f") || { echo "unknown"; return; }
    pe0=$(byte_at "$lfanew" "$f")
    pe1=$(byte_at $(($lfanew + 1)) "$f")
    if [ "$pe0" = "80" ] && [ "$pe1" = "69" ]; then
      mach=$(u16le $(($lfanew + 4)) "$f") || { echo "unknown"; return; }
      case "$mach" in
        34404) echo "windows/amd64" ;;
        43620) echo "windows/arm64" ;;
        332)   echo "windows/x86" ;;
        452)   echo "windows/armv7" ;;
        *)     echo "unknown" ;;
      esac
      return
    fi
    echo "unknown"
    return
  fi

  # ---- Mach-O：FE ED FA CE 等魔数
  if [ "$b0" = "202" ] && [ "$b1" = "250" ] && [ "$b2" = "237" ] && [ "$b3" = "254" ]; then
    cpu=$(u32le 4 "$f") || { echo "unknown"; return; }
    case "$cpu" in
      16777223) echo "macos/amd64" ;;
      16777228) echo "macos/arm64" ;;
      7)        echo "macos/x86" ;;
      12)       echo "macos/armv7" ;;
      *)        echo "unknown" ;;
    esac
    return
  fi

  echo "unknown"
}

# ---------------- 当前系统 ----------------

detect_host() {
  os=$(uname -s 2>/dev/null || echo unknown)
  arch=$(uname -m 2>/dev/null || echo unknown)

  case "$os" in
    Linux)  host_os="linux" ;;
    Darwin) host_os="macos" ;;
    *)      host_os="unknown" ;;
  esac

  case "$arch" in
    x86_64|amd64)        host_arch="amd64" ;;
    aarch64|arm64)       host_arch="arm64" ;;
    armv7l|armv7|armv6l) host_arch="armv7" ;;
    i386|i486|i586|i686) host_arch="x86" ;;
    ppc64le)             host_arch="ppc64le" ;;
    *)                   host_arch="unknown" ;;
  esac

  echo "$host_os/$host_arch"
}

# ---------------- 检验并安装 ----------------

bin_plat=$(detect_binary "$SRC")
host_plat=$(detect_host)

echo "==> 二进制：$SRC"
echo "==> 二进制平台/架构：$bin_plat"
echo "==> 当前系统平台/架构：$host_plat"

if [ "$bin_plat" = "unknown" ]; then
  echo "" >&2
  echo "错误：无法识别该文件的格式，它可能不是可执行二进制，或者已损坏。" >&2
  echo "      （支持 ELF / PE / Mach-O 三种文件头）" >&2
  exit 1
fi

if [ "$host_plat" = "unknown" ]; then
  echo "" >&2
  echo "错误：无法识别当前系统（uname 返回 $os/$arch）。" >&2
  exit 1
fi

bin_os=${bin_plat%%/*}
bin_arch=${bin_plat##*/}
host_os=${host_plat%%/*}
host_arch=${host_plat##*/}

if [ "$bin_os" != "$host_os" ] || [ "$bin_arch" != "$host_arch" ]; then
  echo "" >&2
  echo "错误：架构不匹配，已停止安装。" >&2
  echo "       二进制是：$bin_os/$bin_arch" >&2
  echo "       当前系统：$host_os/$host_arch" >&2
  echo "" >&2
  case "$host_os/$host_arch" in
    linux/amd64)   cand="cochat-linux-amd64" ;;
    linux/arm64)   cand="cochat-linux-arm64" ;;
    linux/armv7)   cand="cochat-linux-armv7" ;;
    windows/amd64) cand="cochat-windows-amd64.exe" ;;
    macos/amd64)   cand="cochat-macos-amd64（暂未发布，需自行编译）" ;;
    macos/arm64)   cand="cochat-macos-arm64（暂未发布，需自行编译）" ;;
    *)             cand="（无预编译版本，需自行编译）" ;;
  esac
  echo "       当前系统应使用：$cand" >&2
  if [ "$FORCE" = "1" ]; then
    echo "" >&2
    echo "警告：COCHAT_FORCE=1，忽略不匹配继续安装。" >&2
  else
    exit 1
  fi
fi

mkdir -p "$PREFIX" 2>/dev/null || {
  echo "错误：无法创建目录 $PREFIX（权限不足？可用 COCHAT_PREFIX 指定其他目录）" >&2
  exit 1
}

tmp="$PREFIX/.${BIN_NAME}.install.$$"
trap 'rm -f "$tmp"' EXIT INT TERM

cp "$SRC" "$tmp" || {
  echo "错误：复制到 $PREFIX 失败" >&2
  exit 1
}
chmod +x "$tmp"
mv -f "$tmp" "$PREFIX/$BIN_NAME"
trap - EXIT INT TERM

if [ ! -x "$PREFIX/$BIN_NAME" ]; then
  echo "错误：安装后 $PREFIX/$BIN_NAME 不可执行，请检查该目录是否 noexec" >&2
  exit 1
fi

# 内建隧道插件：和主程序**同一个目录**里才找得到（loader 先看 exe 同目录）。
# 它不由参数传入，而是"如果二进制旁边躺着就一起装"—— 这样安装脚本的接口
# 不用为可选组件多开一个参数，缺了插件也只是没有隧道，主程序照常可用。
SRC_DIR="$(cd "$(dirname "$SRC")" && pwd)"
for plug in libcochat-tunnel.so cochat-tunnel.dll; do
  if [ -f "$SRC_DIR/$plug" ]; then
    cp "$SRC_DIR/$plug" "$PREFIX/$plug" || {
      echo "警告：隧道插件 $plug 复制失败，内建隧道将不可用" >&2
    }
    echo "==> 隧道插件已安装到 $PREFIX/$plug"
  fi
done

echo ""
echo "==> 已安装到 $PREFIX/$BIN_NAME"

case ":${PATH}:" in
  *":$PREFIX:"*) ;;
  *)
    echo ""
    echo "提示：$PREFIX 不在 PATH 中，加一行即可："
    echo "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.profile"
    ;;
esac

echo ""
echo "完成。运行 '$BIN_NAME' 启动。"
