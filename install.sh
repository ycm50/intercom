#!/bin/sh
# cochat 安装脚本（Linux / macOS 通用）
#
#   用法：
#     curl -fsSL https://raw.githubusercontent.com/ycm50/intercom/main/install.sh | sh
#
#   安装位置：~/.local/bin/cochat（已存在则覆盖）
#   可用环境变量覆盖：
#     COCHAT_VERSION   指定版本号（默认 latest）
#     COCHAT_BASE_URL  指定下载根地址（默认走 GitHub Releases，便于内网/自建镜像）
#     COCHAT_PREFIX    指定安装目录（默认 ~/.local/bin）
set -eu

REPO="ycm50/intercom"
BIN_NAME="cochat"
VERSION="${COCHAT_VERSION:-latest}"
PREFIX="${COCHAT_PREFIX:-$HOME/.local/bin}"

# ---------- 识别平台与架构 ----------
os=$(uname -s 2>/dev/null || echo unknown)
arch=$(uname -m 2>/dev/null || echo unknown)

case "$os" in
  Linux)  os_tag="linux"  ;;
  Darwin) os_tag="macos"  ;;
  *)
    echo "错误：不支持的系统 $os（本脚本支持 Linux / macOS；Windows 请用 install.ps1）" >&2
    exit 1
    ;;
esac

case "$arch" in
  x86_64|amd64)   arch_tag="amd64" ;;
  aarch64|arm64)  arch_tag="arm64" ;;
  armv7l|armv7)   arch_tag="armv7" ;;
  *)
    echo "错误：不支持的架构 $arch" >&2
    exit 1
    ;;
esac

asset="${BIN_NAME}-${os_tag}-${arch_tag}"

# ---------- 拼下载地址 ----------
if [ -n "${COCHAT_BASE_URL:-}" ]; then
  base="${COCHAT_BASE_URL%/}"
  url="$base/$asset"
elif [ "$VERSION" = "latest" ]; then
  url="https://github.com/$REPO/releases/latest/download/$asset"
else
  url="https://github.com/$REPO/releases/download/$VERSION/$asset"
fi

echo "==> 平台 ${os_tag}/${arch_tag}"
echo "==> 下载 $url"

# ---------- 创建目录并下载 ----------
mkdir -p "$PREFIX"
tmp="$PREFIX/.${BIN_NAME}.download.$$"
trap 'rm -f "$tmp"' EXIT INT TERM

if ! curl -fL --retry 3 --retry-delay 2 --connect-timeout 20 -o "$tmp" "$url"; then
  echo "错误：下载失败，请检查网络或版本号" >&2
  exit 1
fi

# ---------- 安装 ----------
chmod +x "$tmp"
mv -f "$tmp" "$PREFIX/$BIN_NAME"
trap - EXIT INT TERM

echo "==> 已安装到 $PREFIX/$BIN_NAME"

# ---------- 提示 PATH ----------
case ":${PATH}:" in
  *":$PREFIX:"*) ;;
  *)
    echo ""
    echo "提示：$PREFIX 不在 PATH 中，可用下面任一方式启用："
    echo "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.profile && . ~/.profile"
    echo "  或直接把 $PREFIX/$BIN_NAME 拷到 /usr/local/bin"
    ;;
esac

echo ""
echo "完成。运行 '"$BIN_NAME"' 启动；若进程报权限问题，请确认挂载点不是 noexec。"
