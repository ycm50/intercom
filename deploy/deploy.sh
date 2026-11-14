#!/bin/bash
# 在 Linux 服务器上一键安装/更新对讲机服务
#   用法：bash deploy.sh <cloudflared 二进制路径，可选>
#   目录：/opt/intercom（可执行文件 + public + data）
set -e

ROOT=${1:-/opt/intercom}
SRC=$(cd "$(dirname "$0")/.." && pwd)

echo "[1/4] 创建目录 $ROOT"
mkdir -p "$ROOT"

echo "[2/4] 安装可执行文件与前端"
BIN=""
for cand in "$SRC/build-linux/cochat" "$SRC/build/cochat" "$SRC/dist/cochat-linux-amd64"; do
  if [ -f "$cand" ]; then BIN="$cand"; break; fi
done
if [ -z "$BIN" ]; then
  echo "未找到编译产物，请先执行 bash build-linux.sh"
  exit 1
fi
install -m 755 "$BIN" "$ROOT/cochat"
rm -rf "$ROOT/public"
mkdir -p "$ROOT/public"
cp -r "$SRC/public/." "$ROOT/public/"
mkdir -p "$ROOT/data"

echo "[3/4] 安装 systemd 服务"
install -m 644 "$SRC/deploy/intercom.service" /etc/systemd/system/intercom.service
systemctl daemon-reload
systemctl enable intercom
systemctl restart intercom
sleep 1

echo "[4/4] 状态"
systemctl --no-pager --lines=5 status intercom || true
echo
echo "本机地址: http://127.0.0.1:8080/"
echo "注册账号: $ROOT/cochat --add 用户名 密码 显示名"
echo "查看日志: journalctl -u intercom -f"
echo
echo "对外发布请启动 cloudflared："
echo "  cloudflared tunnel --url http://127.0.0.1:8080"