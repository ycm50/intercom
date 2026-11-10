# 一键启动：本地对讲机服务 + cloudflared 隧道
#   - 服务只监听 127.0.0.1:8080，公网 IP 无法直连
#   - cloudflared 把本地服务映射到 https://xxx.trycloudflare.com（自带 https，手机 Chrome 才有麦克风/摄像头权限）
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$port = 8080

$exe = Join-Path $here "build\intercom-server.exe"
if (-not (Test-Path $exe)) { throw "未找到 $exe，请先运行 build.ps1" }

Write-Host "[1/2] 启动对讲机服务（仅监听 127.0.0.1:$port）…"
$server = Start-Process -FilePath $exe -ArgumentList "--port", $port -PassThru
Start-Sleep -Seconds 2

$cfd = Join-Path $here "tools\cloudflared.exe"
if (-not (Test-Path $cfd)) {
  Write-Host "未找到 tools\cloudflared.exe，请从 https://github.com/cloudflare/cloudflared/releases 下载 cloudflared-windows-amd64.exe 并改名放入 tools\"
  Stop-Process -Id $server.Id -ErrorAction SilentlyContinue
  exit 1
}

Write-Host "[2/2] 启动 cloudflared 隧道，把下面出现的 https://xxx.trycloudflare.com 发给对方"
try {
  & $cfd tunnel --url "http://127.0.0.1:$port"
} finally {
  Stop-Process -Id $server.Id -ErrorAction SilentlyContinue
}
