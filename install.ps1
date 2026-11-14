# cochat 安装脚本（Windows / PowerShell）
#
#   用法（PowerShell）：
#     irm https://raw.githubusercontent.com/ycm50/intercom/main/install.ps1 | iex
#
#   用法（cmd，需要先有 PowerShell）：
#     powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/ycm50/intercom/main/install.ps1 | iex"
#
#   安装位置：$env:USERPROFILE\.local\bin\cochat.exe（已存在则覆盖）
#   可用环境变量覆盖：
#     COCHAT_VERSION   指定版本号（默认 latest）
#     COCHAT_BASE_URL  指定下载根地址（默认走 GitHub Releases）
#     COCHAT_PREFIX    指定安装目录（默认 %USERPROFILE%\.local\bin）
#
# 注意：全部下载动作使用系统自带的 curl.exe，不依赖 Invoke-WebRequest。
$ErrorActionPreference = 'Stop'

$Repo = 'ycm50/intercom'
$BinName = 'cochat'
$Version = if ($env:COCHAT_VERSION) { $env:COCHAT_VERSION } else { 'latest' }
$Prefix = if ($env:COCHAT_PREFIX) { $env:COCHAT_PREFIX } else { Join-Path $env:USERPROFILE '.local\bin' }

# ---------- 找 curl.exe ----------
$curl = Join-Path $env:SystemRoot 'System32\curl.exe'
if (-not (Test-Path $curl)) {
  $cmd = Get-Command curl.exe -ErrorAction SilentlyContinue
  if ($cmd) { $curl = $cmd.Source }
}
if (-not (Test-Path $curl)) {
  Write-Error '未找到 curl.exe（Windows 10 1803 及以上自带）。请先升级系统或在精简系统中补回 curl.exe。'
  exit 1
}

# ---------- 识别架构 ----------
# PROCESSOR_ARCHITECTURE 在 32 位进程里可能显示 x86，这里以系统真实架构为准
$archRaw = $env:PROCESSOR_ARCHITEW6432
if (-not $archRaw) { $archRaw = $env:PROCESSOR_ARCHITECTURE }
switch ($archRaw.ToUpper()) {
  'AMD64' { $archTag = 'amd64' }
  'ARM64' { $archTag = 'arm64' }
  'X86'   { Write-Error '不支持 32 位 Windows'; exit 1 }
  default { Write-Error "不支持的架构 $archRaw"; exit 1 }
}
$asset = "$BinName-windows-$archTag.exe"

# ---------- 拼下载地址 ----------
if ($env:COCHAT_BASE_URL) {
  $base = $env:COCHAT_BASE_URL.TrimEnd('/')
  $url = "$base/$asset"
} elseif ($Version -eq 'latest') {
  $url = "https://github.com/$Repo/releases/latest/download/$asset"
} else {
  $url = "https://github.com/$Repo/releases/download/$Version/$asset"
}

Write-Host "==> 架构 windows/$archTag"
Write-Host "==> 下载 $url"

# ---------- 下载 ----------
if (-not (Test-Path $Prefix)) { New-Item -ItemType Directory -Path $Prefix -Force | Out-Null }
$target = Join-Path $Prefix "$BinName.exe"
$tmp = Join-Path $Prefix ".$BinName.download.exe"

& $curl -fL --retry 3 --retry-delay 2 --connect-timeout 20 -o $tmp $url
if ($LASTEXITCODE -ne 0) {
  if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
  Write-Error '下载失败，请检查网络或版本号'
  exit 1
}

# ---------- 安装 ----------
Move-Item -Force $tmp $target
Write-Host "==> 已安装到 $target"

# ---------- 提示 PATH ----------
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($userPath -notlike "*$Prefix*") {
  Write-Host ''
  Write-Host "提示：$Prefix 不在用户 PATH 中，已尝试自动添加…"
  try {
    [Environment]::SetEnvironmentVariable('Path', ($userPath.TrimEnd(';') + ';' + $Prefix), 'User')
    Write-Host '已添加到用户 PATH，重新打开终端后生效。'
  } catch {
    Write-Host "添加失败，请手动把 $Prefix 加入 PATH。"
  }
}

Write-Host ''
Write-Host "完成。新开一个终端后运行 'cochat' 即可启动。"
