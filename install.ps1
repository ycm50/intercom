# cochat 安装脚本（Windows / PowerShell）
#
#   用法：
#     .\install.ps1 <二进制文件>
#
#   脚本先读取二进制文件头，判断它是哪个平台、哪个架构编译的，
#   与当前系统不符时直接报错退出，相符才安装成 %USERPROFILE%\.local\bin\cochat.exe
#
#   可用环境变量：
#     COCHAT_PREFIX  指定安装目录
#     COCHAT_FORCE=1 架构不匹配也强行安装（不推荐，仅供排障）
$ErrorActionPreference = "Stop"

$BinName = "cochat"
$Prefix = if ($env:COCHAT_PREFIX) { $env:COCHAT_PREFIX } else { Join-Path $env:USERPROFILE ".local\bin" }
$Force = ($env:COCHAT_FORCE -eq "1")

function Usage {
  Write-Host "用法: .\install.ps1 <二进制文件>" -ForegroundColor Yellow
  Write-Host ""
  Write-Host "例如: .\install.ps1 .\cochat-windows-amd64.exe" -ForegroundColor Yellow
  exit 1
}

if ($args.Count -lt 1) { Usage }
$Src = $args[0]
if (-not $Src) { Usage }

if (-not (Test-Path -LiteralPath $Src -PathType Leaf)) {
  Write-Host ("错误：找不到文件 " + $Src) -ForegroundColor Red
  exit 1
}
$Item = Get-Item -LiteralPath $Src
if ($Item.Length -lt 64) {
  Write-Host ("错误：" + $Src + " 太小，不是可执行文件") -ForegroundColor Red
  exit 1
}

# ---------------- 读取文件头 ----------------

$fs = [System.IO.File]::OpenRead($Item.FullName)
try {
  $head = New-Object byte[] 4096
  $read = $fs.Read($head, 0, $head.Length)
} finally {
  $fs.Dispose()
}

function Detect-Binary {
  param([byte[]]$B, [int]$Len)

  # ---- ELF：0x7F E L F
  if ($B[0] -eq 0x7F -and $B[1] -eq 0x45 -and $B[2] -eq 0x4C -and $B[3] -eq 0x46) {
    $cls = $B[4]
    $dat = $B[5]
    if ($dat -ne 1) { return "unknown" }        # 只支持小端
    $mach = [BitConverter]::ToUInt16($B, 18)
    if ($cls -eq 2) {
      switch ($mach) {
        62  { return "linux/amd64" }
        183 { return "linux/arm64" }
        21  { return "linux/ppc64le" }
        default { return "unknown" }
      }
    } else {
      switch ($mach) {
        3  { return "linux/x86" }
        40 { return "linux/armv7" }
        default { return "unknown" }
      }
    }
  }

  # ---- PE：MZ 开头
  if ($B[0] -eq 0x4D -and $B[1] -eq 0x5A) {
    $lfanew = [BitConverter]::ToInt32($B, 60)
    if ($lfanew -le 0 -or ($lfanew + 6) -ge $Len) { return "unknown" }
    if ($B[$lfanew] -ne 0x50 -or $B[$lfanew + 1] -ne 0x45) { return "unknown" }
    $mach = [BitConverter]::ToUInt16($B, $lfanew + 4)
    switch ($mach) {
      0x8664 { return "windows/amd64" }
      0xAA64 { return "windows/arm64" }
      0x014C { return "windows/x86" }
      0x01C4 { return "windows/armv7" }
      default { return "unknown" }
    }
  }

  # ---- Mach-O
  if (($B[0] -eq 0xCF -and $B[1] -eq 0xFA -and $B[2] -eq 0xED -and $B[3] -eq 0xFE) -or
      ($B[0] -eq 0xFE -and $B[1] -eq 0xED -and $B[2] -eq 0xFA -and $B[3] -eq 0xCF)) {
    $le = ($B[0] -eq 0xCF)
    $cpu = if ($le) { [BitConverter]::ToUInt32($B, 4) } else {
      ([uint32]$B[7] -shl 24) -bor ([uint32]$B[6] -shl 16) -bor ([uint32]$B[5] -shl 8) -bor [uint32]$B[4]
    }
    switch ($cpu) {
      0x01000007 { return "macos/amd64" }
      0x0100000C { return "macos/arm64" }
      7          { return "macos/x86" }
      12         { return "macos/armv7" }
      default    { return "unknown" }
    }
  }

  return "unknown"
}

function Detect-Host {
  # PROCESSOR_ARCHITECTURE 在 32 位进程里会显示 x86，优先用真实架构变量
  $raw = $env:PROCESSOR_ARCHITEW6432
  if (-not $raw) { $raw = $env:PROCESSOR_ARCHITECTURE }
  switch ($raw.ToUpper()) {
    "AMD64" { return "windows/amd64" }
    "ARM64" { return "windows/arm64" }
    "X86"   { return "windows/x86" }
    "ARM"   { return "windows/armv7" }
    default { return "unknown" }
  }
}

# ---------------- 检验并安装 ----------------

$BinPlat  = Detect-Binary -B $head -Len $read
$HostPlat = Detect-Host

Write-Host ("==> 二进制：" + $Item.FullName)
Write-Host ("==> 二进制平台/架构：" + $BinPlat)
Write-Host ("==> 当前系统平台/架构：" + $HostPlat)
Write-Host ""

if ($BinPlat -eq "unknown") {
  Write-Host "错误：无法识别该文件的格式，它可能不是可执行二进制，或者已损坏。" -ForegroundColor Red
  Write-Host "      （支持 ELF / PE / Mach-O 三种文件头）" -ForegroundColor Red
  exit 1
}

if ($HostPlat -eq "unknown") {
  Write-Host ("错误：无法识别当前系统架构（PROCESSOR_ARCHITECTURE=" + $env:PROCESSOR_ARCHITECTURE + "）") -ForegroundColor Red
  exit 1
}

$BinOs, $BinArch   = $BinPlat.Split("/")
$HostOs, $HostArch = $HostPlat.Split("/")

if ($BinOs -ne $HostOs -or $BinArch -ne $HostArch) {
  Write-Host "错误：架构不匹配，已停止安装。" -ForegroundColor Red
  Write-Host ("       二进制是：" + $BinOs + "/" + $BinArch) -ForegroundColor Red
  Write-Host ("       当前系统：" + $HostOs + "/" + $HostArch) -ForegroundColor Red
  Write-Host ""
  $cand = switch ($HostPlat) {
    "windows/amd64" { "cochat-windows-amd64.exe" }
    "windows/arm64" { "cochat-windows-arm64.exe（暂未发布，需自行编译）" }
    "linux/amd64"   { "cochat-linux-amd64（请用 install.sh）" }
    "linux/arm64"   { "cochat-linux-arm64（请用 install.sh）" }
    default         { "（无预编译版本，需自行编译）" }
  }
  Write-Host ("       当前系统应使用：" + $cand) -ForegroundColor Red
  if ($Force) {
    Write-Host ""
    Write-Host "警告：COCHAT_FORCE=1，忽略不匹配继续安装。" -ForegroundColor Yellow
  } else {
    exit 1
  }
}

if (-not (Test-Path -LiteralPath $Prefix)) {
  try {
    New-Item -ItemType Directory -Path $Prefix -Force | Out-Null
  } catch {
    Write-Host ("错误：无法创建目录 " + $Prefix) -ForegroundColor Red
    exit 1
  }
}

$target = Join-Path $Prefix ($BinName + ".exe")
$tmp    = Join-Path $Prefix ("." + $BinName + ".install.exe")

try {
  Copy-Item -LiteralPath $Item.FullName -Destination $tmp -Force
  Move-Item -LiteralPath $tmp -Destination $target -Force
} catch {
  if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
  Write-Host ("错误：安装失败（" + $_.Exception.Message + "）。若 cochat 正在运行，请先退出。") -ForegroundColor Red
  exit 1
}

Write-Host ("==> 已安装到 " + $target) -ForegroundColor Green

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike ("*" + $Prefix + "*")) {
  Write-Host ""
  Write-Host ("提示：" + $Prefix + " 不在用户 PATH 中，正在添加…")
  try {
    [Environment]::SetEnvironmentVariable("Path", ($userPath.TrimEnd(";") + ";" + $Prefix), "User")
    Write-Host "已添加到用户 PATH，重新打开终端后生效。" -ForegroundColor Green
  } catch {
    Write-Host ("添加失败，请手动把 " + $Prefix + " 加入 PATH。") -ForegroundColor Yellow
  }
}

Write-Host ""
Write-Host "完成。新开一个终端后运行 cochat 即可启动。"
