# 使用 MSYS2 UCRT64 工具链构建（g++ / cmake / ninja）
param(
  [string]$BuildDir = "build",
  [switch]$Clean
)

$ErrorActionPreference = "Stop"
$bin = $env:UCRT_PATH
if (-not $bin -or -not (Test-Path (Join-Path $bin "g++.exe"))) {
  throw "未找到 UCRT64 工具链，请先设置 UCRT_PATH（例如 A:\msys64\ucrt64\bin）"
}
$env:PATH = "$bin;$env:PATH"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($Clean -and (Test-Path (Join-Path $root $BuildDir))) {
  Remove-Item -Recurse -Force (Join-Path $root $BuildDir)
}

$cfgArgs = @(
  "-S", $root,
  "-B", (Join-Path $root $BuildDir),
  "-G", "Ninja",
  "-DCMAKE_BUILD_TYPE=Release",
  ("-DCMAKE_C_COMPILER=" + $bin + "\gcc.exe"),
  ("-DCMAKE_CXX_COMPILER=" + $bin + "\g++.exe")
)
& (Join-Path $bin "cmake.exe") @cfgArgs
if ($LASTEXITCODE -ne 0) { throw "cmake 配置失败" }

& (Join-Path $bin "cmake.exe") --build (Join-Path $root $BuildDir)
if ($LASTEXITCODE -ne 0) { throw "编译失败" }

# 前端语法自检：避免 index.html 里的 JS 被改坏后仍被打包发布
$htmlPath = Join-Path $root "public\index.html"
$html = Get-Content $htmlPath -Raw
$matches = [regex]::Matches($html, '<script>([\s\S]*?)</script>')
if ($matches.Count -eq 0) { throw "public/index.html 缺少 <script> 段" }
$js = ($matches | ForEach-Object { $_.Groups[1].Value }) -join "`n;`n"
$tmp = Join-Path $env:TEMP ("intercom-check-" + [guid]::NewGuid().ToString() + ".js")
Set-Content -Path $tmp -Value $js -Encoding UTF8
$node = Get-Command node -ErrorAction SilentlyContinue
if ($node) {
  $checkScript = Join-Path $env:TEMP ("intercom-syntax-" + [guid]::NewGuid().ToString() + ".mjs")
  Set-Content -Path $checkScript -Encoding UTF8 -Value @(
    "import { readFileSync } from 'node:fs';",
    "try { new Function(readFileSync(process.argv[2], 'utf8')); console.log('前端 JS 语法 OK'); }",
    "catch (e) { console.error('前端 JS 语法错误: ' + e.message); process.exit(1); }"
  )
  & $node.Source $checkScript $tmp
  if ($LASTEXITCODE -ne 0) { Remove-Item $tmp, $checkScript -Force -ErrorAction SilentlyContinue; throw "前端 JS 语法检查未通过" }
  Remove-Item $tmp, $checkScript -Force -ErrorAction SilentlyContinue
}

$exe = Get-ChildItem -Path (Join-Path $root $BuildDir) -Filter "intercom-server.exe" -Recurse |
  Select-Object -First 1
Write-Host "构建完成: $($exe.FullName)"