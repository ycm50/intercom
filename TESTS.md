# 测试清单

项目：局域网对讲机（intercom）。测试脚本统一放在仓库外的 `../tmpscripts/`。

两层测试，用途不同：

- **第 0 项 单元测试**：秒级、无网络、无外部进程，随代码走，`ctest` 一把过。改动后总是先跑这个。
- **第 1–10 项 端到端测试**：真起服务、真开浏览器、真走隧道；耗时且依赖本机环境（Chrome、网络），按需跑。

约定：每次改动只跑受影响的那一项；只有说"全量测试"时才从头跑一遍。

## 0. 单元测试（秒级，随代码走）

```powershell
$env:PATH = "$env:UCRT_PATH;$env:PATH"
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release `
      -DCMAKE_C_COMPILER="$env:UCRT_PATH\gcc.exe" `
      -DCMAKE_CXX_COMPILER="$env:UCRT_PATH\g++.exe" `
      -DCOCHAT_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

Linux 下同理（去掉编译器那两个参数）。

覆盖：

| 用例 | 验什么 |
| --- | --- |
| `crypto` | 内置 SHA-256 / HMAC-SHA256 / PBKDF2 与 OpenSSL 逐字节一致；长密码（>64 字节）走的分支也对 |
| `json` | JSON 数组/对象往返，ICE 配置的读入格式 |
| `ops` | `--cur`/`--res` 依赖的进程名识别（`cochat`/`cochat.exe`/发布名算，`cochatx`/`cloudflared` 不算）、进程存活判定、自述目录位置 |

> 为什么测试默认不编：默认构建必须零第三方依赖。测试拿 OpenSSL 当对照实现，
> 所以只有 `-DCOCHAT_BUILD_TESTS=ON` 时才引入它。

### 端到端测试的统一前置条件

1–4 项和第 10 项都要一个跑着的服务和两个账号。**先做这一步，否则后面全是"密码错误"**：

```powershell
$exe  = ".\build\cochat.exe"
$acct = "$env:TEMP\ic-acct"
$env:USERPROFILE = "$env:TEMP\ic-home"          # 让自述文件写到可写目录
New-Item -ItemType Directory -Force $env:USERPROFILE | Out-Null

& $exe --add alice alicepass1 --display 爱丽丝 --accounts $acct
& $exe --add bob   bobpass1   --display 鲍勃   --accounts $acct

# 测试 7 会把 alice 的密码改成 newpass99 再改回来；跑乱了两条命令复位：
& $exe --passwd alice alicepass1 --accounts $acct
& $exe --passwd bob   bobpass1   --accounts $acct

Start-Process $exe -ArgumentList '--port','8080','--accounts',$acct
```

UI 测试还需要：

```powershell
pnpm add puppeteer-core            # 只装库，用系统的 Chrome
$env:IC_CHROME = "C:\Program Files\Google\Chrome\Application\chrome.exe"
```

> 每次 UI 测试用独立的浏览器 profile；如果报 `browser is already running`，
> 说明上一次的 Chrome 没退干净：`Get-Process chrome | Stop-Process -Force` 后重跑。

## 1. 信令协议冒烟测试

```powershell
$env:IC_URL = "ws://127.0.0.1:8080/ws"   # 或 wss://xxx.trycloudflare.com/ws
node ..\tmpscripts\intercom-test.mjs
```

覆盖：两端登录、在线列表、文字转发、来电、通话建立与主叫标记、SDP 信令转发、挂断通知、语音消息转发。

## 2. 移动端 UI 端到端测试（headless Chrome + 手机视口 + 假摄像头）

```powershell
$env:IC_BASE   = "http://127.0.0.1:8080/"      # 或 https://xxx.trycloudflare.com/
$env:IC_PASS_A = "alicepass1"
node ..\tmpscripts\intercom-ui-test.mjs
```

覆盖：登录进大厅看到对方、双向文字气泡、语音录制与播放、来电界面、视频通话建立（双向 audio+video track live）、挂断退出。
截图输出到 `../tmpscripts/shots/`。

> **已知抖动**：headless Chrome 的假摄像头首帧偶尔比应用内的"黑屏看门狗"慢，
> 看门狗会把刚拿到的视频轨停掉重开，此时 `远端解出画面` / `远端视频轨 live` 会红。
> 这是既有行为（用原始提交的二进制同样复现），不是构建问题——隔一次重跑通常就消失。
> 真机或走隧道时观察不到。判定"是不是真回归"的办法：用 `git worktree` 编一份改动前的提交跑同一测试对照。

## 3. 通话保持 / 断线重连测试

```powershell
node ..\tmpscripts\intercom-call-resume-test.mjs
```

覆盖：通话中一方断线 → 服务端保留房间并通知 `call-peer-lost` → 用 token 重连 → 收到 `call-resume` / `call-peer-back` → 恢复后仍能收发消息与挂断。

## 4. 摄像头/麦克风权限被拒测试

```powershell
node ..\tmpscripts\intercom-permission-deny-test.mjs
```

覆盖：`--deny-permission-prompts` 下点击视频通话按钮 → 不进入通话界面、不卡在申请中、聊天页顶部出现可操作的权限提示。

## 5. 端口暴露检查

```powershell
node ..\tmpscripts\intercom-bind-check.mjs
```

期望：`127.0.0.1:8080 -> OPEN`，`<局域网IP>:8080 -> REFUSED`。

## 6. Linux 构建与冒烟（在 WSL 里做，VPS 只跑成品）

```bash
bash build-linux.sh dist     # 产出静态二进制（不依赖目标机任何库）
```

推送到服务器后：

```bash
curl -s http://127.0.0.1:8095/api/info          # API
curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8095/   # 首页应为 200
```

## 7. 账号存储与改密/改名

```powershell
$exe  = ".\build\cochat.exe"
$acct = "$env:TEMP\ic-acct"
& $exe --add alice alicepass1 --display 爱丽丝 --accounts $acct
Get-Content "$acct\alice.json"        # 只有 salt + hash，无明文
& $exe --passwd alice newpass99 --accounts $acct   # 重新加盐
& $exe --un alice alice_new --accounts $acct       # 文件改名、密码不变
& $exe --list --accounts $acct                     # 只输出用户名，一行一个

# 自动化版（同时验证明文不落盘、热加载、改名后旧名失效）
$env:IC_ACCT_DIR = $acct
node ..\tmpscripts\ws-password-check.mjs
```

`ws-password-check.mjs` 跑完会把用户名改回 `alice`，但**密码会停在 `newpass99`**，
继续跑其它项前记得复位：`& $exe --passwd alice alicepass1 --accounts $acct`。

## 8. 账号热加载

命令行 `--add` 注册后**不重启服务**直接登录，应成功（服务按 accounts.json 修改时间热加载）。

## 9. 隧道连通性

```powershell
.\tools\cloudflared.exe tunnel --no-autoupdate --protocol http2 --url http://127.0.0.1:8080
```

日志里出现 `https://xxx.trycloudflare.com` 后：

```powershell
$u = "https://xxx.trycloudflare.com"
(Invoke-WebRequest "$u/api/info" -UseBasicParsing).Content     # 应 200，且 "secure":true
$env:IC_URL  = "wss://xxx.trycloudflare.com/ws"
node ..\tmpscripts\intercom-test.mjs                           # 信令全流程走公网
$env:IC_BASE = "$u/"
node ..\tmpscripts\intercom-ui-test.mjs                        # UI + 视频通话走公网
```

要点：

- `secure:true` 说明请求确实来自隧道（服务端靠 `CF-Ray` / `X-Forwarded-Proto` 判定），
  同时也能反证"公网直连被拒"仍然有效。
- QUIC 不通时加 `--protocol http2`（本机实测默认 quic 会 `timeout: no recent network activity`）。
- 想让 `cochat --cur` 也看得到这个地址，起服务时带 `--tunnel-url https://xxx.trycloudflare.com`。

## 10. 运维参数（--cur / --res / --passwd / --help）

```powershell
$exe = ".\build\cochat.exe"
$acct = "$env:TEMP\ic-acct"

# 帮助里能看到全部参数
& $exe --help | Select-String '--cur','--res','--passwd','--tunnel-url'

# 起两个实例（一个声明隧道地址、一个关闭隧道）
# 用 $env:TEMP 下的 HOME，自述文件才写得进去（受管目录可能不可写）
$env:USERPROFILE = "$env:TEMP\ic-home"
$p1 = Start-Process $exe -ArgumentList '--port','8181','--accounts',$acct,'--tunnel-url','https://demo.trycloudflare.com' -PassThru
$p2 = Start-Process $exe -ArgumentList '--port','8182','--accounts',$acct,'--no-tunnel' -PassThru
Start-Sleep 2

& $exe --cur                       # 两个实例都在，状态分别为「已连接」「隧道已关闭」
& $exe --cur --data .\data --port 8181   # 只看指定实例
& $exe --cur --data .\missing     # 返回 1 并说明找不到

& $exe --passwd alice 123456 --accounts $acct
& $exe --passwd --check alice 123456 --accounts $acct   # 账号文件 + 运行中的服务都应为「匹配 / 接受」
& $exe --passwd --check alice wrong --accounts $acct    # 应为「不匹配 / 拒绝」，返回 1
& $exe --passwd alice 123 --accounts $acct              # 过短：拒绝；加 --force 才改

& $exe --res                       # 重启 pid 最小者，应打印「已用同样的参数启动 pid N」和新地址
& $exe --cur                       # 旧 pid 消失、新 pid 出现，公网地址仍在

Stop-Process $p1.Id,$p2.Id -Force
& $exe --cur                       # 死进程的自述文件应被自动清掉
```

覆盖：`--help` 文案、`--cur` 的实例/隧道状态/数据目录过滤、`--res` 的原命令行重放与地址回显、
`--passwd` 的改密/核对/长度校验、退出时与死进程的自述清理。
