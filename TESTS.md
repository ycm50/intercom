# 测试清单

项目：局域网对讲机（intercom）。测试脚本统一放在仓库外的 `../tmpscripts/`。

## 1. 信令协议冒烟测试

```powershell
$env:IC_URL = "ws://127.0.0.1:8080/ws"   # 或 wss://xxx.trycloudflare.com/ws
node ..\tmpscripts\intercom-test.mjs
```

覆盖：两端登录、在线列表、文字转发、来电、通话建立与主叫标记、SDP 信令转发、挂断通知、语音消息转发。

## 2. 移动端 UI 端到端测试（headless Chrome + 手机视口 + 假摄像头）

```powershell
$env:IC_BASE = "http://127.0.0.1:8080/"
node ..\tmpscripts\intercom-ui-test.mjs
```

覆盖：登录进大厅看到对方、双向文字气泡、语音录制与播放、来电界面、视频通话建立（双向 audio+video track live）、挂断退出。
截图输出到 `../tmpscripts/shots/`。

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
$exe = ".\build\intercom-server.exe"
& $exe --add alice alicepass1 爱丽丝
Get-Content "$env:USERPROFILE\.intercom\alice.json"     # 只有 salt + hash，无明文
& $exe --passwd alice newpass99                          # 重新加盐
& $exe --un alice alice_new                              # 文件改名、密码不变
& $exe --list                                            # 只输出用户名，一行一个
node ..\tmpscripts\ws-password-check.mjs                # 旧密码应失败、新密码成功、旧用户名不存在
```

## 8. 账号热加载

命令行 `--add` 注册后**不重启服务**直接登录，应成功（服务按 accounts.json 修改时间热加载）。

## 9. 隧道连通性

启动 `tools\cloudflared.exe tunnel --url http://127.0.0.1:8080`，用输出的 `https://xxx.trycloudflare.com` 打开页面，走一遍登录 / 通话。