# 局域网对讲机（intercom）

零第三方运行时依赖的聊天服务器：C++20 + 单头文件 cpp-httplib + OpenSSL，全部静态链接，
一个 exe 加一个 `public/index.html` 就能跑。前端是纯 HTML + 原生 JavaScript，针对手机 Chrome 适配。

![登录](docs/01-登录.png)

## 架构

```
手机 Chrome ──https──> cloudflared ──http(127.0.0.1)──> intercom-server
   │                                                          │
   └────────── WebRTC 音视频（点对点，不过服务器）──────────┘
```

- 服务器只处理「谁在线、谁和谁通话、信令转发、文字/语音片段转发」。
- 语音通话、视频通话走 WebRTC 点对点直连，音视频数据完全不经服务器。
- 所有消息转发完立即释放，服务器**不写任何文件、不入库**；双方刷新即消失。

## 特性

| 能力 | 说明 |
| --- | --- |
| 密钥登录 | 账号由命令行注册，密码 PBKDF2-HMAC-SHA256 加盐存储，失败 8 次锁 2 分钟 |
| 文字消息 | 1:1 定向转发，不落盘 |
| 语音消息 | 按住/点击录制，MediaRecorder 编码为 opus/webm，base64 转发 |
| 视频片段 | 从相册选短视频发送，同样只在两端内存 |
| 语音通话 | WebRTC 点对点，服务端只转 SDP/ICE |
| 视频通话 | 前后摄像头、静音、关摄像头、本地小窗 |
| 访问控制 | 只监听 127.0.0.1，公网 IP 无法直连，且校验 Cloudflare 请求头 |
| 账号安全 | 同账号重复登录踢掉旧连接；来电 45 秒无人接听自动取消 |

## 构建

服务端不依赖 OpenSSL，也不依赖 nlohmann/json：密码学（SHA-256 / HMAC / PBKDF2 / 安全随机数）
和 JSON 都是内置实现，因此在任何装好 C++20 编译器的平台上都能直接编译。

### Windows

```powershell
$env:UCRT_PATH = 'A:\msys64\ucrt64\bin'   # MSYS2 UCRT64（g++ / cmake / ninja）
.\build.ps1
```

产物 `build\intercom-server.exe` 为静态链接，只依赖系统 DLL（无需任何第三方 DLL）。

### Linux（本地 WSL 里交叉/原生构建，**绝不在 VPS 上编译**）

```bash
bash build-linux.sh dist      # 输出 dist/intercom-linux-amd64.gz 等静态二进制
```

产出的静态二进制可直接拷到任意 amd64/arm64 Linux 上运行，目标机不需要编译器、不需要任何运行库。

## 账号存储策略（`~/.intercom/<userid>.json`）

每个账号一个独立文件，默认放在 **用户主目录下的 `.intercom`**：

- Windows：`C:\Users\<你>\.intercom\alice.json`
- Linux：`/root/.intercom/alice.json`

文件里**没有明文密码**，只有服务端加盐后的哈希：

```json
{
  "version": 1,
  "user": "alice",
  "display": "爱丽丝",
  "salt": "484d4df37bea1cf5692f0476adb84510",
  "hash": "5e9f0989650ad4858d6349723d31e2f77e440052955bf36b45255868a5529a2f",
  "iterations": 210000,
  "created_at": 1794314325,
  "last_login": 0,
  "algo": "pbkdf2-hmac-sha256"
}
```

- `salt` 由服务端用安全随机数（16 字节）生成，**每个账号都不同**；
- `hash` = PBKDF2-HMAC-SHA256(密码, salt, 210000 轮, 32 字节)，十六进制；
- 登录时**现场读取该用户的文件**、用文件里的盐重新计算并做恒定时间比较，所以手工改文件立即生效，无需重启；
- 改密码会**重新生成盐**，旧盐不会复用；
- 连续 8 次密码错误锁定 2 分钟（仅内存计数，重启清零）。

## 命令行管理账号

```powershell
# 注册：用户名 密码 [--display 展示名]
intercom-server.exe --add alice 123456 --display 爱丽丝

# 省略密码时从标准输入读取（密码里可以有空格）
intercom-server.exe --add alice

# 改密码：服务端重新加盐并保存，明文不落盘
intercom-server.exe --passwd alice 654321
intercom-server.exe --passwd alice            # 交互输入

# 改用户名（账号文件随之改名，密码与展示名保持不变）
intercom-server.exe --un alice 新名字

# 删除 / 列出
intercom-server.exe --del alice
intercom-server.exe --list        # 每行一个用户名，可直接管道处理
```

`--list` 只输出用户名，一行一个：

```
$ intercom-server.exe --list
甲
乙
张三
```

### 用户名（ID）只能用 ASCII，密码不限

| 项目 | 规则 |
| --- | --- |
| 用户名 / ID | **只能用 ASCII 可见字符**：英文、数字、`_ - . ~ ! @ # $ % ^ & * ( ) + = [ ] { } \\ / : ; " ' , < > ?`；1–64 个字符，不能含空格和汉字 |
| 密码 | **不限**：中文、空格、符号都可以，1–512 字符 |
| 展示名 | 不限，可用中文 |

> 为什么 ID 不能是汉字：命令行参数在不同终端编码下容易对不上（`--del 乙` 会「用户不存在」），
> 用 ASCII 作为主键才可靠。展示名可以随便用中文，界面上显示的是展示名。

```powershell
intercom-server.exe --add alice "密码abc123" --display "张三丰"   # ID 英文，密码中文，展示名中文
intercom-server.exe --add bob "p@ss w#rd!" --display "鲍勃"
intercom-server.exe --add 乙 pass123456                          # 拒绝：ID 不能用汉字
```

用户名当文件名时会做**百分号转义**（ASCII 下其实就是原样），文件里的 `user` 字段保存原始 ID。

账号目录可用 `--accounts <目录>` 指定（默认 `~/.intercom`）；指定相对路径时按可执行文件所在目录解析。

## 运行

Windows：

```powershell
.\start.ps1          # 服务 + cloudflared 隧道一起启动
```

Linux 服务器（推荐）：

```bash
# 本地 WSL 构建后推送
bash build-linux.sh dist
scp dist/intercom-linux-amd64.gz root@服务器:/tmp/
ssh root@服务器 "gunzip -c /tmp/intercom-linux-amd64.gz > /opt/intercom/intercom-server && chmod +x /opt/intercom/intercom-server"

# 服务器上安装为 systemd 服务
bash deploy/deploy.sh /opt/intercom
systemctl status intercom
```

**服务器上不需要安装 g++ / cmake / make 等任何编译工具**，只跑静态二进制。

命令行注册的账号会被运行中的服务自动识别（按文件修改时间热加载），无需重启。

分开跑：

```powershell
.\build\intercom-server.exe --port 8080
.\tools\cloudflared.exe tunnel --url http://127.0.0.1:8080
```

把 cloudflared 输出的 `https://xxx.trycloudflare.com` 发给对方，手机 Chrome 打开、输入账号密码即可。

| 截图 | 说明 |
| --- | --- |
| ![](docs/02-在线用户.png) | 登录后看到在线用户 |
| ![](docs/03-聊天.png) | 文字 / 语音 / 视频消息 |
| ![](docs/04-来电.png) | 来电（震动 + 提示音） |
| ![](docs/05-视频通话.png) | 视频通话中 |

## 命令行参数

| 参数 | 说明 |
| --- | --- |
| `--port <端口>` | 监听端口，默认 8080 |
| `--bind <地址>` | 监听地址，默认 127.0.0.1 |
| `--allow-lan` | 允许局域网直连（默认关闭；外部来源仍会被 403） |
| `--tls` | 本地自签名 HTTPS（一般不需要，隧道已提供 https） |
| `--data <目录>` | 数据目录，默认 exe 同级 `data`（只放账号与可选 ice.json） |
| `--port` 默认 8080 | 对外 https 由 cloudflared 提供，服务本身只跑明文 |
| `--public <目录>` | 前端目录，默认 exe 同级 `public` |

## 可选：自定义 ICE（NAT 穿透更稳）

`data/ice.json`：

```json
{
  "iceServers": [
    { "urls": "stun:stun.cloudflare.com:3478" },
    { "urls": "turn:你的TURN:3478", "username": "user", "credential": "pass" }
  ]
}
```

前端启动时通过 `/api/info` 获取。默认用 Cloudflare 与 Google 的公共 STUN，
同一网络/普通 NAT 下可直连；对称 NAT 需要自备 TURN。

## 源码结构

| 文件 | 作用 |
| --- | --- |
| `src/main.cpp` | HTTP 路由、WebSocket 会话、登录鉴权、通话与消息转发 |
| `src/hub.h/.cpp` | 在线用户与 1:1 房间（纯内存） |
| `src/auth.h/.cpp` | 账号库与 PBKDF2 校验、失败锁定 |
| `src/cert.h/.cpp` | 可选的 OpenSSL 自签名证书 |
| `src/util.*`、`src/json.h` | 编码、时间、文件、JSON 封装 |
| `public/index.html` | 手机端单页前端（HTML + JS） |

## 数据边界

服务器内存中只有：在线用户表、1:1 房间配对、待接来电、登录 token。
消息体转发后立即释放；账号目录 `~/.intercom/` 里每个账号一个文件，只有用户名、展示名、盐和密码哈希。

## 测试

见 [TESTS.md](TESTS.md)。