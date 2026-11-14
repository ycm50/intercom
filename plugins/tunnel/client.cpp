// 隧道客户端：拨边缘 -> 以 HTTP/2 服务端身份通信 -> 控制流上完成 capnp 注册
// -> 把边缘转发来的请求中继到本地 origin。
//
// 本文件是整个插件里唯一"同时握着两边"的地方：上面是边缘（HTTP/2 帧 + 一条
// 控制流），下面是本地 origin（明文 HTTP/1.1 字节流）。中继的难点全在"谁可以
// 阻塞"：HTTP/2 回调里任何阻塞都可能让另一端等不到它需要的数据而死锁，所以
// 回调只做拷贝和记账，真正的推进全部由 run() 的主循环做。
//
// 两条从实现方继承来的约定（改之前先看对方注释）：
//   * h2::Server::write_data_some 返回 0 = 窗口关闭（调用方保留剩余字节），
//     返回 (size_t)-1 = 这条流已经死了（RST 或 END_STREAM 之后再写）。
//   * proxy::OriginStream::write 永不阻塞，socket 不收的排队，由 flush() 补推。
#include "client.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "../../src/json.h"

#include "h2.h"
#include "ingress.h"
#include "proxy.h"
#include "tunnelrpc.h"

namespace ct::client {

namespace {

using Bytes = std::vector<std::uint8_t>;

std::int64_t mono_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

std::string lowercase(std::string s) {
    for (char& c : s) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
    return s;
}

// 插件目标（CMake 的 TUNNEL_SOURCES）不含 src/util.cpp，引用 util::b64_decode 会
// 在 Windows 上变成未解析外部符号。十行自己实现换掉一个链接期隐患。
bool b64_decode(const std::string& in, std::string& out) {
    static const char* kAlphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int rev[256];
    for (int i = 0; i < 256; ++i) rev[i] = -1;
    for (int i = 0; i < 64; ++i) rev[static_cast<unsigned char>(kAlphabet[i])] = i;
    out.clear();
    int buf = 0;
    int bits = 0;
    for (char ch : in) {
        if (ch == '=' || ch == '\n' || ch == '\r' || ch == ' ') continue;
        const int v = rev[static_cast<unsigned char>(ch)];
        if (v < 0) return false;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((buf >> bits) & 0xFF));
        }
    }
    return true;
}

std::string b64_encode(const std::string& in) {
    static const char* kAlphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((in.size() + 2) / 3) * 4);
    std::size_t i = 0;
    for (; i + 2 < in.size(); i += 3) {
        const unsigned v = (static_cast<unsigned char>(in[i]) << 16) |
                           (static_cast<unsigned char>(in[i + 1]) << 8) |
                           static_cast<unsigned char>(in[i + 2]);
        out.push_back(kAlphabet[(v >> 18) & 0x3F]);
        out.push_back(kAlphabet[(v >> 12) & 0x3F]);
        out.push_back(kAlphabet[(v >> 6) & 0x3F]);
        out.push_back(kAlphabet[v & 0x3F]);
    }
    if (i < in.size()) {
        unsigned v = static_cast<unsigned char>(in[i]) << 16;
        const bool two = (i + 1 < in.size());
        if (two) v |= static_cast<unsigned char>(in[i + 1]) << 8;
        out.push_back(kAlphabet[(v >> 18) & 0x3F]);
        out.push_back(kAlphabet[(v >> 12) & 0x3F]);
        if (two) out.push_back(kAlphabet[(v >> 6) & 0x3F]);
    }
    return out;
}

// 令牌里的隧道 id 是 uuid 文本，注册要原始 16 字节。
Bytes uuid_to_bytes(const std::string& s) {
    Bytes out;
    unsigned hi = 0;
    int nib = 0;
    for (char c : s) {
        int v = -1;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        if (v < 0) continue;
        hi = (hi << 4) | static_cast<unsigned>(v);
        if (++nib == 2) {
            out.push_back(static_cast<std::uint8_t>(hi));
            hi = 0;
            nib = 0;
        }
    }
    return out;
}

// ---- cloudflared 的 HTTP/1 头序列化（connection/header.go）与反向 ------------
//
// 用户头不能当真正的 h2 头透传（HTTP/1 的取值不满足 h2 的字段规则），边缘把它
// 们塞进一个头里：b64(name):b64(value);b64(name):b64(value)。
// WebSocket 握手那几个是例外，必须走真 h2 头，否则升级永远不会完成。
std::string b64_raw_encode(const std::string& in) { return b64_encode(in); }

bool is_websocket_client_header(const std::string& name) {
    return name == "sec-websocket-accept" || name == "connection" || name == "upgrade" ||
           // Xray 在 101 上回显 Sec-WebSocket-Protocol 来确认早发数据；
           // 丢了它客户端会以为自己发的早期数据被忽略。
           name == "sec-websocket-protocol";
}

std::string b64_raw_decode(const std::string& in) {
    std::string out;
    b64_decode(in, out);
    return out;
}

// "b64(name):b64(value);..." -> 明文头对。解不开的段跳过：
// 这是外部数据，不能因为一个畸形字段就丢掉整条请求。
void deserialize_user_headers(const std::string& in,
                              std::vector<std::pair<std::string, std::string>>& out) {
    std::size_t start = 0;
    while (start <= in.size()) {
        const std::size_t semi = in.find(';', start);
        const std::string pair =
            in.substr(start, semi == std::string::npos ? std::string::npos : semi - start);
        if (!pair.empty()) {
            const std::size_t colon = pair.find(':');
            if (colon != std::string::npos) {
                out.emplace_back(b64_raw_decode(pair.substr(0, colon)),
                                 b64_raw_decode(pair.substr(colon + 1)));
            }
        }
        if (semi == std::string::npos) break;
        start = semi + 1;
    }
}

std::string serialize_user_headers(
    const std::vector<std::pair<std::string, std::string>>& headers) {
    std::string out;
    for (const auto& kv : headers) {
        if (!out.empty()) out.push_back(';');
        out += b64_raw_encode(kv.first);
        out.push_back(':');
        out += b64_raw_encode(kv.second);
    }
    return out;
}

// RFC 6455 5.5.1：close 帧是 opcode 0x8 的空载荷。对端走了却不发这个，
// origin 会一直把 TCP 会话挂到自己的空闲超时。
void send_ws_close(const std::shared_ptr<proxy::OriginStream>& origin) {
    if (!origin || !origin->valid()) return;
    const std::uint8_t frame[2] = {0x88, 0x00};
    origin->write(frame, sizeof(frame));
    origin->flush();
}

// 一条被边缘代理的流全部状态。
struct StreamCtx {
    std::string method;
    std::string path;
    bool isControl = false;
    bool isConfig = false;
    std::string configBody;

    // END_STREAM 已到。配置更新是 HEADERS + DATA + END_STREAM，只在 HEADERS
    // 上就确认会把 body 丢掉，所以必须等 endSeen 才回 ack。
    bool endSeen = false;
    bool responded = false;         // origin 的响应头已经转给边缘
    bool streamedResponse = false;  // origin 没给 content-length：长连接，不能半关
    bool failed = false;            // origin 连不上
    bool isWebsocket = false;
    std::string reqPath;

    std::uint64_t upBytes = 0;    // origin -> 边缘
    std::uint64_t downBytes = 0;  // 边缘 -> origin

    std::shared_ptr<proxy::OriginStream> origin;

    // 边缘送来的字节，等着交给 origin。回调里只追加，主循环搬。
    Bytes toOrigin;
    std::size_t toOriginOff = 0;
    bool endFromEdge = false;   // 边缘发完请求了
    bool resetByEdge = false;    // 边缘 RST 了这条流
    bool edgeDone = false;       // websocket 对端走了

    // origin 产出的字节，边缘的流控窗口还没接受。留在这里而不是阻塞在写调用上，
    // 否则读侧停摆、origin 也就停摆（它自己的写会堵住）。
    Bytes toEdge;
    std::size_t toEdgeOff = 0;
    bool originDone = false;
    bool endSent = false;    // 已经给这条流发过 END_STREAM
};

}  // namespace

bool Client::parse_token(const std::string& token, Config& out, std::string& error) {
    std::string json;
    if (!b64_decode(token, json) || json.empty()) {
        error = "令牌不是合法的 base64";
        return false;
    }
    jsonx::Json doc;
    if (!jsonx::parse(json, doc) || !doc.is_object()) {
        error = "令牌解出来不是 JSON 对象";
        return false;
    }
    out.accountTag = jsonx::str(doc, "a");
    out.tunnelId = jsonx::str(doc, "t");
    const std::string secretB64 = jsonx::str(doc, "s");
    std::string secret;
    if (!b64_decode(secretB64, secret)) {
        error = "令牌里的 s 字段不是合法 base64";
        return false;
    }
    out.tunnelSecret = secret;
    if (out.accountTag.empty() || out.tunnelId.empty() || out.tunnelSecret.empty()) {
        error = "令牌缺少 a/t/s 字段（也许贴的是隧道 ID 而不是连接令牌）";
        return false;
    }
    return true;
}

void Client::abort_connection() {
    std::lock_guard<std::mutex> lk(mutex_);
    if (live_ != nullptr) live_->abort();
}

void Client::stop() {
    stopping_.store(true);
    abort_connection();
}

namespace {

// run() 的一次完整会话。Client 本身只留停止标志与计数，状态全在这里，
// 这样一次断线重连不会把上一轮的半截状态带过去。
class Session {
public:
    Session(const Config& cfg, Status& status, std::function<void(const std::string&)> log,
            std::function<void(const Status&)> onStatus, std::atomic<bool>& stopping)
        : cfg_(cfg), status_(status), log_(std::move(log)), onStatus_(std::move(onStatus)),
          stopping_(stopping) {}

    bool run(const std::function<void(h2::Server*)>& publishLive,
             const std::function<void()>& clearLive) {
        auto L = [&](const std::string& s) {
            if (log_) log_(s);
        };

        status_.connected = false;
        status_.registered = false;
        status_.error.clear();
        status_.uuid = cfg_.tunnelId;

        h2::Server::Callbacks cb;
        cb.on_request = [this](const h2::Server::Request& r) { onRequest(r); };
        cb.on_data = [this](std::uint32_t id, const std::uint8_t* d, std::size_t n) {
            onData(id, d, n);
        };
        cb.on_end = [this](std::uint32_t id) { onEnd(id); };
        cb.on_reset = [this](std::uint32_t id) { onReset(id); };
        cb.on_error = [L](const std::string& e) { L("边缘连接出错：" + e); };

        std::shared_ptr<h2::Server> holder(h2::Server::create(cb));
        srv_ = holder.get();
        // 先发布再拨号：stop() 可能正好落在连接/握手期间，那时要能 shutdown
        // 这个 socket，而不是等满 connectTimeoutMs。
        publishLive(srv_);

        std::string err;
        if (!srv_->connect(cfg_.edgeHost, cfg_.edgePort, cfg_.edgeSni, cfg_.connectTimeoutMs, err)) {
            status_.error = err;
            srv_ = nullptr;
            clearLive();
            return false;
        }
        if (!srv_->start_http2(cfg_.connectTimeoutMs, err)) {
            status_.error = err;
            srv_ = nullptr;
            clearLive();
            return false;
        }
        status_.connected = true;
        publish();
        L("已连上边缘 " + cfg_.edgeHost + ":" + std::to_string(cfg_.edgePort));

        // ---- 主循环 ---------------------------------------------------------
        std::int64_t lastPublish = mono_ms();
        while (!stopping_.load()) {
            // 有字节等着推、或某条 origin 还在建连/等响应头时不能等满 idlePollMs：
            // 后者是同一个进程里的 HTTP 服务，把它饿着等只会让下载永远完不成。
            bool backlog = false;
            bool pendingOrigin = false;
            bool activeStream = false;
            for (const auto& kv : streams_) {
                const StreamCtx& s = kv.second;
                if (!s.origin || s.isControl || s.isConfig) continue;
                activeStream = true;
                if (!s.responded) pendingOrigin = true;
                if (s.toEdgeOff < s.toEdge.size() || s.toOriginOff < s.toOrigin.size() ||
                    s.origin->has_pending_output()) {
                    backlog = true;
                    break;
                }
            }
            // 窗口关着时"有字节没发出去"不算待办：否则会 poll(0) 空转烧满一个核，
            // 而能解除这个状态的只有对端的 WINDOW_UPDATE。
            if (backlog) {
                for (const auto& kv : streams_) {
                    const StreamCtx& s = kv.second;
                    if (s.toEdgeOff < s.toEdge.size() && !srv_->send_credit_available(kv.first)) {
                        backlog = false;
                        break;
                    }
                }
            }

            int wait = cfg_.idlePollMs;
            if (backlog) wait = 0;
            else if (pendingOrigin) wait = std::min(cfg_.activePollMs + 1, cfg_.idlePollMs);
            else if (activeStream) wait = cfg_.activePollMs;

            if (!srv_->poll(wait)) {
                if (stopping_.load()) break;
                status_.error = "边缘连接断开";
                publish();
                break;
            }
            pump();

            // 控制流握手：边缘一开好这条流就 bootstrap + 注册。
            if (ctrlStream_ != 0 && needHandshake_) {
                needHandshake_ = false;
                if (!handshake()) {
                    publish();
                    break;
                }
            }

            // 已服务计数只在状态回调里刷，但主程序可能靠它显示进度：
            // 每秒最多推一次，避免每个请求都抢一次锁。
            const std::int64_t now = mono_ms();
            if (now - lastPublish >= 1000 && activeStream) {
                lastPublish = now;
                publish();
            }
        }

        srv_->close();
        srv_ = nullptr;
        clearLive();
        return status_.registered;
    }

private:
    void publish() {
        if (onStatus_) onStatus_(status_);
    }

    void onRequest(const h2::Server::Request& r) {
        StreamCtx& s = streams_[r.streamId];
        s.method = r.method;
        s.path = r.path;
        s.reqPath = r.path;

        auto it = r.headers.find(h2::kUpgradeHeader);
        if (it != r.headers.end() && it->second == h2::kUpgradeControlStream) {
            s.isControl = true;
            ctrlStream_ = r.streamId;
            needHandshake_ = true;
            return;
        }
        // 边缘用自己的流推 ingress 配置：它根本不到 origin，只要回个 ack。
        if (it != r.headers.end() && it->second == h2::kUpgradeConfiguration) {
            s.isConfig = true;
            return;
        }

        // 被代理的请求：立刻开始拨 origin 并转发请求头。
        // 身体随 DATA 到达再送，长连接协议（WebSocket）因此不用缓冲。
        std::vector<std::pair<std::string, std::string>> hdrs;
        bool isWebsocket = false;
        std::string wsKey;
        for (const auto& kv : r.headers) {
            const std::string& k = kv.first;
            // 边缘把公网域名放在 :authority，且不发自己的 Host。把结构体伪头
            // 一律跳过（对 :method/:path 是对的）会顺手丢掉它，于是 origin 只
            // 看到 OriginStream 自己编的 127.0.0.1:8080 —— 任何按公网域名判断
            // 同源的地方都会答错。所以这一条要在跳过之前处理。
            if (k == ":authority" && !kv.second.empty()) {
                hdrs.emplace_back("Host", kv.second);
                continue;
            }
            if (k.empty() || k[0] == ':') continue;
            if (k == h2::kUpgradeHeader) {
                if (kv.second == "websocket") isWebsocket = true;
                continue;
            }
            if (k == "sec-websocket-key") wsKey = kv.second;
            // 原始 HTTP/1 头被 base64 序列化塞在这一个头里，解出来 origin 才看得到。
            if (k == "cf-cloudflared-request-headers") {
                deserialize_user_headers(kv.second, hdrs);
                continue;
            }
            // 边缘自己的记账头，不该让 origin 看到。
            if (k == "cf-connecting-ip" || k == "cf-ray" || k == "cf-visitor" ||
                k == "cf-ipcountry" || k == "cdn-loop" || k == "cf-cloudflared-response-meta") {
                continue;
            }
            hdrs.emplace_back(k, kv.second);
        }
        // 边缘用 cf-cloudflared-proxy-connection-upgrade: websocket 标记升级，
        // 且不转发 sec-websocket-key。有 key 时接受它（本地联调/旧边缘会发），
        // 但绝不自己编一个：origin 不能对一个客户端从没发过的 key 做摘要。
        if (!wsKey.empty()) {
            isWebsocket = true;
            hdrs.emplace_back("Sec-WebSocket-Key", wsKey);
        }
        if (isWebsocket) {
            hdrs.emplace_back("Upgrade", "websocket");
            hdrs.emplace_back("Connection", "Upgrade");
            hdrs.emplace_back("Sec-WebSocket-Version", "13");
        }

        auto stream = std::make_shared<proxy::OriginStream>();
        s.origin = stream;
        s.isWebsocket = isWebsocket;
        std::string oerr;
        // 只"发起"。响应头由 pump() 收：在这个回调里等响应会死锁带 body 的请求
        // —— 边缘的 DATA 要等回调返回后才排队，origin 于是永远等不到身体。
        if (!stream->begin(cfg_.originHost, cfg_.originPort, r.method, r.path, hdrs,
                           cfg_.connectTimeoutMs, oerr)) {
            log_("连 origin 失败：" + oerr);
            s.failed = true;
        }
    }

    void onData(std::uint32_t id, const std::uint8_t* d, std::size_t n) {
        auto it = streams_.find(id);
        if (it == streams_.end()) return;
        StreamCtx& s = it->second;
        if (s.isControl) {
            ctrlRx_.insert(ctrlRx_.end(), d, d + n);
            return;
        }
        if (s.isConfig) {
            s.configBody.append(reinterpret_cast<const char*>(d), n);
            return;
        }
        // 只排队。主循环负责搬给 origin，所以这个回调不会在任何一边阻塞。
        if (s.origin && n) s.toOrigin.insert(s.toOrigin.end(), d, d + n);
    }

    void onEnd(std::uint32_t id) {
        auto it = streams_.find(id);
        if (it == streams_.end()) return;
        StreamCtx& s = it->second;
        // 配置更新是 HEADERS+DATA+END_STREAM 且没有 origin：记下结束，
        // 等 body 齐了再 ack（在 HEADERS 上 ack 会把 body 丢掉）。
        if (s.isConfig) {
            s.endSeen = true;
            return;
        }
        if (s.isControl || !s.origin) return;
        if (s.isWebsocket) {
            // 升级请求是"没有 body 的 GET"，END_STREAM 只表示这一点。
            // 真正动作要等 101 转出去之后（见 pump），否则每个新 WebSocket
            // 都会在打开的瞬间被关掉。
            s.endFromEdge = false;
            s.edgeDone = true;
            return;
        }
        // 延后到队列排空：半关发生在字节到达之前会截断请求。
        s.endFromEdge = true;
    }

    void onReset(std::uint32_t id) {
        auto it = streams_.find(id);
        if (it == streams_.end()) return;
        // 绝不在回调里 erase：它可能从 pump 的写路径里被重新进来，
        // 那样会让 pump 手里的迭代器失效。置标志，由 pump 清。
        it->second.resetByEdge = true;
    }

    bool handshake() {
        // 控制流先回 200，再在上面放 capnp RPC。
        if (!srv_->write_headers(ctrlStream_, "200",
                                 {{"content-type", "application/octet-stream"}}, false)) {
            status_.error = "控制流回 200 失败";
            return false;
        }
        const auto boot = rpc::Stream::encode_bootstrap(1);
        if (!srv_->write_data(ctrlStream_, boot.data(), boot.size(), false)) {
            status_.error = "发送 bootstrap 失败";
            return false;
        }
        if (!waitForReturn(1, cfg_.registerTimeoutMs, "bootstrap")) return false;
        return sendRegister();
    }

    enum class ReturnOutcome { Ok, Rejected, Malformed };

    // 判断一条 Return 是成功还是失败。
    //
    // 为什么不能直接用 rpc::return_payload：它要求 results.content 是个结构体，
    // 而 bootstrap 的 content 是能力指针。用它会把成功的 bootstrap 判成失败
    // （实测：隧道永远卡在 bootstrap，公网 530）。
    //
    // 这里只做真正需要的那一层判断：Return 的联合体是不是 results 分支。
    // exception/canceled 等分支一定不是成功，而 results 分支的成功与否由
    // 调用方各自的语义决定（bootstrap 只看"拿到了能力"，注册只看"没抛异常"）。
    ReturnOutcome classifyReturn(const std::uint8_t* msg, std::size_t len) {
        std::size_t off = 0;
        std::uint16_t dw = 0;
        std::uint16_t pc = 0;
        std::string err;
        // return_payload 失败的原因串里，"不是 results 分支"是明确的拒绝；
        // 其余（段表/结构定位失败）算畸形。这个字符串匹配不好看，但比起给
        // rpc 层再加一个枚举更不容易出错 —— 那边的错误文案是集中定义的。
        const bool ok = rpc::return_payload(msg, len, off, dw, pc, err);
        if (ok) return ReturnOutcome::Ok;
        if (err.find("不是 results") != std::string::npos) return ReturnOutcome::Rejected;
        if (err.find("能力指针") != std::string::npos) return ReturnOutcome::Ok;  // bootstrap
        return ReturnOutcome::Malformed;
    }

    // 等一条 Return。控制流的消息是 capnp 原样连排的（没有长度前缀），
    // 用段表自描边界来切。
    bool waitForReturn(std::uint32_t wantId, int timeoutMs, const char* what) {
        const std::int64_t deadline = mono_ms() + timeoutMs;
        std::size_t scanned = ctrlConsumed_;
        while (mono_ms() < deadline) {
            if (stopping_.load()) return false;   // 由 run() 传入的引用，见 run 的签名
            if (!srv_->poll(std::min(cfg_.idlePollMs, 50))) {
                status_.error = std::string("等 ") + what + " 时边缘断开了";
                return false;
            }
            pump();
            for (const auto& span : splitMessages(ctrlRx_, scanned)) {
                if (span.first < scanned) continue;
                std::uint16_t kind = 0;
                std::uint32_t id = 0;
                if (rpc::Stream::peek(ctrlRx_.data() + span.first, span.second, kind, id) &&
                    kind == rpc::kReturn && id == wantId) {
                    // 【必须校验】"收到一条 id 匹配的 Return"不等于"调用成功"。
                    // capnp 把失败也编码成 Return（联合体走 exception 分支），
                    // 只看 kind/id 会把「边缘拒绝了这次注册」当成注册成功，
                    // 于是本地显示已连接、公网却一直 530 —— 一个非常误导的状态。
                    // 只看"是 results 分支吗"：exception/canceled 显然是失败，
                    // 而 results.content 的形态随调用不同 —— bootstrap 回的是
                    // 一个能力指针，registerConnection 回的是结构体。用
                    // return_payload 那一套（要求 content 是结构体）会把成功的
                    // bootstrap 误判成失败。
                    ReturnOutcome outcome = classifyReturn(ctrlRx_.data() + span.first,
                                                           span.second);
                    if (outcome == ReturnOutcome::Rejected) {
                        status_.error = std::string(what) + " 被边缘拒绝（exception 分支）";
                        ctrlConsumed_ = span.first + span.second;
                        return false;
                    }
                    if (outcome == ReturnOutcome::Malformed) {
                        status_.error = std::string(what) + " 的 Return 解析失败";
                        ctrlConsumed_ = span.first + span.second;
                        return false;
                    }
                    ctrlConsumed_ = span.first + span.second;
                    return true;
                }
                scanned = span.first + span.second;
            }
            ctrlConsumed_ = scanned;
        }
        status_.error = std::string("等 ") + what + " 超时";
        return false;
    }

    bool sendRegister() {
        const Bytes uuid = uuid_to_bytes(cfg_.tunnelId);
        const std::string version = "2026.10.6";
        const std::string arch = "linux_amd64";
        const auto call = rpc::Stream::encode_call(
            2, /* importId：bootstrap 的 Return 里那张能力表的 0 号 */
            1, rpc::kRegistrationServerId, rpc::kMethodRegisterConnection,
            [&](capnp::Message& m) {
                // RegistrationServer.registerConnection 的参数结构布局：
                //   params：u8 字段（连接形态）
                //   auth：accountTag(text) + tunnelSecret(data)
                //   tunnelId：data
                //   client：id(data) + version(text) + arch(text)
                //   options：client 指针 + origin ip data
                auto params = m.alloc_struct(2, 3);
                params.set_u8(0, 0);  // 0 = 新的注册
                auto auth = m.alloc_struct(0, 2);
                auth.set_text(0, cfg_.accountTag);
                auth.set_data(1, cfg_.tunnelSecret.data(), cfg_.tunnelSecret.size());
                params.set_struct(0, auth);
                params.set_data(1, uuid.data(), uuid.size());
                auto clientInfo = m.alloc_struct(0, 4);
                clientInfo.set_data(0, uuid.data(), uuid.size());
                clientInfo.set_text(2, version);
                clientInfo.set_text(3, arch);
                auto opts = m.alloc_struct(1, 2);
                opts.set_struct(0, clientInfo);
                opts.set_data(1, cfg_.originHost.data(), cfg_.originHost.size());
                params.set_struct(2, opts);
                return params;
            });
        if (!srv_->write_data(ctrlStream_, call.data(), call.size(), false)) {
            status_.error = "发送 registerConnection 失败";
            return false;
        }
        if (!waitForReturn(2, cfg_.registerTimeoutMs, "registerConnection")) return false;
        status_.registered = true;
        publish();
        log_("已向边缘注册成功（隧道 " + cfg_.tunnelId + "）");
        return true;
    }

    // capnp 消息在流上是原样连排的：靠自己开头的段表自描边界。
    std::vector<std::pair<std::size_t, std::size_t>> splitMessages(const Bytes& b,
                                                                   std::size_t from) {
        std::vector<std::pair<std::size_t, std::size_t>> out;
        std::size_t off = from;
        while (off + 4 <= b.size()) {
            const std::uint32_t segCount = static_cast<std::uint32_t>(b[off]) |
                                           (static_cast<std::uint32_t>(b[off + 1]) << 8) |
                                           (static_cast<std::uint32_t>(b[off + 2]) << 16) |
                                           (static_cast<std::uint32_t>(b[off + 3]) << 24);
            const std::uint64_t segments = static_cast<std::uint64_t>(segCount) + 1;
            if (segments > 512) break;  // 不像段表头：放弃，等对端发正经东西
            const std::size_t headerBytes = 4 + 4 * static_cast<std::size_t>(segments);
            const std::size_t padded = (headerBytes + 7) & ~static_cast<std::size_t>(7);
            if (off + padded > b.size()) break;
            std::size_t bodyBytes = 0;
            bool complete = true;
            for (std::uint64_t s = 0; s < segments; ++s) {
                const std::size_t at = off + 4 + 4 * static_cast<std::size_t>(s);
                const std::uint32_t words = static_cast<std::uint32_t>(b[at]) |
                                            (static_cast<std::uint32_t>(b[at + 1]) << 8) |
                                            (static_cast<std::uint32_t>(b[at + 2]) << 16) |
                                            (static_cast<std::uint32_t>(b[at + 3]) << 24);
                bodyBytes += static_cast<std::size_t>(words) * 8;
                if (bodyBytes > 64u * 1024 * 1024) {
                    complete = false;
                    break;
                }
            }
            if (!complete) break;
            const std::size_t len = padded + bodyBytes;
            if (off + len > b.size()) break;  // 等剩下的
            out.emplace_back(off, len);
            off += len;
        }
        return out;
    }

    void onResponseHeaders(std::uint32_t id, const std::string& head, bool isWebsocket) {
        auto it = streams_.find(id);
        if (it == streams_.end()) return;
        StreamCtx& s = it->second;

        int statusCode = 0;
        std::vector<std::pair<std::string, std::string>> userHeaders;
        bool haveLength = false;
        std::string contentLength;
        {
            std::size_t pos = 0;
            const std::size_t lineEnd = head.find("\r\n");
            const std::string statusLine = head.substr(0, lineEnd);
            {
                std::size_t sp = statusLine.find(' ');
                if (sp != std::string::npos) {
                    const std::size_t sp2 = statusLine.find(' ', sp + 1);
                    statusCode = std::atoi(statusLine.substr(sp + 1, sp2 - sp - 1).c_str());
                }
            }
            pos = (lineEnd == std::string::npos) ? head.size() : lineEnd + 2;
            while (pos < head.size()) {
                const std::size_t e = head.find("\r\n", pos);
                const std::string line =
                    head.substr(pos, e == std::string::npos ? std::string::npos : e - pos);
                if (line.empty()) break;
                pos = (e == std::string::npos) ? head.size() : e + 2;
                const std::size_t colon = line.find(':');
                if (colon == std::string::npos) continue;
                const std::string name = line.substr(0, colon);
                std::string value = line.substr(colon + 1);
                while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
                    value.erase(value.begin());
                while (!value.empty() && (value.back() == ' ' || value.back() == '\t'))
                    value.pop_back();
                const std::string ln = lowercase(name);
                if (ln == "content-length") {
                    contentLength = value;
                    haveLength = true;
                }
                // 逐跳字段（RFC 7230 6.1）不能转发：边缘会用它们重建 HTTP/1 头，
                // 而带 transfer-encoding 的 h2 流是协议错误 —— 边缘会 RST_STREAM，
                // 眼球那边什么也收不到。
                if (ln == "transfer-encoding" || ln == "proxy-connection" || ln == "connection" ||
                    ln == "keep-alive")
                    continue;
                userHeaders.emplace_back(name, value);
            }
        }
        if (statusCode == 0) statusCode = 502;
        // 1xx 是过渡响应（curl 的 Expect 会带来 100 Continue）。h2 在这条流上
        // 没法把它当独立消息表达，客户端还要继续等真正的响应；真发出去会让
        // 眼球收到"100 Continue"当成终态，body 再也不会被发完。
        // 101 例外，它必须走：那是 WebSocket 升级结果（下面改写为 200）。
        if (statusCode > 100 && statusCode < 200 && statusCode != 101) return;

        // HTTP/2 取消了 101，边缘靠头判断升级。
        const std::string statusOut = (statusCode == 101) ? "200" : std::to_string(statusCode);

        std::vector<std::pair<std::string, std::string>> h2hdrs;
        s.streamedResponse = !haveLength;
        if (haveLength) h2hdrs.emplace_back("content-length", contentLength);
        for (const auto& kv : userHeaders) {
            const std::string ln = lowercase(kv.first);
            if (is_websocket_client_header(ln)) h2hdrs.emplace_back(ln, kv.second);
        }
        h2hdrs.emplace_back("cf-cloudflared-response-headers", serialize_user_headers(userHeaders));
        h2hdrs.emplace_back("cf-cloudflared-response-meta",
                            "{\"src\":\"origin\",\"flow_rate_limited\":false}");

        if (!srv_->write_headers(id, statusOut, h2hdrs, false)) return;
        s.responded = true;
        ++status_.requestsServed;
        requestsAdd(1);
        (void)isWebsocket;
    }

    // 主循环的推进器：把两边缓存的字节搬过去。每轮都跑，长连接因此两个方向
    // 都能及时响应。
    void pump() {
        std::vector<std::uint32_t> dead;
        std::vector<std::uint32_t> ids;
        ids.reserve(streams_.size());
        for (const auto& kv : streams_) ids.push_back(kv.first);
        // 先按流处理；写边缘可能重入我们的回调（往 streams_ 里插新流），
        // 所以不能持着 map 的引用迭代。
        for (std::uint32_t id : ids) {
            auto found = streams_.find(id);
            if (found == streams_.end()) continue;
            StreamCtx& s = found->second;

            if (s.isConfig) {
                if (!s.endSeen || s.responded) {
                    if (s.responded) dead.push_back(id);
                    continue;
                }
                s.responded = true;
                const std::vector<std::string> hosts = ingress::hostnames(s.configBody);
                const int version = ingress::version(s.configBody);
                if (!hosts.empty()) {
                    status_.hostnames = hosts;
                    std::string joined;
                    for (std::size_t i = 0; i < hosts.size(); ++i) {
                        if (i) joined += ", ";
                        joined += hosts[i];
                    }
                    log_("边缘推送的 ingress 域名：" + joined);
                    publish();
                }
                const std::string ack = ingress::update_ack(version);
                srv_->write_headers(id, "200",
                                    {{"content-type", "application/json"},
                                     {"content-length", std::to_string(ack.size())}},
                                    false);
                srv_->write_data(id, reinterpret_cast<const std::uint8_t*>(ack.data()), ack.size(),
                                 true);
                dead.push_back(id);
                continue;
            }
            // 控制流：数据由 onData 收进 ctrlRx_，这里不做搬运。
            if (s.isControl) continue;
            if (s.resetByEdge) {
                if (s.origin) s.origin->close();
                dead.push_back(id);
                continue;
            }
            if (!s.origin) continue;
            if (s.failed) {
                static const char kMsg[] = "origin unreachable";
                srv_->write_headers(id, "502", {{"content-type", "text/plain"}}, false);
                srv_->write_data(id, reinterpret_cast<const std::uint8_t*>(kMsg), sizeof kMsg - 1,
                                 true);
                dead.push_back(id);
                continue;
            }

            // 推进 origin 状态机（建连 -> 发请求头 -> 收响应头）。
            // Pending 不能跳过：带 body 的请求只有 body 送完才会往下走。
            bool headReady = s.responded;
            if (!headReady) {
                const proxy::OriginStream::Step step = s.origin->step();
                if (step == proxy::OriginStream::Step::Failed) {
                    log_("origin 失败（" + s.reqPath + "）：" + s.origin->error_text());
                    s.failed = true;
                    static const char kMsg[] = "origin unreachable";
                    srv_->write_headers(id, "502", {{"content-type", "text/plain"}}, false);
                    srv_->write_data(id, reinterpret_cast<const std::uint8_t*>(kMsg),
                                     sizeof kMsg - 1, true);
                    dead.push_back(id);
                    continue;
                }
                if (step == proxy::OriginStream::Step::Ready) {
                    onResponseHeaders(id, s.origin->response_head(), s.isWebsocket);
                    headReady = s.responded;
                }
            }

            // 边缘送来的字节搬给 origin。write 不阻塞，收不下的排队。
            if (s.toOriginOff < s.toOrigin.size()) {
                const std::size_t left = s.toOrigin.size() - s.toOriginOff;
                if (!s.origin->write(s.toOrigin.data() + s.toOriginOff, left)) {
                    log_("写 origin 失败，流 " + std::to_string(id));
                    srv_->write_rst_stream(id, 0x2 /* INTERNAL_ERROR */);
                    s.origin->close();
                    dead.push_back(id);
                    continue;
                }
                s.downBytes += left;
                s.toOriginOff += left;
                // 只丢掉刚写出去的那一段：write 可能重入回调，重新进来的字节
                // 会追加到同一个 vector 上，整体清空会把它们一起丢掉。
                if (s.toOriginOff >= s.toOrigin.size()) {
                    s.toOrigin.clear();
                    s.toOriginOff = 0;
                } else if (s.toOriginOff > 256u * 1024u && s.toOriginOff * 2 >= s.toOrigin.size()) {
                    s.toOrigin.erase(s.toOrigin.begin(),
                                     s.toOrigin.begin() + static_cast<std::ptrdiff_t>(s.toOriginOff));
                    s.toOriginOff = 0;
                }
            }
            // socket 之前没收下的尾巴补推一次。
            if (s.origin->has_pending_output() && !s.origin->flush()) {
                log_("origin flush 失败，流 " + std::to_string(id));
                s.origin->close();
                dead.push_back(id);
                continue;
            }

            if (s.edgeDone && s.isWebsocket && s.responded) {
                // 眼球挂了：正经地告诉 origin，并让下游剩余字节排空。
                // 只在 101 已经转出去之后才做（见 onEnd 的说明）。
                send_ws_close(s.origin);
                s.edgeDone = false;
                s.originDone = true;
            }
            // 没有 content-length 的响应是活流（SSE 一类）：请求侧结束不意味着
            // 响应也结束。在这里半关会让 origin 的 chunked 写看到 EOF 直接收流，
            // 边缘转发到的 HEADERS 后面一个字节都没有。
            if (s.streamedResponse && s.endFromEdge) s.endFromEdge = false;
            if (s.endFromEdge && s.origin->request_sent() && !s.origin->has_pending_output()) {
                // 边缘送来的都到 origin 了，可以关写半端而继续读它的回复。
                // 必须等队列排空，否则半关会截断请求；request_sent() 同理 ——
                // 请求头本身是 step() 异步写的，普通 GET 的 END_STREAM 会和
                // HEADERS 同时到达，不检查就会把头截成两半。
                s.origin->shutdown_write();
                s.endFromEdge = false;
            }

            // origin 产出 -> 边缘。只接受当前窗口允许的量；阻塞在这里会让下面
            // 的读停摆，而 origin 自己的写也会因此堵住。
            if (!s.endSent && s.toEdgeOff < s.toEdge.size()) {
                const std::size_t left = s.toEdge.size() - s.toEdgeOff;
                const bool isLast = s.originDone && left <= 16384;
                const std::size_t took = srv_->write_data_some(id, s.toEdge.data() + s.toEdgeOff,
                                                               left, isLast);
                if (took == static_cast<std::size_t>(-1)) {
                    log_("写边缘失败，流 " + std::to_string(id));
                    s.origin->close();
                    dead.push_back(id);
                    continue;
                }
                s.toEdgeOff += took;
                s.upBytes += took;
                // write_data_some 接受最后一批时已经带了 END_STREAM，
                // 记下来，否则下面的收尾会再发一个空 END_STREAM —— 边缘判
                // PROTOCOL_ERROR 并拆整条连接。
                if (isLast && took == left) s.endSent = true;
                if (s.toEdgeOff >= s.toEdge.size()) {
                    s.toEdge.clear();
                    s.toEdgeOff = 0;
                } else if (s.toEdgeOff > 256u * 1024u && s.toEdgeOff * 2 >= s.toEdge.size()) {
                    s.toEdge.erase(s.toEdge.begin(),
                                   s.toEdge.begin() + static_cast<std::ptrdiff_t>(s.toEdgeOff));
                    s.toEdgeOff = 0;
                }
            }

            // 读 origin。预读量按边缘的流控额度算，不是固定常量：
            // 窗口关着时继续读只会在内存里堆一批永远发不出去的字节。
            if (headReady) {
                constexpr std::size_t kSlack = 64u * 1024u;
                constexpr std::size_t kCeiling = 256u * 1024u;
                std::size_t readAhead = srv_->send_credit_bytes(id) + kSlack;
                if (readAhead > kCeiling) readAhead = kCeiling;

                std::uint8_t buf[65536];
                bool gotData = false;
                // 每轮都重查上限：回环 origin 会一直吐 16KB 直到排空，
                // 只查一次会让 toEdge 涨到几 MB，每次搬移都是 O(n) memmove。
                while ((s.toEdge.size() - s.toEdgeOff) < readAhead) {
                    const int n = s.origin->read_some(buf, sizeof(buf), 0);
                    if (n > 0) {
                        s.toEdge.insert(s.toEdge.end(), buf, buf + n);
                        gotData = true;
                        continue;
                    }
                    if (n == 0) break;  // 暂时没有更多
                    // n < 0：origin 关了。先把队列推完再发 END_STREAM ——
                    // 在这里丢队列会把响应正好在窗口重开的位置截断。
                    s.originDone = true;
                    s.origin->close();
                    break;
                }
                // 立刻推一次：等下一轮要多花一整个 poll 间隔，小响应会变成
                // 明显的停顿。但绝不能在响应 HEADERS 之前发 DATA（协议禁止）。
                if (gotData && s.responded && !s.endSent) {
                    const std::size_t left = s.toEdge.size() - s.toEdgeOff;
                    const bool isLast = s.originDone && left <= 16384;
                    const std::size_t took =
                        srv_->write_data_some(id, s.toEdge.data() + s.toEdgeOff, left, isLast);
                    if (took == static_cast<std::size_t>(-1)) {
                        s.origin->close();
                        dead.push_back(id);
                        continue;
                    }
                    s.toEdgeOff += took;
                    s.upBytes += took;
                    if (isLast && took == left) s.endSent = true;
                    if (s.toEdgeOff >= s.toEdge.size()) {
                        s.toEdge.clear();
                        s.toEdgeOff = 0;
                    }
                }
            }

            // origin 结束了且字节都发出去了：收掉这条流，必要时补一个 END_STREAM。
            if (s.originDone && s.toEdgeOff >= s.toEdge.size()) {
                if (!s.endSent) {
                    s.endSent = true;
                    srv_->write_data_some(id, nullptr, 0, true);
                }
                dead.push_back(id);
            }
        }
        for (std::uint32_t id : dead) streams_.erase(id);
    }

    void requestsAdd(std::uint64_t delta) {
        if (addRequests_) addRequests_(delta);
    }

public:
    void set_request_adder(const std::function<void(std::uint64_t)>& fn) {
        addRequests_ = std::move(fn);
    }

private:
    const Config& cfg_;
    Status& status_;
    std::function<void(const std::string&)> log_;
    std::function<void(const Status&)> onStatus_;
    std::function<void(std::uint64_t)> addRequests_;
    std::atomic<bool>& stopping_;   // Client::stopping_ 的引用，stop() 靠它叫停

    h2::Server* srv_ = nullptr;
    std::map<std::uint32_t, StreamCtx> streams_;
    Bytes ctrlRx_;
    std::size_t ctrlConsumed_ = 0;
    std::uint32_t ctrlStream_ = 0;
    bool needHandshake_ = false;

};

}  // namespace

bool Client::run(const Config& cfg, Status& status,
                 const std::function<void(const std::string&)>& log,
                 const std::function<void(const Status&)>& on_status) {
    Session session(cfg, status, log, on_status, stopping_);
    session.set_request_adder([this](std::uint64_t n) {
        requestsServed_.fetch_add(n, std::memory_order_relaxed);
    });
    // 发布/撤回"当前连接"：stop() 靠它 shutdown 这个 socket。
    auto publishLive = [this](h2::Server* srv) {
        std::lock_guard<std::mutex> lk(mutex_);
        live_ = srv;
    };
    auto clearLive = [this]() {
        std::lock_guard<std::mutex> lk(mutex_);
        live_ = nullptr;
    };
    return session.run(publishLive, clearLive);
}

}  // namespace ct::client
