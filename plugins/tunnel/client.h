#pragma once
// 端到端隧道客户端：拨边缘 -> 以服务端身份说 HTTP/2 -> 在控制流上完成 capnp 注册
// -> 把边缘转发来的请求relay到本地 origin。
//
// 刻意做成最小：单条控制流、不做 QUIC、重连交给外层的监督循环。
#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace ct::h2 {
class Server;
}

namespace ct::client {

struct Config {
    std::string accountTag;    // 令牌里的 a
    std::string tunnelId;      // 令牌里的 t（uuid 文本）
    std::string tunnelSecret;  // 令牌里的 s（原始字节）

    std::string edgeHost = "region1.v2.argotunnel.com";
    std::uint16_t edgePort = 7844;
    std::string edgeSni = "h2.cftunnel.com";

    std::string originHost = "127.0.0.1";
    std::uint16_t originPort = 8080;

    int connectTimeoutMs = 15000;
    int registerTimeoutMs = 20000;
    // 什么都不发生时的等待粒度
    int idlePollMs = 100;
    // 有流在转发时的等待粒度。srv->poll() 只盯边缘 socket，origin 的字节只能
    // 按这个粒度被看到；接近 idlePollMs 会把下载限速到 16KB/tick 并给每个往返
    // 加那么多延迟。几毫秒足以填满管道又不会空转。
    int activePollMs = 2;
};

struct Status {
    bool connected = false;
    bool registered = false;
    std::string uuid;
    std::string location;
    std::string error;
    std::uint64_t requestsServed = 0;
    // 边缘在 ingress 配置里给出的公网 hostname（命名隧道唯一的域名来源）
    std::vector<std::string> hostnames;
};

class Client {
public:
    // 解析 base64 令牌 JSON
    static bool parse_token(const std::string& token, Config& out, std::string& error);

    // 跑到 stop() 或连接断掉为止。log 收进度行；on_status 在状态真正变化时调用，
    // 也用于偶尔刷新已服务请求计数（每 publishIntervalMs 至多一次）。
    bool run(const Config& cfg, Status& status,
             const std::function<void(const std::string&)>& log,
             const std::function<void(const Status&)>& on_status = {});

    // 请求停止。立即唤醒连接（对边缘 socket shutdown），run() 在一个 poll 片内返回。
    void stop();
    bool stopping() const { return stopping_.load(); }

    std::uint64_t requests_served() const { return requestsServed_.load(); }

private:
    void abort_connection();

    std::atomic<bool> stopping_{false};
    std::atomic<std::uint64_t> requestsServed_{0};
    mutable std::mutex mutex_;
    h2::Server* live_ = nullptr;
};

}  // namespace ct::client
