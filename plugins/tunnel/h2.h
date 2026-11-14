#pragma once
// 最小 HTTP/2 *服务端* 实现，跑在一条我们自己拨出去的 TLS 连接上。
//
// 方向性容易搞反，这里写清楚（对着真实边缘验证过）：
//   * TCP + TLS: 我们是客户端，拨 region1.v2.argotunnel.com:7844，SNI=h2.cftunnel.com
//     ALPN 不设置、也不要求。
//   * HTTP/2: 我们是*服务端*。握手后边缘先发 "PRI * HTTP/2.0" 和它的 SETTINGS，
//     然后朝我们开 POST 流。
// 这正是 cloudflared 的做法（tls.Client + http2.Server.ServeConn）。
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "netportable.h"

namespace ct::h2 {

// 调试帧追踪，由环境变量 COCHAT_TUNNEL_TRACE=1 打开，生产默认静默。
bool trace_enabled();
void trace(const char* fmt, ...);

// 把完整的 HTTP/2 header 块解码成 name/value（静态表 + 动态表 + huffman 字面量）。
void decode_hpack(const std::uint8_t* block, std::size_t len,
                  std::map<std::string, std::string>& out);

class Server {
public:
    struct Request {
        std::uint32_t streamId = 0;
        std::string method;
        std::string path;
        std::map<std::string, std::string> headers;  // 名字统一小写
    };

    struct Callbacks {
        std::function<void(const Request&)> on_request;
        std::function<void(std::uint32_t streamId, const std::uint8_t* data, std::size_t len)> on_data;
        std::function<void(std::uint32_t streamId)> on_end;
        // 边缘 RST_STREAM：对端放弃了这个流，之后不能再往它写
        std::function<void(std::uint32_t streamId)> on_reset;
        std::function<void(const std::string&)> on_error;
    };

    static Server* create(const Callbacks& cb);
    virtual ~Server() = default;

    // 拨边缘并完成 TLS 客户端握手
    virtual bool connect(const std::string& host, std::uint16_t port, const std::string& sni,
                         int timeout_ms, std::string& error) = 0;

    // 吃掉边缘的 HTTP/2 前言 + SETTINGS，回自己的，切到服务端模式
    virtual bool start_http2(int timeout_ms, std::string& error) = 0;

    // 服务帧。对端关闭或致命错误返回 false。
    virtual bool poll(int timeout_ms) = 0;

    virtual bool write_headers(std::uint32_t streamId, const std::string& status,
                               const std::vector<std::pair<std::string, std::string>>& extra,
                               bool end_stream) = 0;

    // 遵守对端流控窗口地发 DATA。阻塞式：拿到全部额度才返回 true。
    virtual bool write_data(std::uint32_t streamId, const std::uint8_t* data, std::size_t len,
                            bool end_stream) = 0;

    // 非等待版：只写当前窗口允许的量，返回被接受的字节数（0 = 窗口关闭）。
    // 调用方必须保留剩余部分，处理完读侧后重试。
    virtual std::size_t write_data_some(std::uint32_t streamId, const std::uint8_t* data,
                                        std::size_t len, bool end_stream) = 0;

    // 对端此刻在这个流上还有没有写额度
    virtual bool send_credit_available(std::uint32_t streamId) = 0;

    // 对端此刻愿意接受多少字节（连接窗口与流窗口取小）
    virtual std::size_t send_credit_bytes(std::uint32_t streamId) = 0;

    virtual bool write_rst_stream(std::uint32_t streamId, std::uint32_t errorCode) = 0;

    virtual void close() = 0;

    // 唤醒另一个线程里阻塞的 poll()/SSL_read()，并让后续读立即失败。
    // 用于 stop()：让转发线程在一个 poll 周期内退出，而不是等边缘先关。
    virtual void abort() = 0;
};

inline constexpr const char* kUpgradeHeader = "cf-cloudflared-proxy-connection-upgrade";
inline constexpr const char* kUpgradeControlStream = "control-stream";
inline constexpr const char* kUpgradeConfiguration = "update-configuration";

}  // namespace ct::h2
