#pragma once
// 本地 origin 的两种连接方式：
//   1) OriginStream —— 双向字节管道（长连接协议如 WebSocket 必须用它）
//   2) LocalOrigin —— 一次性请求/响应（quick tunnel 注册、DNS 探测够用）
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace ct::proxy {

// 到 origin 的双向管道。
// 关键约束：begin() 绝不能等 *响应*。转发线程是在 HTTP/2 回调里调它的，
// 而带 body 的请求要等回调返回后才把 body 送过来——在这里等响应会死锁：
// origin 等 body，我们等 head，边缘的 PING/WINDOW_UPDATE 全程没人读。
class OriginStream {
public:
    OriginStream() = default;
    ~OriginStream();
    OriginStream(const OriginStream&) = delete;
    OriginStream& operator=(const OriginStream&) = delete;

    bool begin(const std::string& host, std::uint16_t port, const std::string& method,
               const std::string& path,
               const std::vector<std::pair<std::string, std::string>>& headers, int timeout_ms,
               std::string& error);

    enum class Step { Pending, Ready, Failed };
    Step step();

    const std::string& response_head() const { return responseHead_; }
    const std::string& error_text() const { return error_; }
    std::int64_t age_ms() const;

    bool pending() const { return state_ == Step::Pending; }

    // 请求头是否已整条交给 socket（此后才可以半关闭）
    bool request_sent() const {
        return fd_ >= 0 && requestHead_.size() > 0 && headSent_ >= requestHead_.size();
    }

    // 排队写出，永不阻塞：socket 不收的留到 flush() 再推。
    bool write(const void* data, std::size_t len);
    bool flush();
    bool has_pending_output() const { return pendingOut_.size() > pendingOutOff_; }
    std::size_t pending_output_bytes() const { return pendingOut_.size() - pendingOutOff_; }

    // 半关写端（相当于 shutdown(SHUT_WR)）。
    //
    // 什么时候需要它：边缘发完请求（END_STREAM）之后，origin 仍要读请求体、
    // 处理、再回响应。不半关的话，origin 上等 "请求结束" 的逻辑（读循环收到
    // EOF 才认为请求完整）会永远等下去，响应根本不会产生。
    // 什么时候不能调：dispatch 里还有没写出去的字节（会截断请求），或者响应是
    // 没有 content-length 的活流（半关会让 origin 的 chunked 写看到 EOF 收流）。
    // 这两条判断由调用方负责，本函数只做半关，幂等。
    void shutdown_write();

    // >0 读到的字节；0 超时；-1 对端关闭/出错
    int read_some(void* buf, std::size_t cap, int timeout_ms);

    std::intptr_t fd() const { return fd_; }
    bool valid() const { return fd_ >= 0; }
    void close();

private:
    std::intptr_t fd_ = -1;
    std::vector<std::uint8_t> pending_;
    std::size_t pendingOff_ = 0;
    std::vector<std::uint8_t> pendingOut_;
    std::size_t pendingOutOff_ = 0;
    Step state_ = Step::Pending;
    bool connecting_ = false;
    std::string requestHead_;
    std::size_t headSent_ = 0;
    std::string headBuf_;
    std::string responseHead_;
    std::string error_;
    std::int64_t startedAt_ = 0;
    int timeoutMs_ = 15000;
    bool shutWrite_ = false;   // 半关只能做一次，重复调用要安全
};

// 一次性 HTTP/1.1 请求
class LocalOrigin {
public:
    struct Response {
        int status = 0;
        std::string reason;
        std::vector<std::pair<std::string, std::string>> headers;
        std::vector<std::uint8_t> body;
        std::string header(const std::string& name) const;
    };

    static bool request(const std::string& host, std::uint16_t port, const std::string& method,
                        const std::string& path,
                        const std::vector<std::pair<std::string, std::string>>& headers,
                        const std::vector<std::uint8_t>& body, bool keep_alive, Response& out,
                        std::string& error);
};

}  // namespace ct::proxy
