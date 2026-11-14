#pragma once
// 可移植 socket 层：把 POSIX 的 socket/poll/fcntl 语义收敛到一处，
// 让协议代码（h2 / proxy / client）不出现任何 #ifdef _WIN32。
//
// 之所以要有这一层：原参考实现用 int fd + poll(2) + <sys/socket.h>，
// 在 Windows 上根本编不出来（对方干脆把整个隧道桩掉了）。这里统一成
// intptr_t 句柄 + 自己的 poll 封装，两个平台走同一套代码。
#include <cstddef>
#include <cstdint>
#include <string>

namespace ct::net {

// Windows 的 SOCKET 是 UINT_PTR，POSIX 是 int。intptr_t 能无损装下两者，
// 且两边的"无效句柄"都恰好是 -1。
using socket_t = intptr_t;
constexpr socket_t kInvalid = static_cast<socket_t>(-1);

struct PollFd {
    socket_t fd;
    short events;
    short revents;
};

// 事件位：统一成自己的常量，内部映射到 POLLIN/POLLOUT 或 POLLRDNORM/POLLWRNORM。
constexpr short kRead = 0x0001;
constexpr short kWrite = 0x0002;
constexpr short kErr = 0x0004;
constexpr short kHangup = 0x0008;
constexpr short kInvalidFd = 0x0010;

// 进程级初始化/清理。Windows 上是 WSAStartup/WSACleanup，POSIX 上什么也不做。
// 必须由每个模块在用到 socket 前调用一次；重复调用要安全（内部计数）。
bool init(std::string& error);
void shutdown();

bool set_nonblocking(socket_t s);
bool set_nodelay(socket_t s);

// 关闭。不会重复关闭（内部不维护状态，调用方保证唯一所有权）。
void close(socket_t s);

// 半关写端（POSIX 的 shutdown(SHUT_WR) / Windows 的 SD_SEND）。
//
// 用途：HTTP/1.1 里"请求到此结束"只能靠半关表达。origin 的读循环要收到 EOF
// 才认为请求完整，不半关它就永远等下去、响应根本不会产生。
// 只关写方向，读方向仍然可用 —— 这正是"把请求发给 origin、继续读它的响应"
// 所需要的语义。句柄非法或已关闭时安静返回（调用方不必自己判重）。
void shutdown_write(socket_t s);

int last_error();
std::string error_string(int code);
bool would_block(int code);          // EAGAIN/EWOULDBLOCK/WSAEWOULDBLOCK 一族
bool connect_in_progress(int code);  // EINPROGRESS/WSAEWOULDBLOCK(WSAEINPROGRESS)

// 等待。timeout_ms < 0 = 无限。返回就绪个数，0 = 超时，-1 = 出错。
int poll_fds(PollFd* fds, std::size_t count, int timeout_ms);

// ---- 字节收发 -------------------------------------------------------------
// Windows 用 ::recv/::send（不存在 POSIX 的 ::read/::write），POSIX 用 ::recv/::send。
// 两者语义在此收敛，调用方不需要知道平台差异。
//
// 两者都要求 socket 已设为非阻塞（set_nonblocking）。返回值语义统一：
//   >0  实际处理的字节数
//    0  对端已正常关闭（recv）／当前不可写（send，且 would_block(last_error())）
//   -1  出错，原因用 last_error()/error_string() 取
// 注意 send 返回 -1 时可能是 would_block（暂时没空间），调用方**必须**用
// would_block() 区分"重试即可"和"连接坏了"；把它们混在一起会让大响应卡死。
std::size_t send_some(socket_t s, const void* data, std::size_t len);
std::size_t recv_some(socket_t s, void* buf, std::size_t cap);

// 解析 host 并在超时内完成非阻塞 connect。成功时 out 是已连接的非阻塞 socket。
// 失败返回 false，error 是可直接展示的原因。
bool connect_tcp(const std::string& host, std::uint16_t port, int timeout_ms, socket_t& out,
                 std::string& error);

// 基于 getaddrinfo 的便携包装，只取第一个可用地址族。失败返回 false。
bool resolve_host(const std::string& host, std::uint16_t port, void* sockaddr_out,
                  int& sockaddr_len, int& family, std::string& error);

}  // namespace ct::net
