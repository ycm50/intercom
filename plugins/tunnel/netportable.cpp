#include "netportable.h"

// socket 层的唯一实现处：POSIX 与 Winsock 的差异全部收口在这里。
//
// 为什么需要这一层：参考实现直接摸 <sys/socket.h> + poll(2) + fcntl，
// 换到 Windows 整条隧道就编不出来。这里对外只暴露 intptr_t 句柄、
// 自己的一套事件位和统一的收发返回约定，上层（h2 / proxy / client）
// 永远不需要知道自己在哪个系统上跑，也不该出现任何 #ifdef _WIN32。

#include <cerrno>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace ct::net {
namespace {

#if defined(_WIN32)
using native_socket = SOCKET;
constexpr native_socket kInvalidNative = INVALID_SOCKET;
using native_pollfd = WSAPOLLFD;
using opt_len_t = int;  // Winsock 的 getsockopt 长度参数是 int*
constexpr int kNotSocketCode = WSAENOTSOCK;
constexpr int kInvalidArgumentCode = WSAEINVAL;
constexpr int kInterruptedCode = WSAEINTR;
constexpr int kWouldBlockCode = WSAEWOULDBLOCK;
#else
using native_socket = int;
constexpr native_socket kInvalidNative = -1;
using native_pollfd = pollfd;
using opt_len_t = socklen_t;  // POSIX 是 socklen_t*
constexpr int kNotSocketCode = ENOTSOCK;
constexpr int kInvalidArgumentCode = EINVAL;
constexpr int kInterruptedCode = EINTR;
constexpr int kWouldBlockCode = EAGAIN;
#endif

// send_some / recv_some 的返回类型是 size_t（头文件如此），"出错"没法写成 -1，
// 只能编成 size_t 的最大值。这里是唯一的编码点；调用方比对这个常量，
// 再用 would_block(last_error()) 区分"重试即可"和"连接坏了"。
constexpr std::size_t kIoError = static_cast<std::size_t>(-1);

inline native_socket to_native(socket_t s) { return static_cast<native_socket>(s); }

inline socket_t to_portable(native_socket s) {
#if defined(_WIN32)
    // INVALID_SOCKET 是全 1 的 UINT_PTR，转成 intptr_t 就是 -1；这里写明确免得看花。
    return s == INVALID_SOCKET ? kInvalid : static_cast<socket_t>(s);
#else
    return static_cast<socket_t>(s);
#endif
}

#if defined(_WIN32)
// Winsock 的 optval 是 char*，POSIX 是 void*；两个小转换函数把类型擦干净。
inline char* optval_out(void* p) { return static_cast<char*>(p); }
inline const char* optval_in(const void* p) { return static_cast<const char*>(p); }
#else
inline void* optval_out(void* p) { return p; }
inline const void* optval_in(const void* p) { return p; }
#endif

inline void set_last_error(int code) {
#if defined(_WIN32)
    WSASetLastError(code);
#else
    errno = code;
#endif
}

// 事件位映射：上层只认 kRead/kWrite，底下是 POLLIN 还是 POLLRDNORM 只在这里决定。
// 这一步绝不能省：Winsock 里 POLLERR 恰好等于 0x0001，跟我们的 kRead 撞值，
// 直接把我们的位丢给 WSAPoll 会把"读就绪"当成错误上报。
inline short events_to_native(short events) {
    short out = 0;
#if defined(_WIN32)
    if ((events & kRead) != 0) out |= POLLRDNORM;
    if ((events & kWrite) != 0) out |= POLLWRNORM;
#else
    if ((events & kRead) != 0) out |= POLLIN;
    if ((events & kWrite) != 0) out |= POLLOUT;
#endif
    return out;
}

inline short revents_to_portable(short revents) {
    short out = 0;
#if defined(_WIN32)
    // WSAPoll 用的是 POLLRDNORM/POLLWRNORM 这一组；POLLIN/POLLOUT 只是别名。
    // WSAPoll 本身不会回 POLLNVAL（它是整批失败），坏句柄在 poll_fds 里自己标，
    // 所以这里只映射真正可能出现的四个位。
    if ((revents & POLLRDNORM) != 0) out |= kRead;
    if ((revents & POLLWRNORM) != 0) out |= kWrite;
    if ((revents & POLLERR) != 0) out |= kErr;
    if ((revents & POLLHUP) != 0) out |= kHangup;
#else
    // POLLPRI 是带外数据，读起来同样会立刻返回，算作可读。
    if ((revents & (POLLIN | POLLPRI)) != 0) out |= kRead;
    if ((revents & POLLOUT) != 0) out |= kWrite;
    // 三个异常位两边都放在 revents 里，原样折叠成我们自己的错误位。
    if ((revents & POLLERR) != 0) out |= kErr;
    if ((revents & POLLHUP) != 0) out |= kHangup;
    if ((revents & POLLNVAL) != 0) out |= kInvalidFd;
#endif
    return out;
}

// 从绝对截止时间算这次还能等多久。EINTR 之后重等必须重算，
// 否则一轮轮被信号打断就会把 timeout_ms 悄悄放大成"无限"。
int remaining_timeout_ms(std::chrono::steady_clock::time_point deadline) {
    const auto left =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now())
            .count();
    if (left <= 0) return 0;
    if (left > 3600000) return 3600000;  // 转 int 之前先夹住，别溢出成负数
    return static_cast<int>(left);
}

// count == 0 时 poll 的语义就是"睡满超时"，而 WSAPoll 对空集合的行为没有保证，
// 干脆自己分段睡（也顺便让退出流程有机会插进来）。
void sleep_without_fds(int timeout_ms) {
    // 对齐 poll 的语义：空集合 + 无限超时就是"一直等到进程结束"（永远不会有事件）。
    // 分段睡只是让调用方在调试器/信号下有插进来的机会，结果与一次性长睡相同。
    if (timeout_ms < 0) {
        for (;;) std::this_thread::sleep_for(std::chrono::hours(1));
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        const auto left =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now())
                .count();
        std::this_thread::sleep_for(std::chrono::milliseconds(left < 100 ? left : 100));
    }
}

#if defined(_WIN32)
// WSAPoll 遇到坏句柄是整批失败（POSIX poll 只把那一项标成 POLLNVAL），
// 拿不到"是谁坏了"的时候只能逐个探活；SO_TYPE 是最便宜的无损探测。
bool socket_alive(native_socket s) {
    int type = 0;
    int len = static_cast<int>(sizeof(type));
    return getsockopt(s, SOL_SOCKET, SO_TYPE, optval_out(&type), &len) == 0;
}
#endif

// 查 connect 的真实结果：非阻塞 connect 之后内核把成功/失败原因挂在 SO_ERROR。
// 返回 false 表示连 SO_ERROR 都读不出来（sys_error 是读失败的原因）。
bool query_so_error(native_socket s, int& code, std::string& sys_error) {
    int so_error = 0;
    opt_len_t len = static_cast<opt_len_t>(sizeof(so_error));
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, optval_out(&so_error), &len) != 0) {
        code = 0;
        sys_error = error_string(last_error());
        return false;
    }
    code = so_error;
    sys_error.clear();
    return true;
}

#if defined(_WIN32)
const char* wsa_text(int code) {
    switch (code) {
        case WSAEINTR: return "操作被中断";
        case WSAEBADF: return "句柄编号无效";
        case WSAEACCES: return "权限不足";
        case WSAEFAULT: return "地址参数非法";
        case WSAEINVAL: return "参数非法";
        case WSAEMFILE: return "本进程 socket 句柄用尽";
        case WSAEWOULDBLOCK: return "暂时不可用，稍后重试";
        case WSAEINPROGRESS: return "上一个阻塞调用仍在进行";
        case WSAEALREADY: return "非阻塞操作已经在进行";
        case WSAENOTSOCK: return "不是有效 socket（句柄可能已被关闭）";
        case WSAEDESTADDRREQ: return "缺少目标地址";
        case WSAEMSGSIZE: return "报文超过上限";
        case WSAEPROTOTYPE: return "socket 类型与协议不匹配";
        case WSAENOPROTOOPT: return "不认识的选项";
        case WSAEPROTONOSUPPORT: return "不支持的协议";
        case WSAEOPNOTSUPP: return "不支持的操作";
        case WSAEAFNOSUPPORT: return "不支持的地址族";
        case WSAEADDRINUSE: return "地址已被占用";
        case WSAEADDRNOTAVAIL: return "地址不可用";
        case WSAENETDOWN: return "网络子系统已关闭";
        case WSAENETUNREACH: return "网络不可达";
        case WSAENETRESET: return "连接因网络重置而断开";
        case WSAECONNABORTED: return "连接被本机中止";
        case WSAECONNRESET: return "连接被对方重置";
        case WSAENOBUFS: return "缓冲区不足";
        case WSAEISCONN: return "已经处于连接状态";
        case WSAENOTCONN: return "尚未连接";
        case WSAESHUTDOWN: return "socket 已关闭收发";
        case WSAETIMEDOUT: return "连接超时";
        case WSAECONNREFUSED: return "连接被对方拒绝";
        case WSAEHOSTDOWN: return "主机已关闭";
        case WSAEHOSTUNREACH: return "主机不可达";
        case WSASYSNOTREADY: return "网络子系统未就绪";
        case WSAVERNOTSUPPORTED: return "Winsock 版本不支持";
        case WSANOTINITIALISED: return "尚未调用 WSAStartup";
        case WSAHOST_NOT_FOUND: return "主机名找不到";
        case WSATRY_AGAIN: return "名字服务暂时失败";
        case WSANO_RECOVERY: return "名字服务不可恢复的错误";
        case WSANO_DATA: return "名字存在但没有可用地址";
        default: return nullptr;
    }
}
#endif

#if !defined(_WIN32)
std::string gai_error_text(int rc) {
    switch (rc) {
        case EAI_NONAME: return "主机名或服务名不存在";
        case EAI_AGAIN: return "名字服务暂时失败，稍后再试";
        case EAI_FAIL: return "名字服务返回不可恢复的错误";
        case EAI_FAMILY: return "不支持的地址族";
        case EAI_SOCKTYPE: return "不支持的 socket 类型";
        case EAI_SERVICE: return "不支持的服务名";
        case EAI_MEMORY: return "解析时内存不足";
        case EAI_SYSTEM: return std::string("系统调用出错：") + error_string(errno);
        default: break;
    }
    return "getaddrinfo 返回错误码 " + std::to_string(rc);
}
#endif

// 进程级引用计数。init 会被多个模块各自调用一次，
// Windows 只有最后一个使用者退出时才 WSACleanup，否则后 init 的模块会突然没网。
std::mutex g_init_mutex;
int g_init_count = 0;

}  // namespace

std::size_t send_some(socket_t s, const void* data, std::size_t len) {
    if (s == kInvalid) {
        set_last_error(kNotSocketCode);
        return kIoError;
    }
    if (data == nullptr && len != 0) {
        set_last_error(kInvalidArgumentCode);
        return kIoError;
    }
    if (len == 0) {
        set_last_error(0);
        return 0;  // 空发送是成功，不是"写不进去"
    }

    const native_socket ns = to_native(s);
    // 系统调用只收 int 长度。非阻塞 socket 本来就一次收不满全部数据，
    // 所以这里把单次量夹到 INT_MAX，剩下的由调用方按返回的字节数续发。
    const int chunk = len > static_cast<std::size_t>(INT_MAX) ? INT_MAX : static_cast<int>(len);
    for (;;) {
        const int n = ::send(ns, optval_in(data), chunk, 0);
        if (n > 0) return static_cast<std::size_t>(n);
        if (n == 0) {
            // len 非 0 时内核基本不会返回 0；真拿到就按"当前不可写"处理。
            // 契约规定 send 返回 0 = 暂时写不进去，所以这里必须留下一个
            // would_block 类错误码，否则调用方查 last_error() 会拿到空结论。
            set_last_error(kWouldBlockCode);
            return 0;
        }
        const int code = last_error();
        // EINTR 只是被信号打断，socket 状态没变，重试即可（不是错误，也没数据丢失）。
        if (code == kInterruptedCode) continue;
        // 暂时写不进去按契约返回 0（而不是 -1），这样调用方可以直接把剩余数据
        // 留着下次 flush；last_error 里仍保留 would_block 码，想区分的调用方查得到。
        if (would_block(code)) return 0;
        return kIoError;
    }
}

std::size_t recv_some(socket_t s, void* buf, std::size_t cap) {
    if (s == kInvalid) {
        set_last_error(kNotSocketCode);
        return kIoError;
    }
    if (buf == nullptr && cap != 0) {
        set_last_error(kInvalidArgumentCode);
        return kIoError;
    }
    if (cap == 0) {
        set_last_error(0);
        return 0;  // 没要字节：既不是 EOF 也不是错误
    }

    const native_socket ns = to_native(s);
    const int chunk = cap > static_cast<std::size_t>(INT_MAX) ? INT_MAX : static_cast<int>(cap);
    for (;;) {
        const int n = ::recv(ns, static_cast<char*>(buf), chunk, 0);
        if (n > 0) return static_cast<std::size_t>(n);
        if (n == 0) {
            // 对端发完 FIN：这是正常关闭，不是错误。顺手把错误槽清零，
            // 免得调用方读到一个上一次残留的码而误判。
            set_last_error(0);
            return 0;
        }
        const int code = last_error();
        if (code == kInterruptedCode) continue;
        // 这里不能用 0 表示"暂时没数据"：0 已经被约定成"对端正常关闭"，
        // 混用会让 poll 与 recv 之间的竞态被误判成断链。所以 would_block 与
        // 真正的错误（ECONNRESET / WSAECONNRESET 等）一样返回 kIoError，
        // 调用方靠 would_block(last_error()) 区分"再等一轮"和"连接坏了"。
        return kIoError;
    }
}

bool init(std::string& error) {
#if defined(_WIN32)
    std::lock_guard<std::mutex> lock(g_init_mutex);
    if (g_init_count > 0) {
        ++g_init_count;
        return true;
    }
    WSADATA data{};
    const int rc = WSAStartup(MAKEWORD(2, 2), &data);
    if (rc != 0) {
        // WSAStartup 失败时不能只报码，要让运维看得懂到底缺什么。
        error = "WSAStartup(2.2) 失败：" + error_string(rc);
        return false;
    }
    g_init_count = 1;
    return true;
#else
    // POSIX 没有进程级初始化；计数照样维护，只为了 shutdown 能配对而不是空转。
    (void)error;
    std::lock_guard<std::mutex> lock(g_init_mutex);
    ++g_init_count;
    return true;
#endif
}

void shutdown() {
    std::lock_guard<std::mutex> lock(g_init_mutex);
    if (g_init_count <= 0) return;  // 多减不该炸：调用方的 init 可能早就失败了
    --g_init_count;
#if defined(_WIN32)
    if (g_init_count == 0) WSACleanup();
#endif
}

bool set_nonblocking(socket_t s) {
    if (s == kInvalid) return false;
#if defined(_WIN32)
    u_long mode = 1;
    return ioctlsocket(to_native(s), FIONBIO, &mode) == 0;
#else
    // fcntl 会被信号打断，必须重试；否则偶发 EINTR 会让连接悄悄留成阻塞式，
    // 后面一次 ::recv 就可能把整条转发线程挂住。
    int flags = 0;
    do {
        flags = ::fcntl(to_native(s), F_GETFL, 0);
    } while (flags < 0 && errno == EINTR);
    if (flags < 0) return false;
    if ((flags & O_NONBLOCK) != 0) return true;
    int rc = 0;
    do {
        rc = ::fcntl(to_native(s), F_SETFL, flags | O_NONBLOCK);
    } while (rc < 0 && errno == EINTR);
    return rc == 0;
#endif
}

bool set_nodelay(socket_t s) {
    if (s == kInvalid) return false;
    const int one = 1;
    // 隧道上全是密集小包（HTTP/2 控制帧 + 代理头），Nagle 只会白白攒包增加延迟。
    return setsockopt(to_native(s), IPPROTO_TCP, TCP_NODELAY, optval_in(&one),
                      static_cast<int>(sizeof(one))) == 0;
}

void close(socket_t s) {
    // 句柄是唯一所有权，这里不做重复关闭保护；无效句柄直接忽略。
    if (s == kInvalid) return;
#if defined(_WIN32)
    closesocket(to_native(s));
#else
    ::close(to_native(s));
#endif
}

void shutdown_write(socket_t s) {
    // 这是 POSIX 与 Windows 在此文件里第二处（也是最后一处）无法共写的差异：
    // 两个平台的 shutdown 常量与句柄类型都不同。
    if (s == kInvalid) return;
#if defined(_WIN32)
    // SD_SEND = 只关发送方向。用 SD_BOTH 会把读方向也断掉，
    // 而 relay 在请求发完之后正是靠读方向收 origin 的响应。
    ::shutdown(to_native(s), SD_SEND);
#else
    // SHUT_WR = 只关发送方向，同一道理。
    ::shutdown(to_native(s), SHUT_WR);
#endif
}

int last_error() {
#if defined(_WIN32)
    return WSAGetLastError();
#else
    return errno;
#endif
}

std::string error_string(int code) {
    if (code == 0) return "无错误";
#if defined(_WIN32)
    if (const char* text = wsa_text(code)) {
        return std::string(text) + "（WSA " + std::to_string(code) + "）";
    }
    return "Winsock 错误 " + std::to_string(code);
#else
    switch (code) {
        case EINTR: return "操作被信号打断（EINTR）";
        case EAGAIN: return "暂时不可用，稍后重试（EAGAIN）";
        case EINPROGRESS: return "非阻塞操作正在进行（EINPROGRESS）";
        case EALREADY: return "非阻塞操作已在进行（EALREADY）";
        case EINVAL: return "参数非法（EINVAL）";
        case EBADF: return "句柄无效（EBADF）";
        case EMFILE: return "本进程句柄用尽（EMFILE）";
        case ENFILE: return "系统句柄用尽（ENFILE）";
        case ENOMEM: return "内存不足（ENOMEM）";
        case ENOBUFS: return "缓冲区不足（ENOBUFS）";
        case EACCES: return "权限不足（EACCES）";
        case EPIPE: return "对端已关闭（EPIPE）";
        case ECONNREFUSED: return "连接被拒绝（ECONNREFUSED）";
        case ECONNRESET: return "连接被对方重置（ECONNRESET）";
        case ECONNABORTED: return "连接被中止（ECONNABORTED）";
        case ENOTCONN: return "尚未连接（ENOTCONN）";
        case EISCONN: return "已经连接（EISCONN）";
        case ETIMEDOUT: return "操作超时（ETIMEDOUT）";
        case EHOSTUNREACH: return "主机不可达（EHOSTUNREACH）";
        case ENETUNREACH: return "网络不可达（ENETUNREACH）";
        case ENETDOWN: return "网络已关闭（ENETDOWN）";
        case EADDRINUSE: return "地址已被占用（EADDRINUSE）";
        case EADDRNOTAVAIL: return "地址不可用（EADDRNOTAVAIL）";
        case EAFNOSUPPORT: return "不支持的地址族（EAFNOSUPPORT）";
        case EPROTONOSUPPORT: return "不支持的协议（EPROTONOSUPPORT）";
        case ENOTSOCK: return "不是 socket（ENOTSOCK）";
        case EMSGSIZE: return "报文过长（EMSGSIZE）";
        default: break;
    }
    // 剩下的交给 strerror：错误路径上不追求严格线程安全，具体文字比"码"有用。
    const char* text = std::strerror(code);
    return std::string(text != nullptr ? text : "未知错误") + "（" + std::to_string(code) + "）";
#endif
}

bool would_block(int code) {
#if defined(_WIN32)
    // WSAEINPROGRESS 是老 Winsock 的口径，一并算"现在不能做、稍后重试"。
    return code == WSAEWOULDBLOCK || code == WSAEINPROGRESS;
#else
    // Linux 上 EAGAIN 与 EWOULDBLOCK 数值相同，所以用 || 而不是 switch。
    return code == EAGAIN || code == EWOULDBLOCK;
#endif
}

bool connect_in_progress(int code) {
#if defined(_WIN32)
    // 非阻塞 connect 在 Windows 上报 WSAEWOULDBLOCK（老代码上报 WSAEINPROGRESS），
    // 对同一个 socket 重复 connect 则是 WSAEALREADY。
    return code == WSAEWOULDBLOCK || code == WSAEINPROGRESS || code == WSAEALREADY;
#else
    // EINTR 也算：非阻塞 connect 被信号打断，连接其实还在推进，不能判死。
    return code == EINPROGRESS || code == EALREADY || code == EINTR;
#endif
}

int poll_fds(PollFd* fds, std::size_t count, int timeout_ms) {
    if (count == 0) {
        sleep_without_fds(timeout_ms);
        return 0;
    }
    if (fds == nullptr) {
        set_last_error(kInvalidArgumentCode);
        return -1;
    }

    // 先把无效句柄挑出来自己处理。原因：Windows 只要集合里混进一个坏句柄，
    // 整个 WSAPoll 就失败且不告诉你坏的是哪个；POSIX 则会立刻返回并标 POLLNVAL。
    // 统一成"把坏的那一项标 kInvalidFd 并立刻返回"，两平台的调用约定就一致了。
    std::size_t invalid_count = 0;
    for (std::size_t i = 0; i < count; ++i) {
        fds[i].revents = 0;
        if (fds[i].fd < 0) {
            fds[i].revents = kInvalidFd;
            ++invalid_count;
        }
    }

    std::vector<native_pollfd> native;
    std::vector<std::size_t> native_index;  // native[i] 对应调用方的第几项
    native.reserve(count - invalid_count);
    native_index.reserve(count - invalid_count);
    for (std::size_t i = 0; i < count; ++i) {
        if (fds[i].fd < 0) continue;
        native_pollfd entry{};
        entry.fd = to_native(fds[i].fd);
        entry.events = events_to_native(fds[i].events);
        entry.revents = 0;
        native.push_back(entry);
        native_index.push_back(i);
    }

#if !defined(_WIN32)
    // 只有 POSIX 的 EINTR 重等路径需要绝对截止时间；Windows 侧没有这个变量免得告警。
    const bool infinite = timeout_ms < 0;
    // infinite 时 deadline 只是个占位（重新计算的那一步会直接还原成 -1）。
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(infinite ? 1 : timeout_ms);
#endif
    // 有坏句柄时按 POSIX 语义立即返回，不给系统调用机会去阻塞。
    int wait = invalid_count > 0 ? 0 : timeout_ms;

    int ready = 0;
    while (!native.empty()) {
        int rc = 0;
#if defined(_WIN32)
        rc = WSAPoll(native.data(), static_cast<ULONG>(native.size()), wait);
#else
        rc = ::poll(native.data(), static_cast<nfds_t>(native.size()), wait);
#endif
        if (rc >= 0) {
            ready = rc;
            break;
        }
#if defined(_WIN32)
        const int code = WSAGetLastError();
        if (code == WSAENOTSOCK || code == WSAEINVAL) {
            // 上面只兜住了"传进来就是 -1"这种；句柄被别处关掉再传进来时 WSAPoll
            // 只报"整批里有坏的"，不知道是谁。逐个探活，把死句柄折成 kInvalidFd
            // 交给调用方（它本来就该处理 POLLNVAL），活的句柄照常保留继续等。
            std::vector<native_pollfd> alive;
            std::vector<std::size_t> alive_index;
            int dead = 0;
            for (std::size_t i = 0; i < native.size(); ++i) {
                if (socket_alive(native[i].fd)) {
                    native[i].revents = 0;
                    alive.push_back(native[i]);
                    alive_index.push_back(native_index[i]);
                } else {
                    fds[native_index[i]].revents |= kInvalidFd;
                    ++dead;
                }
            }
            native.swap(alive);
            native_index.swap(alive_index);
            if (dead > 0) {
                // 死的已经报完了；活的用 0 超时顺手看一眼，别漏掉已就绪的事件。
                // 返回值按"死的 + 活的就绪"合起来算，和 poll 的语义保持一致。
                int alive_ready = 0;
                if (!native.empty()) {
                    const int rr = WSAPoll(native.data(), static_cast<ULONG>(native.size()), 0);
                    alive_ready = rr > 0 ? rr : 0;
                }
                ready = dead + alive_ready;
                break;
            }
        }
        set_last_error(code);
        return -1;
#else
        if (errno != EINTR) return -1;
        // 被信号打断就按"剩余时间"重等；否则一个 EINTR 就能让读循环误判成超时。
        // 无限等待必须还原成 -1：deadline 在 infinite 分支里只是个占位值。
        wait = infinite ? -1 : remaining_timeout_ms(deadline);
#endif
    }

    for (std::size_t i = 0; i < native.size(); ++i) {
        const short mapped = revents_to_portable(native[i].revents);
        if (mapped != 0) fds[native_index[i]].revents |= mapped;
    }

    return ready + static_cast<int>(invalid_count);
}

bool resolve_host(const std::string& host, std::uint16_t port, void* sockaddr_out,
                  int& sockaddr_len, int& family, std::string& error) {
    error.clear();
    if (sockaddr_out == nullptr) {
        error = "resolve_host：输出缓冲区为空（调用方要给至少 sizeof(sockaddr_storage) 的空间）";
        return false;
    }
    if (host.empty()) {
        error = "resolve_host：主机名为空";
        return false;
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;  // v4/v6 都收，优先级交给系统的 RFC 6724 排序
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_NUMERICSERV;  // 端口是我们自己给的数字，别去查 services 表

    addrinfo* res = nullptr;
    const int rc = ::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res);
    if (rc != 0 || res == nullptr) {
#if defined(_WIN32)
        // Windows 的 getaddrinfo 直接返回 WSA 错误码（11001/11002/11004），
        // 走 error_string 的 WSA 表就足够具体。
        error = "解析主机 \"" + host + "\" 失败：" + error_string(rc);
#else
        error = "解析主机 \"" + host + "\" 失败：" + gai_error_text(rc);
#endif
        if (res != nullptr) ::freeaddrinfo(res);
        return false;
    }

    // 只取第一条可用记录：每条隧道连接都独占一条 TCP，多地址轮询留给上层决定。
    const addrinfo* picked = res;
    while (picked != nullptr && (picked->ai_addr == nullptr || picked->ai_addrlen == 0)) {
        picked = picked->ai_next;
    }
    if (picked == nullptr) {
        error = "解析主机 \"" + host + "\" 没有拿到可用地址";
        ::freeaddrinfo(res);
        return false;
    }

    const std::size_t len = static_cast<std::size_t>(picked->ai_addrlen);
    if (len > sizeof(sockaddr_storage)) {
        error = "解析主机 \"" + host + "\" 得到的地址结构过长：" + std::to_string(len) + " 字节";
        ::freeaddrinfo(res);
        return false;
    }
    std::memcpy(sockaddr_out, picked->ai_addr, len);
    sockaddr_len = static_cast<int>(len);
    family = picked->ai_family;
    ::freeaddrinfo(res);
    return true;
}

bool connect_tcp(const std::string& host, std::uint16_t port, int timeout_ms, socket_t& out,
                 std::string& error) {
    out = kInvalid;
    error.clear();
    const std::string endpoint = host + ":" + std::to_string(port);

    // 超时预算从最外层开始算：DNS 也要吃预算，否则一个卡住的名字解析
    // 会把"15 秒内连不上就放弃"变成"永远不放弃"。
    const bool infinite = timeout_ms < 0;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(infinite ? 0 : timeout_ms);

    sockaddr_storage addr{};
    int addr_len = 0;
    int family = 0;
    if (!resolve_host(host, port, &addr, addr_len, family, error)) return false;

    const native_socket ns = ::socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (ns == kInvalidNative) {
        error = "为 " + endpoint + " 创建 socket 失败：" + error_string(last_error());
        return false;
    }
    const socket_t s = to_portable(ns);

    if (!set_nonblocking(s)) {
        error = "无法把 " + endpoint + " 的 socket 切成非阻塞：" + error_string(last_error());
        close(s);
        return false;
    }
    // Nagle 对隧道是纯负担（控制帧都很小）；设不上也不影响正确性，忽略。
    (void)set_nodelay(s);

    if (::connect(ns, reinterpret_cast<const sockaddr*>(&addr), addr_len) != 0) {
        const int code = last_error();
        // 只有"还在推进"才是正常路径；其余（拒绝/不可达/地址族不符）立刻报出去。
        if (!connect_in_progress(code) && !would_block(code)) {
            error = "连接 " + endpoint + " 失败：" + error_string(code);
            close(s);
            return false;
        }

        // 等待预算要"扣掉"解析和建 socket 已花掉的那部分；infinite 时必须传 -1，
        // 否则用 deadline 算出来是个固定的小数，等于把无限预算缩成几毫秒。
        // 预算已耗尽时仍然走一次 0 超时的 poll：连接可能在这期间已经完成了。
        const int wait = infinite ? -1 : remaining_timeout_ms(deadline);

        // 非阻塞 connect 结束时内核把结果挂在"可写"上；失败时 Windows 可能只报
        // POLLERR/POLLHUP 甚至什么都不报，所以下面任何就绪位都去查 SO_ERROR。
        PollFd pfd{};
        pfd.fd = s;
        pfd.events = kWrite;
        pfd.revents = 0;
        const int pr = poll_fds(&pfd, 1, wait);
        if (pr < 0) {
            error = "等待 " + endpoint + " 的连接结果时出错：" + error_string(last_error());
            close(s);
            return false;
        }

        int so_error = 0;
        std::string sys_error;
        const bool queried = query_so_error(ns, so_error, sys_error);
        if (!queried) {
            error = "读取 " + endpoint + " 的 SO_ERROR 失败：" + sys_error;
            close(s);
            return false;
        }

        if (pr == 0) {
            // 超时也可能只是系统没把失败挂到 poll 上：SO_ERROR 真为 0 才叫超时。
            if (so_error != 0) {
                error = "连接 " + endpoint + " 失败：" + error_string(so_error);
                close(s);
                return false;
            }
            error = "连接 " + endpoint + " 超时（" + std::to_string(timeout_ms) +
                    " ms 内未能完成三次握手）";
            close(s);
            return false;
        }

        if (so_error != 0) {
            error = "连接 " + endpoint + " 失败：" + error_string(so_error);
            close(s);
            return false;
        }
        if ((pfd.revents & (kErr | kHangup | kInvalidFd)) != 0) {
            // SO_ERROR 是 0 但 poll 报了异常位：对端在握手阶段就撤了，别当成功。
            error = "连接 " + endpoint + " 被对端中止（poll 报告 err/hangup 而 SO_ERROR 为 0）";
            close(s);
            return false;
        }
    }

    out = s;
    return true;
}

}  // namespace ct::net
