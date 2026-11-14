#include "proxy.h"

#include "h2.h"
#include "netportable.h"

#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

// 本地 origin 的两种连接方式，职责分得很清楚：
//   * OriginStream 是"活管道"：只把请求头递出去，body 与之后的字节全部流式转交，
//     绝不缓存整条响应（WebSocket / 长轮询这类协议一旦缓存就废了）。
//   * LocalOrigin 是"一问一答"：把整条响应读进内存再返回，给 quick tunnel 注册这种
//     一次性调用用，不追求复用连接。
//
// 平台差异一律交给 netportable：这个文件里没有 <sys/socket.h>、没有 poll(2)、
// 没有 fcntl，也没有 #ifdef _WIN32。

namespace ct::proxy {

namespace {

// netportable 的收发接口返回 size_t，而文档约定 -1 表示硬错误：在 size_t 里
// 它就是最大值。给它起个名字，免得每处都写一遍强制转换，也避免有人误以为
// 返回值只可能是"小非负数"。
constexpr std::size_t kIoError = static_cast<std::size_t>(-1);

// 队列上限。到这个量级说明 origin 根本没在读（对端流控窗口被塞满），继续堆
// 只会把"停顿"变成 OOM；上层看到 false 就该拆掉这条流，让边缘重试。
constexpr std::size_t kMaxQueuedBytes = 8u * 1024u * 1024u;

// 响应头超过这个量：要么是 origin 在灌垃圾，要么是协议对不上，早失败省得吃内存。
constexpr std::size_t kMaxHeadBytes = 256u * 1024u;

// 一次性请求的响应体上限。quick 注册返回的是几百字节 JSON，正常永远不会碰到它；
// 有了上限，一个吐不完响应的 origin 不至于把插件的 worker 线程吃干。
constexpr std::size_t kMaxBodyBytes = 8u * 1024u * 1024u;

// LocalOrigin 的两种预算：建连用较短的那个，整条请求（发送 + 收完）另算。
constexpr int kConnectTimeoutMs = 15000;
constexpr int kRequestTimeoutMs = 30000;

// steady_clock 在两个平台都映射到单调时钟，正好用来判超时；system_clock 会被
// 校时跳变影响，用它算超时会偶发"还没到点就先超时"。
std::int64_t mono_ms() {
  using namespace std::chrono;
  return static_cast<std::int64_t>(
      duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

// netportable 要求"用到 socket 前初始化一次"（Windows 上是 WSAStartup）。
// 用函数内静态量保证进程内只做一次：静态局部变量的初始化自 C++11 起是线程安全的，
// 正好覆盖 relay 的多线程场景，不需要在头文件里再加一个"已初始化"标志。
bool ensure_net(std::string& error) {
  struct Once {
    bool ok;
    std::string err;
    Once() : ok(net::init(err)) {}
  };
  static const Once once;
  if (!once.ok) {
    error = once.err.empty() ? "socket 层初始化失败" : once.err;
    return false;
  }
  return true;
}

std::string lower_copy(const std::string& s) {
  std::string out = s;
  for (auto& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return out;
}

std::string trim_copy(const std::string& s) {
  std::size_t b = 0;
  std::size_t e = s.size();
  while (b < e && static_cast<unsigned char>(s[b]) <= ' ') ++b;
  while (e > b && static_cast<unsigned char>(s[e - 1]) <= ' ') --e;
  return s.substr(b, e - b);
}

// 头字段里出现裸 CR/LF 就是请求走私的现成入口。这些 header 来自边缘（外部数据），
// 不能原样拼进我们发出的请求行；碰上就整条丢掉字段，而不是让 origin 看到两行。
bool has_ctl(const std::string& s) {
  return s.find('\r') != std::string::npos || s.find('\n') != std::string::npos;
}

// "HTTP/1.1 200 OK" -> 200 与 "OK"。解析不出来返回 -1——宁可报错，也不要拿
// 一个猜出来的状态码往边缘回。
int parse_status_line(const std::string& line, std::string& reason) {
  reason.clear();
  if (line.compare(0, 5, "HTTP/") != 0) return -1;
  const std::size_t sp = line.find(' ');
  if (sp == std::string::npos) return -1;
  std::size_t i = sp;
  while (i < line.size() && line[i] == ' ') ++i;
  int code = 0;
  int digits = 0;
  while (i < line.size() && digits < 3 && line[i] >= '0' && line[i] <= '9') {
    code = code * 10 + (line[i] - '0');
    ++i;
    ++digits;
  }
  if (digits != 3) return -1;
  reason = trim_copy(line.substr(i));
  return code;
}

// 1xx 里只有 101 是最终答案（WebSocket 升级后的最后状态），其余（100 Continue、
// 103 Early Hints）后面一定还跟着真正的响应头。把过渡块当成最终响应，就会出现
// "把 100 转给边缘 + 请求体永远没人读"这种要命的错。
bool is_interim_head(const std::string& head) {
  const std::size_t eol = head.find("\r\n");
  const std::string statusLine = head.substr(0, eol == std::string::npos ? head.size() : eol);
  std::string reason;
  const int code = parse_status_line(statusLine, reason);
  return code >= 100 && code < 200 && code != 101;
}

// 把请求头推向 socket，推不动就停（非阻塞，绝不在这里等）。
// 返回 false 只代表"连接已经坏了"，半途没写完不算失败，交给 step() 下次再推。
bool push_head(net::socket_t s, const std::string& head, std::size_t& sent,
               std::string& error) {
  while (sent < head.size()) {
    const std::size_t n = net::send_some(s, head.data() + sent, head.size() - sent);
    if (n == kIoError) {
      const int code = net::last_error();
      if (net::would_block(code)) return true;  // 暂时写不进去：留着下次 flush
      error = "发送请求头失败: " + net::error_string(code);
      return false;
    }
    if (n == 0) return true;  // 当前不可写，同样留着
    sent += n;
  }
  return true;
}

// 等到某个方向就绪。deadline 是绝对时刻，所有重试都在同一个预算里收敛，
// 不会因为"每次重试重新计时"把一次卡死的请求拖成无限长。
bool wait_io(net::socket_t s, short events, std::int64_t deadline, std::string& error) {
  for (;;) {
    const std::int64_t left = deadline - mono_ms();
    if (left <= 0) {
      error = "等待 origin 超时";
      return false;
    }
    net::PollFd pfd{s, events, 0};
    const int pr = net::poll_fds(&pfd, 1, static_cast<int>(left));
    if (pr == 0) {
      error = "等待 origin 超时";
      return false;
    }
    if (pr < 0) {
      error = "等待 origin 时 poll 失败: " + net::error_string(net::last_error());
      return false;
    }
    if ((pfd.revents & net::kInvalidFd) != 0) {
      error = "socket 句柄已失效";
      return false;
    }
    // 对端关闭（kHangup）与出错（kErr）都算"可继续动作"：真正的结论要靠
    // send/recv 的返回值来给，poll 只负责把我们从等待里叫醒。
    if ((pfd.revents & (events | net::kErr | net::kHangup)) != 0) return true;
    // revents 里没有我们关心的事件位：继续等，剩余时间会把它收敛掉。
  }
}

// 有预算的整块发送。socket 是非阻塞的，写不进去就 poll 等可写，而不是忙转。
bool send_block(net::socket_t s, const void* data, std::size_t len, std::int64_t deadline,
                std::string& error) {
  const std::uint8_t* p = static_cast<const std::uint8_t*>(data);
  std::size_t off = 0;
  while (off < len) {
    const std::size_t n = net::send_some(s, p + off, len - off);
    if (n == kIoError) {
      const int code = net::last_error();
      if (net::would_block(code)) {
        if (!wait_io(s, net::kWrite, deadline, error)) return false;
        continue;
      }
      error = "发送请求失败: " + net::error_string(code);
      return false;
    }
    if (n == 0) {
      if (!wait_io(s, net::kWrite, deadline, error)) return false;
      continue;
    }
    off += n;
  }
  return true;
}

// 收一块。>0 字节；0 超时（error 已填）；-1 对端关闭或出错（error 已填）。
int recv_block(net::socket_t s, void* buf, std::size_t cap, std::int64_t deadline,
               std::string& error) {
  for (;;) {
    const std::int64_t left = deadline - mono_ms();
    if (left <= 0) {
      error = "读取 origin 响应超时";
      return 0;
    }
    net::PollFd pfd{s, net::kRead, 0};
    const int pr = net::poll_fds(&pfd, 1, static_cast<int>(left));
    if (pr == 0) {
      error = "读取 origin 响应超时";
      return 0;
    }
    if (pr < 0) {
      error = "读取 origin 响应时 poll 失败: " + net::error_string(net::last_error());
      return -1;
    }
    if ((pfd.revents & net::kInvalidFd) != 0) {
      error = "socket 句柄已失效";
      return -1;
    }
    const std::size_t n = net::recv_some(s, buf, cap);
    if (n == kIoError) {
      const int code = net::last_error();
      if (net::would_block(code)) continue;  // poll 与 recv 之间的竞态：再等一轮
      error = "读取 origin 响应失败: " + net::error_string(code);
      return -1;
    }
    if (n == 0) {
      error = "origin 提前关闭了连接";
      return -1;
    }
    return static_cast<int>(n);
  }
}

// 往 raw 里补数据。返回 false 表示读侧结束/超时（error 已填）。
bool fill_raw(net::socket_t s, std::vector<std::uint8_t>& raw, std::int64_t deadline,
              std::string& error) {
  char tmp[8192];
  const int n = recv_block(s, tmp, sizeof(tmp), deadline, error);
  if (n <= 0) {
    if (error.empty()) error = "读取响应体超时";
    return false;
  }
  const std::uint8_t* p = reinterpret_cast<const std::uint8_t*>(tmp);
  raw.insert(raw.end(), p, p + n);
  return true;
}

std::size_t find_crlf(const std::vector<std::uint8_t>& raw, std::size_t from) {
  for (std::size_t i = from; i + 1 < raw.size(); ++i) {
    if (raw[i] == '\r' && raw[i + 1] == '\n') return i;
  }
  return std::string::npos;
}

// "1a" / "1a;ext=1" -> 26。分块长度行允许带扩展参数，粘贴到分号为止。
bool parse_chunk_size(const std::vector<std::uint8_t>& raw, std::size_t from, std::size_t to,
                      std::uint64_t& out) {
  std::uint64_t v = 0;
  int digits = 0;
  for (std::size_t i = from; i < to; ++i) {
    const int c = static_cast<int>(raw[i]);
    int d = -1;
    if (c >= '0' && c <= '9') d = c - '0';
    else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
    if (d < 0) break;  // 扩展参数或空白：到此为止
    v = v * 16 + static_cast<std::uint64_t>(d);
    if (v > (1ull << 48)) return false;  // 明显不合法：别让一个破行把内存算爆
    ++digits;
  }
  if (digits == 0) return false;
  out = v;
  return true;
}

bool parse_decimal(const std::string& s, std::uint64_t& out) {
  if (s.empty()) return false;
  std::uint64_t v = 0;
  for (char c : s) {
    if (c < '0' || c > '9') return false;
    v = v * 10 + static_cast<std::uint64_t>(c - '0');
    if (v > (1ull << 48)) return false;
  }
  out = v;
  return true;
}

}  // namespace

// --- OriginStream ----------------------------------------------------------

OriginStream::~OriginStream() { close(); }

bool OriginStream::begin(const std::string& host, std::uint16_t port, const std::string& method,
                         const std::string& path,
                         const std::vector<std::pair<std::string, std::string>>& headers,
                         int timeout_ms, std::string& error) {
  // 允许同一个对象重新 begin（边缘重连就是这么用的）。先把上一次的状态全部丢掉，
  // 尤其是 responseHead_：残留的旧响应头会被上层当成这次的答案，比连不上更难查。
  // error 是调用方传进来的输出参数，成功路径必须清空，否则会读到上一次的残留。
  error.clear();
  close();
  timeoutMs_ = timeout_ms > 0 ? timeout_ms : 15000;
  startedAt_ = mono_ms();
  state_ = Step::Pending;
  error_.clear();
  responseHead_.clear();
  requestHead_.clear();
  headSent_ = 0;
  headBuf_.clear();
  pending_.clear();
  pendingOff_ = 0;
  pendingOut_.clear();
  pendingOutOff_ = 0;

  // 请求头只依赖入参，先拼好：这样拨号失败时错误信息里还能带上目标，
  // 而且拼头这一步永远不会因为网络状态而卡住。
  std::string req;
  req.reserve(256);
  req += method;
  req += ' ';
  req += path.empty() ? "/" : path;
  req += " HTTP/1.1\r\n";
  bool haveHost = false;
  for (const auto& kv : headers) {
    // h2 伪头（":path" 之类）属于 HTTP/2，拼进 HTTP/1.1 请求行就是非法请求；
    // 裸 CR/LF 则能拆出第二行请求。两种都丢掉，而不是把它们交给 origin。
    if (kv.first.empty() || kv.first[0] == ':') continue;
    if (has_ctl(kv.first) || has_ctl(kv.second)) continue;
    if (lower_copy(kv.first) == "host") haveHost = true;
    req += kv.first;
    req += ": ";
    req += kv.second;
    req += "\r\n";
  }
  if (!haveHost) {
    req += "Host: ";
    req += host;
    req += ':';
    req += std::to_string(port);
    req += "\r\n";
  }
  req += "\r\n";
  requestHead_ = req;

  if (h2::trace_enabled()) {
    h2::trace("[origin] 请求头 -> %s:%u\n%.600s---\n", host.c_str(),
              static_cast<unsigned>(port), requestHead_.c_str());
  }

  std::string initErr;
  if (!ensure_net(initErr)) {
    error_ = initErr;
    error = error_;
    state_ = Step::Failed;
    return false;
  }

  // netportable 只提供带超时的 connect_tcp（它内部做完 getaddrinfo + 非阻塞
  // connect + poll + SO_ERROR），所以这里的"拨号"最多占用 timeoutMs_。
  // 不等响应的底线不能破：转发线程是在 HTTP/2 回调里调 begin() 的，
  // 带 body 的请求要等回调返回才把 body 送过来——在这里等响应头会死锁。
  net::socket_t s = net::kInvalid;
  if (!net::connect_tcp(host, port, timeoutMs_, s, initErr)) {
    error_ = "连接 " + host + ":" + std::to_string(port) + " 失败: " + initErr;
    error = error_;
    state_ = Step::Failed;
    return false;
  }
  fd_ = static_cast<std::intptr_t>(s);
  // 小请求/小响应的隧道场景里 Nagle 只会白加延迟。
  (void)net::set_nodelay(s);
  // connect_tcp 返回时握手已经完成，没有"半开连接"留给 step() 推进。
  connecting_ = false;

  // 顺手把请求头推出去（纯非阻塞写，不等任何响应）。回环 origin 通常一次就能收下，
  // 于是 requestSent() 立刻为真，relay 可以据此决定何时半关闭；收不全也没关系，
  // step() 会接着推。
  std::string headErr;
  if (!push_head(s, requestHead_, headSent_, headErr)) {
    error_ = headErr;
    error = error_;
    state_ = Step::Failed;
    close();
    return false;
  }
  return true;
}

std::int64_t OriginStream::age_ms() const { return mono_ms() - startedAt_; }

// 一次非阻塞推进：发请求头 -> 放行排队的 body -> 收响应头。任何一步拿不到
// 进展就返回 Pending，让 relay 去处理别的方向（边缘的 PING/WINDOW_UPDATE 全靠这个）。
OriginStream::Step OriginStream::step() {
  if (state_ != Step::Pending) return state_;
  if (fd_ < 0) {
    error_ = "socket 已关闭";
    state_ = Step::Failed;
    return state_;
  }
  const auto fail = [&](const std::string& why) {
    error_ = why;
    state_ = Step::Failed;
    return state_;
  };
  const net::socket_t s = static_cast<net::socket_t>(fd_);

  // 连接阶段没有单独的状态：netportable 的 connect_tcp 只在握手完成（或失败）后
  // 才返回，connecting_ 恒为 false，无需在这里再 poll SO_ERROR。

  std::string pushErr;
  if (!push_head(s, requestHead_, headSent_, pushErr)) return fail(pushErr);
  if (headSent_ < requestHead_.size()) {
    if (age_ms() > timeoutMs_) return fail("发送请求头超时");
    return Step::Pending;
  }

  // 头已经出去了，把排队中的 body 放出去：它可能是在连接期间就到了的。
  if (has_pending_output() && !flush()) {
    return fail(error_.empty() ? "发送请求体失败" : error_);
  }

  // 收响应头。注意这里只看头：头之后同一批字节里可能已经带了 body 开头，
  // 必须原样留给 read_some()，丢了首帧的 WebSocket 会立刻握手失败。
  char tmp[8192];
  for (;;) {
    const std::size_t n = net::recv_some(s, tmp, sizeof(tmp));
    if (n == kIoError) {
      const int code = net::last_error();
      if (net::would_block(code)) break;  // 读空了，正常
      return fail("读取响应头失败: " + net::error_string(code));
    }
    if (n == 0) return fail("origin 在响应头之前关闭了连接");
    headBuf_.append(tmp, n);
    const std::size_t hdrEnd = headBuf_.find("\r\n\r\n");
    if (hdrEnd != std::string::npos) {
      std::string head = headBuf_.substr(0, hdrEnd);
      if (is_interim_head(head)) {
        // 过渡块丢掉继续读：剩下的字节里可能已经躺着最终响应头了。
        if (h2::trace_enabled()) {
          h2::trace("[origin] 跳过过渡响应 %.40s\n", head.c_str());
        }
        headBuf_.erase(0, hdrEnd + 4);
        continue;
      }
      responseHead_ = head;
      // 头后面剩下的部分就是 body 的开头；挪进 pending_，让 read_some 先吐出它。
      pending_.assign(headBuf_.begin() + static_cast<std::ptrdiff_t>(hdrEnd + 4),
                      headBuf_.end());
      pendingOff_ = 0;
      headBuf_.clear();
      state_ = Step::Ready;
      return state_;
    }
    if (headBuf_.size() > kMaxHeadBytes) return fail("响应头过大");
  }
  if (age_ms() > timeoutMs_) return fail("等待响应头超时");
  return Step::Pending;
}

bool OriginStream::write(const void* data, std::size_t len) {
  if (fd_ < 0) return false;
  if (len == 0) return flush();
  if (data == nullptr) return false;
  const std::size_t queued = pendingOut_.size() - pendingOutOff_;
  if (queued + len > kMaxQueuedBytes) return false;  // 对端不读：报错让上层拆掉这条流
  const std::uint8_t* p = static_cast<const std::uint8_t*>(data);
  pendingOut_.insert(pendingOut_.end(), p, p + len);
  return flush();
}

bool OriginStream::flush() {
  if (fd_ < 0) return false;
  // 请求头还没送完时不能先发 body：origin 收到的是"半截头 + body"，会把连接判成
  // 畸形请求直接断掉。这里把队列压住，等 step() 把头推完再放行。
  if (headSent_ < requestHead_.size()) return true;

  const net::socket_t s = static_cast<net::socket_t>(fd_);
  while (pendingOutOff_ < pendingOut_.size()) {
    const std::size_t n = net::send_some(s, pendingOut_.data() + pendingOutOff_,
                                         pendingOut_.size() - pendingOutOff_);
    if (n == kIoError) {
      const int code = net::last_error();
      // 暂时没窗口不是错误：这条流还活着，只是 origin 读得慢。
      if (net::would_block(code)) break;
      error_ = "发送数据失败: " + net::error_string(code);
      return false;  // 硬错误：origin 已经跑了
    }
    if (n == 0) break;  // 当前不可写，等下一次 flush
    pendingOutOff_ += n;
  }
  if (pendingOutOff_ >= pendingOut_.size()) {
    pendingOut_.clear();
    pendingOutOff_ = 0;
  } else if (pendingOutOff_ > 256 * 1024) {
    // 偶尔把已消费的前缀丢掉，避免 front 一直往后长、缓冲区虚胖。
    pendingOut_.erase(pendingOut_.begin(),
                      pendingOut_.begin() + static_cast<std::ptrdiff_t>(pendingOutOff_));
    pendingOutOff_ = 0;
  }
  return true;
}

int OriginStream::read_some(void* buf, std::size_t cap, int timeout_ms) {
  if (fd_ < 0) return -1;
  if (buf == nullptr || cap == 0) return 0;

  // 先吐缓冲：跟响应头同一批到达的 body 首字节就躺在这里。
  if (pendingOff_ < pending_.size()) {
    const std::size_t avail = pending_.size() - pendingOff_;
    const std::size_t n = avail < cap ? avail : cap;
    std::memcpy(buf, pending_.data() + pendingOff_, n);
    pendingOff_ += n;
    if (pendingOff_ >= pending_.size()) {
      pending_.clear();
      pendingOff_ = 0;
    }
    return static_cast<int>(n);
  }

  net::PollFd pfd{static_cast<net::socket_t>(fd_), net::kRead, 0};
  const int pr = net::poll_fds(&pfd, 1, timeout_ms);
  if (pr == 0) return 0;  // 超时不是错误：relay 还要轮询反方向
  if (pr < 0) return -1;
  if ((pfd.revents & net::kInvalidFd) != 0) return -1;
  // 即使只有 kErr 也试着读一次：Windows 上对端 RST 之后 recv 才能给出准确原因，
  // 直接判死会把"最后一批数据 + RST"的尾巴丢掉。
  if ((pfd.revents & (net::kRead | net::kHangup | net::kErr)) == 0) return -1;

  const std::size_t n = net::recv_some(static_cast<net::socket_t>(fd_), buf, cap);
  if (n == kIoError) {
    const int code = net::last_error();
    if (net::would_block(code)) return 0;
    return -1;
  }
  if (n == 0) return -1;  // 对端关闭
  return static_cast<int>(n);
}

void OriginStream::shutdown_write() {
  // 幂等：relay 每轮都可能判定"该半关了"。平台差异交给 netportable，
  // 本文件保持"零 #ifdef"（见文件头的说明）。
  if (shutWrite_) return;
    if (fd_ < 0) return;
  shutWrite_ = true;
  net::shutdown_write(static_cast<net::socket_t>(fd_));
}

void OriginStream::close() {
  // 幂等：relay 在 RST、出错、退休时都会关，shared_ptr 析构时还会再关一次。
  if (fd_ >= 0) {
    // 尽力把还排队的请求字节交出去再拆连接；失败也不影响接下来的关闭。
    (void)flush();
    net::close(static_cast<net::socket_t>(fd_));
    fd_ = -1;
  }
  // 关上之后再被问 pending() 必须是 false，否则 relay 会一直等一个不会来的头。
  if (state_ == Step::Pending) state_ = Step::Failed;
  connecting_ = false;
  headBuf_.clear();
  pending_.clear();
  pendingOff_ = 0;
  pendingOut_.clear();
  pendingOutOff_ = 0;
}

// --- LocalOrigin -----------------------------------------------------------

std::string LocalOrigin::Response::header(const std::string& name) const {
  const std::string want = lower_copy(name);
  for (const auto& kv : headers) {
    if (lower_copy(kv.first) == want) return kv.second;
  }
  return {};
}

bool LocalOrigin::request(const std::string& host, std::uint16_t port, const std::string& method,
                          const std::string& path,
                          const std::vector<std::pair<std::string, std::string>>& headers,
                          const std::vector<std::uint8_t>& body, bool keep_alive, Response& out,
                          std::string& error) {
  out = Response{};
  error.clear();

  std::string initErr;
  if (!ensure_net(initErr)) {
    error = initErr;
    return false;
  }

  const std::int64_t deadline = mono_ms() + kRequestTimeoutMs;
  std::string dialErr;
  net::socket_t s = net::kInvalid;
  // keep_alive 只影响请求头：这个最小客户端不复用连接（没有连接池、也不缓存
  // 半开的流），所以请求结束一律 close；对端看到 FIN 是正常收尾。
  if (!net::connect_tcp(host, port, kConnectTimeoutMs, s, dialErr)) {
    error = "连接 " + host + ":" + std::to_string(port) + " 失败: " + dialErr;
    return false;
  }
  (void)net::set_nodelay(s);

  const auto finish = [&](bool ok, const std::string& why) {
    if (s != net::kInvalid) {
      net::close(s);
      s = net::kInvalid;
    }
    error = why;  // 成功时传空串，保证调用方不会读到上一次的残留错误
    return ok;
  };

  // --- 请求头 ---
  std::string head;
  head.reserve(256);
  head += method;
  head += ' ';
  head += path.empty() ? "/" : path;
  head += " HTTP/1.1\r\n";
  head += "Host: ";
  head += host;
  head += ':';
  head += std::to_string(port);
  head += "\r\n";
  bool sentLength = false;
  for (const auto& kv : headers) {
    if (kv.first.empty() || kv.first[0] == ':') continue;
    if (has_ctl(kv.first) || has_ctl(kv.second)) continue;
    const std::string ln = lower_copy(kv.first);
    // Host / Connection 由这里重建；Transfer-Encoding 不支持（本客户端不做分块上传），
    // 混着转发会让 origin 按分块编码去解析我们发的原始 body。
    if (ln == "host" || ln == "connection" || ln == "transfer-encoding") continue;
    if (ln == "content-length") sentLength = true;
    head += kv.first;
    head += ": ";
    head += kv.second;
    head += "\r\n";
  }
  if (!sentLength) {
    head += "Content-Length: ";
    head += std::to_string(body.size());
    head += "\r\n";
  }
  head += "Connection: ";
  head += keep_alive ? "keep-alive" : "close";
  head += "\r\n\r\n";

  if (!send_block(s, head.data(), head.size(), deadline, error)) return finish(false, error);
  if (!body.empty() && !send_block(s, body.data(), body.size(), deadline, error)) {
    return finish(false, error);
  }

  // --- 响应头 ---
  char tmp[8192];
  std::string buf;
  std::string headBlock;
  for (;;) {
    const std::size_t hdrEnd = buf.find("\r\n\r\n");
    if (hdrEnd != std::string::npos) {
      headBlock = buf.substr(0, hdrEnd);
      if (is_interim_head(headBlock)) {
        // 100 Continue / 103 Early Hints 后面还有最终响应头，跳过继续读。
        buf.erase(0, hdrEnd + 4);
        continue;
      }
      break;
    }
    if (buf.size() > kMaxHeadBytes) return finish(false, "响应头过大");
    const int n = recv_block(s, tmp, sizeof(tmp), deadline, error);
    if (n <= 0) return finish(false, error.empty() ? "未收到响应头" : error);
    buf.append(tmp, static_cast<std::size_t>(n));
  }
  const std::size_t hdrEnd = buf.find("\r\n\r\n");
  std::vector<std::uint8_t> raw(buf.begin() + static_cast<std::ptrdiff_t>(hdrEnd + 4),
                                buf.end());

  std::size_t lineEnd = headBlock.find("\r\n");
  if (lineEnd == std::string::npos) lineEnd = headBlock.size();
  const int code = parse_status_line(headBlock.substr(0, lineEnd), out.reason);
  if (code < 0) return finish(false, "响应状态行无法解析");
  out.status = code;

  std::size_t pos = lineEnd < headBlock.size() ? lineEnd + 2 : headBlock.size();
  bool haveLength = false;
  bool chunked = false;
  std::uint64_t contentLength = 0;
  while (pos < headBlock.size()) {
    std::size_t next = headBlock.find("\r\n", pos);
    if (next == std::string::npos) next = headBlock.size();
    const std::string line = headBlock.substr(pos, next - pos);
    pos = next < headBlock.size() ? next + 2 : headBlock.size();
    if (line.empty()) continue;
    const std::size_t colon = line.find(':');
    if (colon == std::string::npos) continue;  // 畸形行忽略，不判整条响应失败
    const std::string name = trim_copy(line.substr(0, colon));
    if (name.empty()) continue;
    const std::string value = trim_copy(line.substr(colon + 1));
    out.headers.emplace_back(name, value);
    const std::string ln = lower_copy(name);
    if (ln == "content-length") {
      // 长度解析不出来就当"没有长度"（按对端关闭划界），不要让一个破字段
      // 把整个响应打成失败——注册接口的响应通常远比这个字段可靠。
      if (parse_decimal(value, contentLength)) haveLength = true;
      else haveLength = false;
    } else if (ln == "transfer-encoding" && lower_copy(value).find("chunked") != std::string::npos) {
      chunked = true;
    }
  }

  // --- 响应体 ---
  // HEAD、204、304 没有 body；1xx（含 101 升级）对一次性客户端来说也没有 body。
  const bool noBody = method == "HEAD" || out.status == 204 || out.status == 304 ||
                      (out.status >= 100 && out.status < 200);
  if (noBody) return finish(true, {});

  if (chunked) {
    // 分块解码而不是把原始分块字节塞给调用方：注册响应是 JSON，带着
    // "1a\r\n{...}\r\n0" 这类框架根本解析不了。
    std::size_t rpos = 0;
    for (;;) {
      std::size_t eol = find_crlf(raw, rpos);
      while (eol == std::string::npos) {
        if (raw.size() - rpos > 4096) return finish(false, "chunked 块首行过长");
        if (!fill_raw(s, raw, deadline, error)) return finish(false, error);
        eol = find_crlf(raw, rpos);
      }
      std::uint64_t chunkSize = 0;
      if (!parse_chunk_size(raw, rpos, eol, chunkSize)) {
        return finish(false, "chunked 块长度无法解析");
      }
      rpos = eol + 2;
      if (chunkSize == 0) {
        // 尾部可能有 trailer 字段，读到空行为止；没有 trailer 就直接结束。
        for (;;) {
          std::size_t t = find_crlf(raw, rpos);
          while (t == std::string::npos) {
            if (raw.size() - rpos > 4096) return finish(false, "chunked 尾部过长");
            if (!fill_raw(s, raw, deadline, error)) return finish(false, error);
            t = find_crlf(raw, rpos);
          }
          const bool empty = t == rpos;
          rpos = t + 2;
          if (empty) break;
        }
        break;
      }
      const std::size_t want = static_cast<std::size_t>(chunkSize);
      if (out.body.size() + want > kMaxBodyBytes) return finish(false, "响应体过大");
      while (raw.size() - rpos < want + 2) {
        if (!fill_raw(s, raw, deadline, error)) return finish(false, error);
      }
      out.body.insert(out.body.end(), raw.begin() + static_cast<std::ptrdiff_t>(rpos),
                      raw.begin() + static_cast<std::ptrdiff_t>(rpos + want));
      rpos += want + 2;  // 跳过块末尾的 CRLF
    }
    return finish(true, {});
  }

  if (haveLength) {
    if (contentLength > kMaxBodyBytes) return finish(false, "响应体过大");
    const std::size_t want = static_cast<std::size_t>(contentLength);
    out.body.assign(raw.begin(), raw.end());
    while (out.body.size() < want) {
      const int n = recv_block(s, tmp, sizeof(tmp), deadline, error);
      if (n <= 0) return finish(false, error.empty() ? "响应体未读完" : error);
      out.body.insert(out.body.end(), tmp, tmp + static_cast<std::ptrdiff_t>(n));
    }
    if (out.body.size() > want) out.body.resize(want);
    return finish(true, {});
  }

  // 既无 Content-Length 也无 chunked：body 只能以"对端关闭"划界。发的是
  // Connection: close，所以对端收尾时会关连接；读到超时就把已有字节交出去
  // （body 不完整由上层解析时自然暴露，而不是在这里误判成整条请求失败）。
  out.body.assign(raw.begin(), raw.end());
  for (;;) {
    const int n = recv_block(s, tmp, sizeof(tmp), deadline, error);
    if (n <= 0) break;
    if (out.body.size() + static_cast<std::size_t>(n) > kMaxBodyBytes) {
      return finish(false, "响应体过大");
    }
    out.body.insert(out.body.end(), tmp, tmp + static_cast<std::ptrdiff_t>(n));
  }
  return finish(true, {});
}

}  // namespace ct::proxy
