#include "quick.h"

#include <chrono>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iterator>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "netportable.h"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wincrypt.h>
#endif

#include "../../src/json.h"

namespace ct::quick {

namespace {

#if defined(_WIN32)
// 把 Windows 系统 ROOT 证书存储里的证书逐张加进 ctx 的信任链。
//
// 为什么需要：MSYS2 的 OpenSSL 走的是它自己的默认路径（通常是安装目录里的
// ca-bundle），它不认识 Windows 证书存储；干净机器上那个 bundle 往往不存在，
// 于是任何 HTTPS 握手都会 "certificate verify failed"。这不是"该不该校验"的
// 问题 —— 校验必须开 —— 而是"信任库从哪来"的问题。
//
// 逐张加而不是找系统文件：Windows 没有 PEM 聚合文件，证书就散在存储里。
bool add_windows_root_store(SSL_CTX* ctx) {
    // 必须用 CertOpenStore + CERT_STORE_PROV_SYSTEM 明确指定存储位置。
    // CertOpenSystemStoreA(0, "ROOT") 在这套工具链上返回 NULL（实测），
    // 于是"信任库一张都没加载"却被当成成功，握手仍然失败——比直接报错更难查。
    HCERTSTORE store =
        ::CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
                        CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_READONLY_FLAG, "ROOT");
    if (store == nullptr) return false;
    X509_STORE* x509_store = SSL_CTX_get_cert_store(ctx);
    if (x509_store == nullptr) {
        ::CertCloseStore(store, 0);
        return false;
    }
    int added = 0;
    PCCERT_CONTEXT cur = nullptr;
    while ((cur = ::CertEnumCertificatesInStore(store, cur)) != nullptr) {
        const unsigned char* der = cur->pbCertEncoded;
        if (der == nullptr || cur->cbCertEncoded == 0) continue;
        X509* cert = ::d2i_X509(nullptr, &der, static_cast<long>(cur->cbCertEncoded));
        if (cert == nullptr) continue;
        // X509_STORE_add_cert 对重复证书返回 0 并置错误码，这是正常现象
        // （ROOT 存储里本来就有交叉签名出来的同一张证书），不算失败。
        if (X509_STORE_add_cert(x509_store, cert) == 1) ++added;
        X509_free(cert);
    }
    ::CertCloseStore(store, 0);
    ::ERR_clear_error();
    return added > 0;
}
#endif

using Clock = std::chrono::steady_clock;

// API 与 DoH 的应答都是几 KiB 的 JSON。这个上限只是不让一个失控的对端把进程
// 内存读爆，正常路径永远碰不到。
constexpr std::size_t kMaxResponseBytes = 2u * 1024u * 1024u;
constexpr int kRegisterTimeoutMs = 20000;
// DoH 是两条独立的短连接（A / AAAA），单条超时别设得太长：它在 supervise 线程
// 上同步执行，超时直接变成整条隧道上线前的等待。
constexpr int kDohTimeoutMs = 4000;
constexpr std::uint16_t kHttpsPort = 443;

std::string ascii_lower(const std::string& in) {
    std::string out = in;
    for (char& c : out) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return out;
}

bool ends_with(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string trim(const std::string& in) {
    std::size_t begin = 0;
    std::size_t end = in.size();
    while (begin < end && (in[begin] == ' ' || in[begin] == '\t')) ++begin;
    while (end > begin && (in[end - 1] == ' ' || in[end - 1] == '\t')) --end;
    return in.substr(begin, end - begin);
}

// 两个平台都接受 '/'，用它拼路径就省掉一次分隔符差异的判断。
std::string join_path(const std::string& dir, const std::string& name) {
    if (dir.empty()) return name;
    const char last = dir.back();
    if (last == '/' || last == '\\') return dir + name;
    return dir + "/" + name;
}

// 这里自带一份 base64 而不是复用 src/util.cpp：插件的构建目标（CMake 里的
// TUNNEL_SOURCES）只编插件自己的源文件，引用服务端的 util 会在 Windows 上变成
// 未解析的外部符号。十行代码换掉一个链接期隐患，值得。
std::string base64_encode(const std::string& in) {
    static const char* kAlphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((in.size() + 2) / 3) * 4);
    std::size_t i = 0;
    for (; i + 2 < in.size(); i += 3) {
        const std::uint32_t v = (static_cast<std::uint32_t>(in[i]) << 16) |
                                (static_cast<std::uint32_t>(in[i + 1]) << 8) |
                                static_cast<std::uint32_t>(in[i + 2]);
        out += kAlphabet[(v >> 18) & 0x3f];
        out += kAlphabet[(v >> 12) & 0x3f];
        out += kAlphabet[(v >> 6) & 0x3f];
        out += kAlphabet[v & 0x3f];
    }
    if (i + 1 == in.size()) {
        const std::uint32_t v = static_cast<std::uint32_t>(in[i]) << 16;
        out += kAlphabet[(v >> 18) & 0x3f];
        out += kAlphabet[(v >> 12) & 0x3f];
        out += '=';
        out += '=';
    } else if (i + 2 == in.size()) {
        const std::uint32_t v = (static_cast<std::uint32_t>(in[i]) << 16) |
                                (static_cast<std::uint32_t>(in[i + 1]) << 8);
        out += kAlphabet[(v >> 18) & 0x3f];
        out += kAlphabet[(v >> 12) & 0x3f];
        out += kAlphabet[(v >> 6) & 0x3f];
        out += '=';
    }
    return out;
}

std::string url_encode(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (char ch : in) {
        const unsigned char c = static_cast<unsigned char>(ch);
        const bool unreserved = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                                (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' ||
                                c == '~';
        if (unreserved) {
            out += ch;
            continue;
        }
        char buf[5];
        std::snprintf(buf, sizeof(buf), "%%%02X", static_cast<unsigned>(c));
        out += buf;
    }
    return out;
}

// netportable 要求每个用到 socket 的模块先 init（它内部计数，重复调用安全），
// 用 RAII 成对包一层，任何提前 return 都不会漏掉 shutdown。
struct NetGuard {
    bool ok = false;
    explicit NetGuard(std::string& error) { ok = net::init(error); }
    ~NetGuard() {
        if (ok) net::shutdown();
    }
    NetGuard(const NetGuard&) = delete;
    NetGuard& operator=(const NetGuard&) = delete;
};

// SSL_connect / SSL_read / SSL_write 在非阻塞句柄上会用 WANT_READ/WANT_WRITE
// 表示"还没好"。等哪一侧、等多久，交给 net::poll_fds；deadline 让反复重试收敛
// 到一个总超时，而不是每重试一次就把计时清零。
bool wait_for_socket(net::socket_t sock, short events, Clock::time_point deadline,
                     const char* what, std::string& error) {
    for (;;) {
        const auto now = Clock::now();
        if (now >= deadline) {
            error = std::string(what) + "超时";
            return false;
        }
        const long long remain =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        const int timeout_ms = remain < 1 ? 1 : static_cast<int>(remain);
        net::PollFd p{};
        p.fd = sock;
        p.events = events;
        const int ready = net::poll_fds(&p, 1, timeout_ms);
        if (ready < 0) {
            error = std::string(what) + "等待失败: " + net::error_string(net::last_error());
            return false;
        }
        if (ready == 0) continue;  // 超时统一由上面的 deadline 判定
        if ((p.revents & net::kInvalidFd) != 0) {
            error = std::string(what) + "句柄已失效";
            return false;
        }
        if ((p.revents & net::kErr) != 0) {
            error = std::string(what) + "socket 出错";
            return false;
        }
        if ((p.revents & events) != 0) return true;
        if ((p.revents & net::kHangup) != 0) {
            // 对端半关闭：读侧还要让 TLS 层把已经到达的数据和 EOF 自己判完；
            // 写侧则不可能再成功。
            if ((events & net::kRead) != 0) return true;
            error = std::string(what) + "对端已关闭";
            return false;
        }
    }
}

std::string last_openssl_error() {
    // 队列里可能堆了多条：只取第一条通常就是根因（后面多是级联）。
    const unsigned long code = ERR_get_error();
    if (code == 0) return "无详细信息";
    char buf[256];
    ERR_error_string_n(code, buf, sizeof(buf));
    return std::string(buf);
}

// 一次性的 TLS 连接：拨 TCP -> 校验证书地握手 -> 收发 -> 关闭。
// 只谈 HTTP/1.1，不做 keep-alive；我们每个请求本来就是一次独立的短连接。
class TlsSession {
 public:
    TlsSession() = default;
    ~TlsSession() {
        // 析构里做网络关闭（SSL_shutdown + close）对"连接还活着"的路径是多余的，
        // 但代价只有一次；这换来实现上不用在每个错误分支都记得 close。
        reset();
    }
    TlsSession(const TlsSession&) = delete;
    TlsSession& operator=(const TlsSession&) = delete;

    bool connect(const std::string& host, int timeout_ms, std::string& error);
    bool write_all(const std::string& data, int timeout_ms, std::string& error);
    bool read_all(std::string& out, int timeout_ms, std::string& error);
    void reset();

 private:
    net::socket_t sock_ = net::kInvalid;
    SSL_CTX* ctx_ = nullptr;
    SSL* ssl_ = nullptr;
};

bool TlsSession::connect(const std::string& host, int timeout_ms, std::string& error) {
    reset();
    if (!net::connect_tcp(host, kHttpsPort, timeout_ms, sock_, error)) {
        error = host + ":" + std::to_string(kHttpsPort) + " 连接失败: " + error;
        return false;
    }
    // connect_tcp 承诺给的就是非阻塞句柄，这里再确认一次：SSL 的 WANT_READ/WANT_WRITE
    // 分支必须有可轮询的句柄撑着，变成阻塞式就会把整条 supervise 线程卡死在读上。
    if (!net::set_nonblocking(sock_)) {
        error = "切换到非阻塞失败: " + net::error_string(net::last_error());
        reset();
        return false;
    }
    net::set_nodelay(sock_);
    const auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);

    ERR_clear_error();
    ctx_ = SSL_CTX_new(TLS_client_method());
    if (ctx_ == nullptr) {
        error = "SSL_CTX_new 失败: " + last_openssl_error();
        reset();
        return false;
    }
    // 证书必须按系统信任库校验：注册接口返回的是隧道凭据，来源不可信就等于
    // 把隧道送给别人。所以这里没有"校验失败就降级成不校验"的开关。
    SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);
#if defined(SSL_OP_IGNORE_UNEXPECTED_EOF)
    // 我们发的是 Connection: close，对端常常直接断开而不发 close_notify。
    // OpenSSL 3 把这种"未加 close_notify 的 EOF"当成致命错误，会让一份已经
    // 读全了的响应被判成读取失败；打开这个选项后它按正常 EOF 处理。真被截断
    // 的 body 会在 JSON 解析时报错，不会静默通过。
    SSL_CTX_set_options(ctx_, SSL_OP_IGNORE_UNEXPECTED_EOF);
#endif
    // 信任库分两步装。
    //
    // 第一步 set_default_verify_paths 走 OpenSSL 自己的默认位置（Linux 读
    // /etc/ssl/certs，MSYS2 读安装目录下的 ca-bundle）。它在 Linux 上够用。
    //
    // 第二步只在 Windows 上做：这个 OpenSSL 是 MSYS2 自带的，它看不到 Windows
    // 证书存储，而干净机器上往往没有 ca-bundle 文件。实测这种情况下握手直接
    // 报 "certificate verify failed"（0A000086），quick 隧道永远注册不上。
    // 所以把系统 ROOT 存储里的证书逐张塞进 ctx 的信任链。这是"信任库从哪来"
    // 的问题，不是"要不要校验"的问题 —— 校验仍然强制开启，没有任何降级开关。
    int loaded = 0;
    if (SSL_CTX_set_default_verify_paths(ctx_) == 1) loaded = 1;
#if defined(_WIN32)
    if (add_windows_root_store(ctx_)) loaded = 1;
#endif
    if (loaded == 0) {
        error = "加载系统 CA 信任库失败（没有它就无法校验服务端证书）: " + last_openssl_error();
        reset();
        return false;
    }
    // 明确只谈 HTTP/1.1：这两个接口都是普通 JSON，用不上 h2，省掉一条
    // "对方回了 h2 帧"的解析分支。
    static const unsigned char kAlpn[] = {'h', 't', 't', 'p', '/', '1', '.', '1'};
    (void)SSL_CTX_set_alpn_protos(ctx_, kAlpn, sizeof(kAlpn));

    ERR_clear_error();
    ssl_ = SSL_new(ctx_);
    if (ssl_ == nullptr) {
        error = "SSL_new 失败: " + last_openssl_error();
        reset();
        return false;
    }
    if (SSL_set1_host(ssl_, host.c_str()) != 1) {
        error = "设置证书主机名校验失败: " + last_openssl_error();
        reset();
        return false;
    }
    // 同一个 IP 上按 SNI 挑证书，缺了它握手会拿到错误的证书链。
    (void)SSL_set_tlsext_host_name(ssl_, host.c_str());

    // OpenSSL 的 SSL_set_fd 只认 int，而 netportable 的 socket_t 是 intptr_t。
    // 两个目标平台上真实句柄都落在 32 位范围内，但这个前提要显式成立：装不进
    // int 就报错，绝不悄悄截断成另一个句柄。SSL_set_fd 内部建的是 BIO_NOCLOSE
    // 的 socket BIO，所以句柄所有权仍归我们，统一由 net::close 关。
    if (sock_ > static_cast<net::socket_t>(INT_MAX)) {
        error = "socket 句柄超出 SSL_set_fd 的 int 范围";
        reset();
        return false;
    }
    if (SSL_set_fd(ssl_, static_cast<int>(sock_)) != 1) {
        error = "SSL_set_fd 失败: " + last_openssl_error();
        reset();
        return false;
    }

    ERR_clear_error();
    int ret = SSL_connect(ssl_);
    while (ret != 1) {
        const int err = SSL_get_error(ssl_, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            const short events = err == SSL_ERROR_WANT_READ ? net::kRead : net::kWrite;
            if (!wait_for_socket(sock_, events, deadline, "TLS 握手", error)) {
                reset();
                return false;
            }
            ERR_clear_error();
            ret = SSL_connect(ssl_);
            continue;
        }
        error = "TLS 握手失败: " + last_openssl_error();
        reset();
        return false;
    }
    const long verify = SSL_get_verify_result(ssl_);
    if (verify != X509_V_OK) {
        error = "服务端证书校验失败: " + std::string(X509_verify_cert_error_string(verify));
        reset();
        return false;
    }
    return true;
}

bool TlsSession::write_all(const std::string& data, int timeout_ms, std::string& error) {
    const auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
    std::size_t sent = 0;
    while (sent < data.size()) {
        ERR_clear_error();
        const int n = SSL_write(ssl_, data.data() + sent, static_cast<int>(data.size() - sent));
        if (n > 0) {
            sent += static_cast<std::size_t>(n);
            continue;
        }
        const int err = SSL_get_error(ssl_, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            const short events = err == SSL_ERROR_WANT_READ ? net::kRead : net::kWrite;
            if (!wait_for_socket(sock_, events, deadline, "发送请求", error)) return false;
            continue;
        }
        error = "发送请求失败: " + last_openssl_error();
        return false;
    }
    return true;
}

bool TlsSession::read_all(std::string& out, int timeout_ms, std::string& error) {
    const auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
    std::vector<char> buf(8192);
    for (;;) {
        ERR_clear_error();
        const int n = SSL_read(ssl_, buf.data(), static_cast<int>(buf.size()));
        if (n > 0) {
            out.append(buf.data(), static_cast<std::size_t>(n));
            if (out.size() > kMaxResponseBytes) {
                error = "响应超过上限 " + std::to_string(kMaxResponseBytes) + " 字节";
                return false;
            }
            continue;
        }
        const int err = SSL_get_error(ssl_, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            const short events = err == SSL_ERROR_WANT_READ ? net::kRead : net::kWrite;
            if (!wait_for_socket(sock_, events, deadline, "读取响应", error)) return false;
            continue;
        }
        // 我们发的是 Connection: close，所以"读完"有两个等价判据：对端发了
        // close_notify，或者直接断开（没有 close_notify 的 EOF 很常见）。
        if (err == SSL_ERROR_ZERO_RETURN) return true;
        if (err == SSL_ERROR_SYSCALL && n == 0) return true;
        error = "读取响应失败: " + last_openssl_error();
        return false;
    }
}

void TlsSession::reset() {
    if (ssl_ != nullptr) {
        // 非阻塞句柄上 SSL_shutdown 只会把 close_notify 推进缓冲，失败无所谓；
        // 不发它也能断开，所以这里不为它做等待。
        (void)SSL_shutdown(ssl_);
        SSL_free(ssl_);
        ssl_ = nullptr;
    }
    if (ctx_ != nullptr) {
        SSL_CTX_free(ctx_);
        ctx_ = nullptr;
    }
    if (sock_ != net::kInvalid) {
        net::close(sock_);
        sock_ = net::kInvalid;
    }
}

struct HttpResponse {
    int status = 0;
    std::string body;
};

bool decode_chunked(const std::string& in, std::string& out) {
    std::size_t pos = 0;
    for (;;) {
        const std::size_t eol = in.find("\r\n", pos);
        if (eol == std::string::npos) return false;
        std::string size_line = in.substr(pos, eol - pos);
        const std::size_t semi = size_line.find(';');
        if (semi != std::string::npos) size_line.resize(semi);
        size_line = trim(size_line);
        if (size_line.empty()) return false;
        // 自己解析十六进制，不用 std::strtoull。
        //
        // 两个原因：一是 glibc 2.38+ 会把它重定向到 __isoc23_strtoull，
        // 而插件是动态库、宿主的 libstdc++ 未必是同一代，符号对不上就整个加载失败；
        // 二是 strtoull 会默默接受前缀垃圾，本来也要先自己验一遍。
        unsigned long long len = 0;
        for (char c : size_line) {
            unsigned d = 0;
            if (c >= '0' && c <= '9') d = static_cast<unsigned>(c - '0');
            else if (c >= 'a' && c <= 'f') d = static_cast<unsigned>(c - 'a') + 10;
            else if (c >= 'A' && c <= 'F') d = static_cast<unsigned>(c - 'A') + 10;
            else return false;  // 不是十六进制数字，这个 chunk 头就是坏的
            // 长度字段最多 16 位十六进制；再长必然超出 size_t，直接判失败，
            // 免得在下面乘加时溢出。
            if (len > (0xFFFFFFFFFFFFFFFFULL - d) / 16) return false;
            len = len * 16 + d;
        }
        pos = eol + 2;
        if (len > in.size()) return false;  // 明显不可能的分块长度，顺带挡住溢出
        if (len == 0) return true;          // 末块
        if (pos + len > in.size()) return false;
        out.append(in, pos, static_cast<std::size_t>(len));
        pos += static_cast<std::size_t>(len);
        if (pos + 2 > in.size() || in.compare(pos, 2, "\r\n") != 0) return false;
        pos += 2;
    }
}

bool parse_http_response(const std::string& raw, HttpResponse& out, std::string& error) {
    const std::size_t head_end = raw.find("\r\n\r\n");
    if (head_end == std::string::npos) {
        error = "响应头不完整（没有空行结尾）";
        return false;
    }
    const std::string head = raw.substr(0, head_end);
    std::string payload = raw.substr(head_end + 4);

    std::size_t line_end = head.find("\r\n");
    if (line_end == std::string::npos) line_end = head.size();
    const std::string status_line = head.substr(0, line_end);
    const std::size_t sp1 = status_line.find(' ');
    if (sp1 == std::string::npos) {
        error = "响应状态行无法解析: " + status_line;
        return false;
    }
    std::size_t sp2 = status_line.find(' ', sp1 + 1);
    const std::string code_text =
        status_line.substr(sp1 + 1, (sp2 == std::string::npos ? status_line.size() : sp2) - sp1 - 1);
    const int status = std::atoi(code_text.c_str());
    if (status <= 0) {
        error = "响应状态行无法解析: " + status_line;
        return false;
    }
    out.status = status;

    bool chunked = false;
    long long content_length = -1;
    std::size_t pos = line_end;
    while (pos < head.size()) {
        std::size_t next = head.find("\r\n", pos);
        if (next == std::string::npos) next = head.size();
        const std::string line = head.substr(pos, next - pos);
        const std::size_t colon = line.find(':');
        if (colon != std::string::npos) {
            const std::string name = ascii_lower(trim(line.substr(0, colon)));
            const std::string value = trim(line.substr(colon + 1));
            if (name == "transfer-encoding" &&
                ascii_lower(value).find("chunked") != std::string::npos) {
                chunked = true;
            } else if (name == "content-length") {
                content_length = std::atoll(value.c_str());
            }
        }
        pos = next + 2;
    }

    if (chunked) {
        std::string decoded;
        if (!decode_chunked(payload, decoded)) {
            error = "分块响应无法解码";
            return false;
        }
        out.body = std::move(decoded);
        return true;
    }
    if (content_length >= 0 && static_cast<long long>(payload.size()) > content_length) {
        payload.resize(static_cast<std::size_t>(content_length));
    }
    out.body = std::move(payload);
    return true;
}

// 只覆盖本文件需要的形态：固定 443、Connection: close、响应整段读到 EOF 再解析。
// 不做连接复用：省掉一台状态机，出错时的"读到哪儿了"也只有一个判据。
bool https_request(const std::string& host, const std::string& target, const std::string& method,
                   const std::string& body,
                   const std::vector<std::pair<std::string, std::string>>& headers,
                   int timeout_ms, HttpResponse& out, std::string& error) {
    // 每个模块在用到 socket 前 init 一次，netportable 内部计数，和上层调用方的
    // 那次 init 会配对，不会互相抵消。
    std::string init_error;
    NetGuard net_guard(init_error);
    if (!net_guard.ok) {
        error = "socket 层初始化失败: " + init_error;
        return false;
    }

    TlsSession tls;
    if (!tls.connect(host, timeout_ms, error)) return false;

    std::string request;
    request.reserve(512);
    request += method + " " + target + " HTTP/1.1\r\n";
    request += "Host: " + host + "\r\n";
    for (const auto& h : headers) request += h.first + ": " + h.second + "\r\n";
    request += "Connection: close\r\n";
    if (!body.empty()) {
        request += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    }
    request += "\r\n";
    request += body;

    if (!tls.write_all(request, timeout_ms, error)) return false;

    std::string raw;
    if (!tls.read_all(raw, timeout_ms, error)) return false;
    return parse_http_response(raw, out, error);
}

// 状态码不是 200 时，把一小段响应体一起报出来：Cloudflare 的错误信息在 body 里，
// 只报 "HTTP 502" 让人完全无从判断是令牌问题还是出口问题。
std::string brief(const std::string& body) {
    constexpr std::size_t kMaxBrief = 200;
    if (body.size() <= kMaxBrief) return body;
    return body.substr(0, kMaxBrief) + "...";
}

// DoH 的三种结论必须区分：NXDOMAIN 是"确定不存在"，没问到是"我们不知道"。
// 把后者当成死人，会在出口抖动时把一条好隧道注销掉。
enum class DohAnswer { Records, NoSuchName, Unasked };

DohAnswer doh_query(const std::string& host, const char* type, int timeout_ms,
                    std::string& error) {
    const std::string target =
        "/dns-query?name=" + url_encode(host) + "&type=" + type;
    HttpResponse res;
    std::string net_error;
    if (!https_request("cloudflare-dns.com", target, "GET", std::string(),
                       {{"Accept", "application/dns-json"}}, timeout_ms, res, net_error)) {
        error = std::string("DoH(") + type + ") 没问到: " + net_error;
        return DohAnswer::Unasked;
    }
    if (res.status != 200) {
        error = std::string("DoH(") + type + ") 返回 HTTP " + std::to_string(res.status);
        return DohAnswer::Unasked;
    }
    jsonx::Json doc;
    if (!jsonx::parse(res.body, doc) || !doc.is_object()) {
        error = std::string("DoH(") + type + ") 返回的不是 JSON";
        return DohAnswer::Unasked;
    }
    // RFC 8484 的 Status 沿用 DNS RCODE：3 = NXDOMAIN。
    auto status = doc.find("Status");
    if (status != doc.end() && status->is_number() && status->is_integer() &&
        status->get<int>() == 3) {
        error = std::string("DoH(") + type + ") 返回 NXDOMAIN";
        return DohAnswer::NoSuchName;
    }
    // NOERROR + 空 Answer 只是"记录还没发布"，不是"没有这个域名"。
    auto answer = doc.find("Answer");
    if (answer != doc.end() && answer->is_array() && answer->size() > 0) {
        error.clear();
        return DohAnswer::Records;
    }
    error = std::string("DoH(") + type + ") 应答里没有记录";
    return DohAnswer::Unasked;
}

// 系统解析失败时 resolve_host 只给出 bool + 一句人话（netportable 的 error_string
// 会把 Windows 的 WSA 码和 POSIX 的 EAI 码各自翻成中文）。要区分"确定不存在"和
// "解析器故障"，只能看这句话里的关键标记。标记清单覆盖两个平台上
// "name not found" 的几种实际措辞；**WSANO_DATA（11004 / 名字存在但没有地址）
// 故意不算**，它和 DoH 的 NOERROR + 空 Answer 是同一种证据，而后者按"还没发布"
// 处理 —— 判错方向（把活域名判死）比判不出来危险得多。
bool looks_like_no_such_host(const std::string& message) {
    const std::string m = ascii_lower(message);
    static const char* kMarkers[] = {
        "no such host",                // glibc getaddrinfo 文本
        "unknown host",                // BSD/macOS 文本
        "name or service not known",   // 部分 POSIX 文本
        "nodename nor servname",       // macOS 文本
        "nxdomain",
        "主机名找不到",                // netportable 对 WSAHOST_NOT_FOUND 的翻译
        "主机名或服务名不存在",        // netportable 对 EAI_NONAME 的翻译
        "11001",                       // WSAHOST_NOT_FOUND
    };
    for (const char* marker : kMarkers) {
        if (m.find(marker) != std::string::npos) return true;
    }
    return false;
}

struct CachedRecord {
    std::string token;
    std::string hostname;
    // 上次写入时域名是否已经解析。只有明确记成 false 才值得再探一次；
    // 缺这个字段的老缓存按"可用"处理，免得一次升级就把隧道换掉。
    bool usable = true;
};

bool write_cache(const std::string& data_dir, const Credentials& cred, bool usable) {
    jsonx::Json doc;
    doc["token"] = cred.token;
    doc["hostname"] = cred.hostname;
    doc["usable"] = usable;
    doc["updated_at"] = static_cast<long long>(std::time(nullptr));
    std::ofstream file(join_path(data_dir, "tunnel-quick.json"), std::ios::trunc);
    if (!file) return false;
    file << doc.dump() << "\n";
    return static_cast<bool>(file);
}

// 读一次就把四个字段都拿到：调用方要同时判断"有没有凭据"和"域名当时解析没
// 解析"，分两次读文件既多一次 IO，也让两次读到的东西可能不是同一份。
bool read_cache(const std::string& data_dir, CachedRecord& out) {
    std::ifstream file(join_path(data_dir, "tunnel-quick.json"));
    if (!file) return false;
    std::string text((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    jsonx::Json doc;
    if (!jsonx::parse(text, doc) || !doc.is_object()) return false;
    out.token = jsonx::str(doc, "token");
    out.hostname = jsonx::str(doc, "hostname");
    out.usable = jsonx::boolean(doc, "usable", true);
    return !out.token.empty();
}

}  // namespace

bool hostname_resolves(const std::string& host, std::string& error) {
    error.clear();
    if (host.empty()) {
        error = "empty hostname";
        return false;
    }
    const std::string lower = ascii_lower(host);
    // 本机名、"*.localhost" 这类名字不可能出现在公共 DNS 里，拿去问 DoH 得到
    // 的 NXDOMAIN 没有任何意义，直接放行。
    if (lower == "localhost" || ends_with(lower, ".localhost")) return true;

    // DoH 与系统解析都要用 socket 层。https_request 内部虽然也会 init，但它在返回
    // 出这个分支时就 shutdown 了；如果只靠它，走到下面的 resolve_host 时进程可能
    // 已经没有 WSAStartup。所以在这儿开一层自己的 init/shutdown，把整段包住。
    std::string init_error;
    NetGuard net_guard(init_error);
    if (!net_guard.ok) {
        // 连问都问不出去：没有任何证据说这个名字死了，只能报"未证实"。
        error = "unverified (socket 层初始化失败: " + init_error + ")";
        return true;
    }

    int answered = 0;  // 至少返回了一条记录
    int nxdomain = 0;  // 明确说"没有这个域名"
    int asked = 0;     // 应答真的读到了的
    std::string first_probe_error;
    // A 和 AAAA 都要问：有的域名只有 AAAA，只问 A 会把它判成 NXDOMAIN。
    // 只有两族都 NXDOMAIN 才算死。
    for (const char* type : {"A", "AAAA"}) {
        std::string probe_error;
        const DohAnswer answer = doh_query(host, type, kDohTimeoutMs, probe_error);
        if (answer == DohAnswer::Unasked) {
            if (first_probe_error.empty()) first_probe_error = probe_error;
            continue;
        }
        ++asked;
        if (answer == DohAnswer::NoSuchName) {
            ++nxdomain;
            continue;
        }
        ++answered;
    }
    if (answered > 0) return true;
    if (asked > 0 && nxdomain == asked) {
        error = "NXDOMAIN (A 与 AAAA 都被 DoH 判为不存在)";
        return false;
    }

    // 走到这里说明 DoH 没给出结论（到不了 cloudflare-dns.com，或应答里只有空
    // Answer）。DoH 和注册接口是两台不同的主机，能注册不代表能问 DNS，所以
    // 退回系统解析。系统解析失败时，只有"确定不存在"才算死。
    union SockAddrBuffer {
        unsigned char bytes[128];  // 大于两边的 sockaddr_storage
        std::uint64_t alignment;
    };
    SockAddrBuffer addr{};
    int addr_len = static_cast<int>(sizeof(addr.bytes));
    int family = 0;
    std::string sys_error;
    if (net::resolve_host(host, kHttpsPort, &addr, addr_len, family, sys_error)) return true;
    if (looks_like_no_such_host(sys_error)) {
        error = "NXDOMAIN (系统解析器认为域名不存在)";
        return false;
    }
    // 没问到的证据同样是"不知道"，按可用放行，但把原因留在 error 里给调用方看。
    error = "unverified (DoH 未给出结论" +
            (first_probe_error.empty() ? std::string() : (": " + first_probe_error)) +
            "; 系统解析: " + sys_error + ")";
    return true;
}

bool hostname_usable(const std::string& host, int attempts, int delay_ms, std::string& error) {
    error.clear();
    if (host.empty()) {
        error = "empty hostname";
        return false;
    }
    if (attempts < 1) attempts = 1;
    for (int i = 0; i < attempts; ++i) {
        if (hostname_resolves(host, error)) return true;
        // 只有"确定不存在"值得等：新域名发布有延迟，实测刚注册的名字常常
        // NXDOMAIN 一到两分钟。其它失败原因在 hostname_resolves 里已经被判成
        // "未证实"（返回 true），走不到这里。
        if (error.find("NXDOMAIN") == std::string::npos) return true;
        if (i + 1 < attempts && delay_ms > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
        }
    }
    return false;
}

bool register_new(const std::string& data_dir, Credentials& out, std::string& error) {
    error.clear();
    HttpResponse res;
    std::string net_error;
    const std::vector<std::pair<std::string, std::string>> headers = {
        {"User-Agent", "cloudflared/2026.10.7"},
        {"Content-Type", "application/json"},
        {"Accept", "application/json"},
    };
    // 空 body 的 POST 就够：quick tunnel 不需要账号，Cloudflare 会直接发一套
    // 凭据回来。
    if (!https_request("api.trycloudflare.com", "/tunnel", "POST", "{}", headers,
                       kRegisterTimeoutMs, res, net_error)) {
        error = "quick tunnel 注册请求失败: " + net_error;
        return false;
    }
    if (res.status != 200) {
        error = "quick tunnel 注册返回 HTTP " + std::to_string(res.status) +
                (res.body.empty() ? std::string() : (": " + brief(res.body)));
        return false;
    }
    jsonx::Json doc;
    if (!jsonx::parse(res.body, doc) || !doc.is_object()) {
        error = "quick tunnel 注册返回了非预期 JSON: " + brief(res.body);
        return false;
    }
    auto result = doc.find("result");
    if (result == doc.end() || !result->is_object()) {
        error = "quick tunnel 注册结果缺少 result: " + brief(res.body);
        return false;
    }
    const std::string id = jsonx::str(*result, "id");
    const std::string account = jsonx::str(*result, "account_tag");
    const std::string secret = jsonx::str(*result, "secret");
    const std::string hostname = jsonx::str(*result, "hostname");
    if (id.empty() || account.empty() || secret.empty()) {
        error = "quick tunnel 凭据不完整（id/account_tag/secret 有缺失）";
        return false;
    }
    // hostname 是这次注册的全部意义所在，缺了它凭据拿到也用不了。
    if (hostname.empty()) {
        error = "quick tunnel 注册结果没有 hostname";
        return false;
    }

    // 连接令牌就是这三元组，和 dashboard 里复制出来的串同构，因此后面可以复用
    // 同一套 capnp 注册代码，不必为 quick tunnel 单开一条路径。
    jsonx::Json cred;
    cred["a"] = account;
    cred["t"] = id;
    cred["s"] = secret;
    out.token = base64_encode(cred.dump());
    out.hostname = hostname;

    // 这里只探一次、不重试：调用方（client）会在发布域名之前做那一次耐心的
    // 循环。探活结果决定的是"缓存里记不记 usable"，不是"注册成不成功" ——
    // 域名还没发布并不代表这次注册失败，隧道本身马上就要用起来。
    std::string probe_error;
    const bool usable = hostname_resolves(hostname, probe_error);

    if (!data_dir.empty()) {
        // 缓存写失败不值得让一次成功的注册作废：凭据在内存里已经有效，缓存只是
        // 下次启动（API 不可达时）的兜底。所以这里静默失败。
        (void)write_cache(data_dir, out, usable);
    }
    return true;
}

bool load_cached(const std::string& data_dir, Credentials& out) {
    if (data_dir.empty()) return false;
    CachedRecord cached;
    if (!read_cache(data_dir, cached)) return false;
    // 没有 hostname 的缓存对调用方毫无用处（它要拿域名去发布订阅），当成没有
    // 缓存处理，让上层去注册一个新的。刻意不返回"半个凭据"。
    if (cached.hostname.empty()) return false;
    // 上次明确记下"当时还没解析"的，再探一次：那份缓存很可能就是那 1-2 分钟
    // 的传播窗口里写的。只有探活确定失败才作废；探不到（DoH 到不了）不算死 ——
    // hostname_resolves 对"没问到"返回 true，所以这里不会误删。
    if (!cached.usable) {
        std::string probe_error;
        if (!hostname_resolves(cached.hostname, probe_error)) return false;
    }
    out.token = cached.token;
    out.hostname = cached.hostname;
    return true;
}

}  // namespace ct::quick
