// 最小 HTTP/2 服务端实现：TLS 客户端 + 服务端帧机 + HPACK + 流控。
//
// 方向性（对着真实边缘验证过）：
//   TCP/TLS 我们是客户端（拨 region*.v2.argotunnel.com:7844，SNI=h2.cftunnel.com，不设 ALPN）；
//   HTTP/2 我们是*服务端*（边缘先发前言和 SETTINGS，然后朝我们开 POST 流）。
// 所以这里的帧解析器站在服务端立场：入站是请求，出站是响应。
//
// 所有 socket 操作只走 netportable.h：本文件里没有一行 POSIX 专有调用，
// 也没有任何平台分支——可移植性全部由那一层负责。
#include "h2.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <atomic>
#include <chrono>
#include <climits>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace ct::h2 {

namespace {

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------

constexpr char kPreface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
constexpr std::size_t kPrefaceLen = 24;

enum : std::uint8_t {
    kFrameData = 0x0,
    kFrameHeaders = 0x1,
    kFramePriority = 0x2,
    kFrameRstStream = 0x3,
    kFrameSettings = 0x4,
    kFramePushPromise = 0x5,
    kFramePing = 0x6,
    kFrameGoAway = 0x7,
    kFrameWindowUpdate = 0x8,
    kFrameContinuation = 0x9,
};

enum : std::uint8_t {
    kFlagEndStream = 0x1,
    kFlagAck = 0x1,        // 与 END_STREAM 撞值：RST/SETTINGS/PING/GOAWAY 才有 ACK 语义
    kFlagEndHeaders = 0x4,
    kFlagPadded = 0x8,
    kFlagPriority = 0x20,
};

// SETTINGS 参数 id
enum : std::uint16_t {
    kSetHeaderTableSize = 0x1,
    kSetEnablePush = 0x2,
    kSetMaxConcurrentStreams = 0x3,
    kSetInitialWindowSize = 0x4,
    kSetMaxFrameSize = 0x5,
};

// 我们愿意收的最大帧。帧头里的长度字段是 24 位，理论最大 16 MB-1；
// 对端若声明一个远大于此的值又不遵守我们的 SETTINGS，直接分配那块内存会被打穿，
// 所以读帧前先卡一个上限。边缘实际用的是 16 KB 默认值。
constexpr std::size_t kMaxFramePayload = 4u * 1024 * 1024;

constexpr std::size_t kDataFrameMax = 16384;  // 对端 SETTINGS_MAX_FRAME_SIZE 的默认值

// 帧读到一半时的停滞预算。读“半个帧”卡住不代表对端慢——边缘会先发 PING/GOAWAY，
// 所以超过这个时间还没有任何字节进来就是死路，按连接不可用处理，交给监督循环重连。
constexpr int kFrameReadStallMs = 30000;

// 写侧的停滞预算。比读宽松：一次 flush 可能背着 32 KB 攒批数据，
// 但对端完全不读时同样不能无限等。
constexpr int kWriteStallMs = 30000;

// RFC 7540 s6.9.1：流控窗口是 31 位无符号量，任何一侧都不得越过 2^31-1。
constexpr std::int64_t kMaxWindow = 0x7FFFFFFF;

// 出站攒批阈值：控制帧立刻刷，DATA 攒到这么大再进一个 TLS 记录。
constexpr std::size_t kTxBatchBytes = 32 * 1024;

// 入站授信攒批阈值。每收到一个 DATA 就立刻回 WINDOW_UPDATE 会让连接级窗口
// 永远只有一帧的量（大文件下载退化成 16 KB/RTT），所以攒到 1 MB 再一次性还。
constexpr std::int64_t kRecvGrantAt = 1024 * 1024;

// 连接级接收窗口的上限。我们向上游一次性开放 4 MB 后，每次归还额度都会把窗口推高；
// 不设顶的话几小时的长连接会把窗口涨到 31 位天花板，之后 WINDOW_UPDATE 就没法再加，
// 再还额度就成了协议错误。降到 2 MB 再补，等价于"永远有额度、永远加得动"。
constexpr std::int64_t kRecvConnWindowCap = 2 * 1024 * 1024;

constexpr std::size_t kDynamicTableMax = 4096;  // RFC 7541 s4.2 默认值

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

void put_u32(std::vector<std::uint8_t>& v, std::uint32_t x) {
    v.push_back(static_cast<std::uint8_t>((x >> 24) & 0xFF));
    v.push_back(static_cast<std::uint8_t>((x >> 16) & 0xFF));
    v.push_back(static_cast<std::uint8_t>((x >> 8) & 0xFF));
    v.push_back(static_cast<std::uint8_t>(x & 0xFF));
}

std::uint32_t get_u32(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

// 帧类型名只用于追踪输出；越界时返回 "?"，不抛异常。
const char* frame_name(std::uint8_t type) {
    static const char* kNames[] = {"DATA", "HEADERS", "PRIORITY", "RST_STREAM", "SETTINGS",
                                   "PUSH", "PING",   "GOAWAY",    "WINDOW_UPDATE", "CONT"};
    return type < sizeof(kNames) / sizeof(kNames[0]) ? kNames[type] : "?";
}

std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

}  // namespace

// ---------------------------------------------------------------------------
// 追踪
// ---------------------------------------------------------------------------

bool trace_enabled() {
    // 函数内静态初始化由编译器保证只跑一次且线程安全，比手写"算过没有"的
    // 标志位少一处数据竞争。用环境变量而不是全局日志级别：这条连接可能同时
    // 被多个线程碰，生产者只想在自己需要时打开逐帧输出。
    static const bool on = [] {
        const char* v = std::getenv("COCHAT_TUNNEL_TRACE");
        return v && v[0] != '\0' && std::strcmp(v, "0") != 0;
    }();
    return on;
}

void trace(const char* fmt, ...) {
    if (!trace_enabled()) return;
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(stderr, fmt, ap);
    va_end(ap);
    std::fputc('\n', stderr);
    std::fflush(stderr);
}

// ---------------------------------------------------------------------------
// HPACK（RFC 7541）
// ---------------------------------------------------------------------------
// 解码侧要能吃下真实边缘发来的一切（静态表索引、带/不带增量索引的字面量、
// 动态表尺寸更新、huffman 字符串）；编码侧只需要产出我们自己要发的响应头，
// 因此只做"静态表名字索引 + 字面量"，不往动态表里塞东西——我们从不发两个
// 相同的头，增量索引只是给对端添解码负担和同步风险。

namespace {

// RFC 7541 附录 A 静态表，下标 0 对应协议索引 1。
struct StaticEntry {
    const char* name;
    const char* value;
};

const StaticEntry kStaticTable[61] = {
    {":authority", ""},
    {":method", "GET"},
    {":method", "POST"},
    {":path", "/"},
    {":path", "/index.html"},
    {":scheme", "http"},
    {":scheme", "https"},
    {":status", "200"},
    {":status", "204"},
    {":status", "206"},
    {":status", "304"},
    {":status", "400"},
    {":status", "404"},
    {":status", "500"},
    {"accept-charset", ""},
    {"accept-encoding", "gzip, deflate"},
    {"accept-language", ""},
    {"accept-ranges", ""},
    {"accept", ""},
    {"access-control-allow-origin", ""},
    {"age", ""},
    {"allow", ""},
    {"authorization", ""},
    {"cache-control", ""},
    {"content-disposition", ""},
    {"content-encoding", ""},
    {"content-language", ""},
    {"content-length", ""},
    {"content-location", ""},
    {"content-range", ""},
    {"content-type", ""},
    {"cookie", ""},
    {"date", ""},
    {"etag", ""},
    {"expect", ""},
    {"expires", ""},
    {"from", ""},
    {"host", ""},
    {"if-match", ""},
    {"if-modified-since", ""},
    {"if-none-match", ""},
    {"if-range", ""},
    {"if-unmodified-since", ""},
    {"last-modified", ""},
    {"link", ""},
    {"location", ""},
    {"max-forwards", ""},
    {"proxy-authenticate", ""},
    {"proxy-authorization", ""},
    {"range", ""},
    {"referer", ""},
    {"refresh", ""},
    {"retry-after", ""},
    {"server", ""},
    {"set-cookie", ""},
    {"strict-transport-security", ""},
    {"transfer-encoding", ""},
    {"user-agent", ""},
    {"vary", ""},
    {"via", ""},
    {"www-authenticate", ""},
};

// 这里只写"每个符号的码长"（RFC 7541 附录 B），码字由它推出。
//
// 为什么不直接抄一张 (code,bits) 表：HPACK 的码是规范给出的，而"给定码长的码字"
// 是按附录 B 的符号顺序做 canonical 分配得到的唯一结果（已验证：用这份码长推出的
// 码字与参考实现的表逐项相同）。只保留长度数组，表就小得多，也不会出现抄错码字
// 这种最难查的错误。
constexpr std::uint8_t kHuffLen[257] = {
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 6,  10, 10, 12, 13, 6,  8,  11, 10, 10, 8,  11, 8,  6,  6,  6,
    5,  5,  5,  6,  6,  6,  6,  6,  6,  6,  7,  8,  15, 6,  12, 10, 13, 6,  7,  7,  7,  7,  7,  7,
    7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  8,  7,  8,  13, 19, 13, 14, 6,
    15, 5,  6,  5,  6,  5,  6,  6,  6,  5,  7,  7,  6,  6,  6,  5,  6,  7,  6,  5,  5,  6,  7,  7,
    7,  7,  7,  15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22, 21, 20, 22, 22, 23, 23, 21,
    23, 22, 22, 23, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19, 21, 26, 27, 27, 26, 27, 24,
    21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26, 30};

constexpr int kHuffMaxLen = 30;

// 解码表。HPACK 的码字是按码长做 canonical 分配的，于是"同长度的码字"在符号序上
// 占据一段连续值：长度 l 的码字区间是 [first[l], first[l] + count[l])，落在这段里
// 的第 k 个值对应的符号就是 order[start[l] + k]。三张表因此够用，
// 不需要 30 层的前缀树，也不需要每解一个符号就扫一遍 257 项。
struct HuffTables {
    std::uint32_t first[kHuffMaxLen + 1];
    std::uint16_t count[kHuffMaxLen + 1];
    std::uint16_t start[kHuffMaxLen + 1];
    std::uint16_t order[257];

    HuffTables() {
        unsigned n[kHuffMaxLen + 1] = {0};
        for (int sym = 0; sym < 257; ++sym) ++n[kHuffLen[sym]];
        unsigned c = 0;
        for (int l = 1; l <= kHuffMaxLen; ++l) {
            c = (c + n[l - 1]) << 1;  // canonical：下一个长度从"上个长度的末码 +1"左移一位起
            first[l] = c;
            count[l] = static_cast<std::uint16_t>(n[l]);
        }
        unsigned cursor = 0;
        for (int l = 1; l <= kHuffMaxLen; ++l) {
            start[l] = static_cast<std::uint16_t>(cursor);
            cursor += n[l];
        }
        // order 把每个长度段里的符号按符号序排好。这里必须用另一个游标推进，
        // 不能就地改 start——start 是解码侧的索引基准，改了之后解出来全是乱码。
        unsigned fill[kHuffMaxLen + 1] = {0};
        for (int l = 1; l <= kHuffMaxLen; ++l) fill[l] = start[l];
        for (int sym = 0; sym < 257; ++sym) {
            order[fill[kHuffLen[sym]]++] = static_cast<std::uint16_t>(sym);
        }
    }
};

const HuffTables& huff_tables() {
    // 静态构造：码表是常量，多线程同时解码不能各算一遍。
    static const HuffTables t;
    return t;
}

}  // namespace

namespace {

// ---------------------------------------------------------------------------
// 整数 / 字符串原语
// ---------------------------------------------------------------------------

// RFC 7541 s5.1 前缀整数。解析失败（越界）时返回 false，调用方必须放弃整个块，
// 不能拿着半个值继续解——错位之后每个字节都会被当成新的表示。
bool read_prefix_int(const std::uint8_t* p, std::size_t len, std::size_t& pos, int prefixBits,
                     std::uint32_t& out) {
    if (pos >= len) return false;
    const std::uint32_t mask = (1u << prefixBits) - 1u;
    std::uint32_t v = p[pos] & mask;
    ++pos;
    if (v < mask) {
        out = v;
        return true;
    }
    // 用 64 位累加：把 (b & 0x7F) 直接左移 28 位在 32 位里就会绕回去，
    // 损坏的或刻意构造的块能借此构造出一个"看起来很合理"的越界索引。
    std::uint64_t acc = v;
    std::uint32_t shift = 0;
    while (pos < len) {
        const std::uint8_t b = p[pos++];
        acc += static_cast<std::uint64_t>(b & 0x7F) << shift;
        if (acc > 0xFFFFFFFFull) return false;
        if (!(b & 0x80)) {
            out = static_cast<std::uint32_t>(acc);
            return true;
        }
        shift += 7;
        if (shift > 35) return false;  // 再往后加就一定是垃圾
    }
    return false;
}

// huffman 解码。解码失败（过长的填充或没有以 EOS 前缀收尾）返回 false：
// 宁可丢掉一个头，也不能把垃圾字符串塞进 headers。
bool huffman_decode(const std::uint8_t* data, std::size_t len, std::string& out) {
    const auto& tab = huff_tables();
    // 打包器最多一次压进 30 位，于是"下一个码一定在最高 bits 位里"——不需要逐位
    // 重新对齐，也不需要每解出一个符号就回读一个字节。
    std::uint64_t acc = 0;  // 高 bits 位有效
    int bits = 0;
    out.clear();
    out.reserve(len * 2);
    std::size_t i = 0;
    for (;;) {
        // 补齐到"够长"：剩余字节不足时也继续，收尾只看填充是否合法。
        while (bits < kHuffMaxLen && i < len) {
            acc = (acc << 8) | static_cast<std::uint64_t>(data[i++]);
            bits += 8;
        }
        bool matched = false;
        for (int l = 1; l <= kHuffMaxLen && l <= bits; ++l) {
            if (tab.count[l] == 0) continue;
            const std::uint32_t top =
                static_cast<std::uint32_t>((acc >> (bits - l)) & ((1ull << l) - 1ull));
            const std::uint32_t base = tab.first[l];
            if (top >= base && top - base < tab.count[l]) {
                out.push_back(static_cast<char>(tab.order[tab.start[l] + (top - base)]));
                bits -= l;
                matched = true;
                break;
            }
        }
        if (!matched) {
            // 没有任何码能匹配：如果后面还有字节，说明这一块是坏的。
            if (i < len) return false;
            // 已经没有后续字节了，剩下的只能是 EOS 的填充位：必须是全 1，
            // 且长度不超过最长码（RFC 7541 s5.2）。
            if (bits > kHuffMaxLen) return false;
            if (bits > 0) {
                const std::uint64_t mask = (1ull << bits) - 1ull;
                if ((acc & mask) != mask) return false;
            }
            break;
        }
        if (bits == 0 && i >= len) break;
    }
    return true;
}

bool read_string(const std::uint8_t* p, std::size_t len, std::size_t& pos, std::string& out) {
    if (pos >= len) return false;
    const bool huffman = (p[pos] & 0x80) != 0;
    std::uint32_t n = 0;
    if (!read_prefix_int(p, len, pos, 7, n)) return false;
    // 长度超过剩余字节只可能是损坏的块；直接失败，不去做截断猜测。
    if (n > len - pos) return false;
    if (!huffman) {
        out.assign(reinterpret_cast<const char*>(p + pos), n);
    } else {
        if (!huffman_decode(p + pos, n, out)) return false;
    }
    pos += n;
    return true;
}

// ---------------------------------------------------------------------------
// 动态表（RFC 7541 s2.3.2 / s4）
// ---------------------------------------------------------------------------

struct HpackTable {
    std::vector<std::pair<std::string, std::string>> entries;  // entries[0] = 最新的
    std::int64_t used = 0;                                      // RFC 7541 s4.1 的字节占用
    std::int64_t limit = static_cast<std::int64_t>(kDynamicTableMax);

    void clear() {
        entries.clear();
        entries.shrink_to_fit();  // 不为一张空表留着几 MB 的容量
        used = 0;
    }

    void evict_to_limit() {
        while (used > limit && !entries.empty()) {
            used -= entry_size(entries.back().first, entries.back().second);
            entries.pop_back();
        }
        if (entries.size() > entries.capacity() / 4) {
            // 长连接里动态表会被反复推空再填满；容量不回收会让 vector 永远停在峰值。
            std::vector<std::pair<std::string, std::string>> compacted = entries;
            entries.swap(compacted);
        }
    }

    static std::int64_t entry_size(const std::string& n, const std::string& v) {
        return static_cast<std::int64_t>(n.size()) + static_cast<std::int64_t>(v.size()) + 32;
    }

    void insert(const std::string& n, const std::string& v) {
        const std::int64_t sz = entry_size(n, v);
        if (sz > limit) {
            // 单个条目就比表上限还大：规范要求既不插入，也把整表清空（s4.4）。
            clear();
            return;
        }
        entries.insert(entries.begin(), std::make_pair(n, v));
        used += sz;
        evict_to_limit();
    }

    const std::pair<std::string, std::string>* lookup(std::uint32_t idx) const {
        if (idx >= 1 && idx <= 61) return nullptr;  // 静态表由调用方处理
        const std::uint32_t d = idx - 62;
        if (d >= entries.size()) return nullptr;
        return &entries[d];
    }

    void set_limit(std::int64_t v) {
        limit = v;
        evict_to_limit();
    }
};

void put_header(std::map<std::string, std::string>& out, std::string name,
                 const std::string& value) {
    // 头名统一小写：HTTP/2 规定头名必须小写，但历史实现里有大写漏进来的，
    // 归一化之后调用方按 "content-length" 查就一定查得到。
    for (char& c : name) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    auto it = out.find(name);
    if (it == out.end()) {
        out.emplace(std::move(name), value);
        return;
    }
    // 同名多值（set-cookie、x-forwarded-for）按 HTTP/1 的观感合并成一行，
    // 不然调用方拿到的是一份被悄悄覆盖过的头。
    if (it->second != value) {
        it->second += ", ";
        it->second += value;
    }
}

bool hpack_decode_block(const std::uint8_t* p, std::size_t len, HpackTable& tab,
                       std::map<std::string, std::string>& out) {
    std::size_t pos = 0;
    bool ok = true;
    while (pos < len) {
        const std::uint8_t b = p[pos];
        if ((b & 0x80) != 0) {
            // 1xxxxxxx：静态表/动态表索引
            std::uint32_t idx = 0;
            if (!read_prefix_int(p, len, pos, 7, idx)) {
                ok = false;
                break;
            }
            if (idx == 0) continue;  // 规范里 0 非法，跳过而不是把后面全当索引
            if (idx <= 61) {
                put_header(out, kStaticTable[idx - 1].name, kStaticTable[idx - 1].value);
            } else {
                const auto* e = tab.lookup(idx);
                if (!e) {
                    ok = false;
                    break;
                }
                put_header(out, e->first, e->second);
            }
        } else if ((b & 0xC0) == 0x40) {
            // 01xxxxxx：带增量索引的字面量
            std::uint32_t idx = 0;
            if (!read_prefix_int(p, len, pos, 6, idx)) {
                ok = false;
                break;
            }
            std::string name;
            if (idx > 0) {
                if (idx <= 61) {
                    name = kStaticTable[idx - 1].name;
                } else {
                    const auto* e = tab.lookup(idx);
                    if (!e) {
                        ok = false;
                        break;
                    }
                    name = e->first;
                }
            } else if (!read_string(p, len, pos, name)) {
                ok = false;
                break;
            }
            std::string value;
            if (!read_string(p, len, pos, value)) {
                ok = false;
                break;
            }
            put_header(out, name, value);
            tab.insert(name, value);
        } else if ((b & 0xF0) == 0x00 || (b & 0xF0) == 0x10) {
            // 0000xxxx 不带索引 / 0001xxxx 从不索引：都不进动态表
            std::uint32_t idx = 0;
            if (!read_prefix_int(p, len, pos, 4, idx)) {
                ok = false;
                break;
            }
            std::string name;
            if (idx > 0) {
                if (idx <= 61) {
                    name = kStaticTable[idx - 1].name;
                } else {
                    const auto* e = tab.lookup(idx);
                    if (!e) {
                        ok = false;
                        break;
                    }
                    name = e->first;
                }
            } else if (!read_string(p, len, pos, name)) {
                ok = false;
                break;
            }
            std::string value;
            if (!read_string(p, len, pos, value)) {
                ok = false;
                break;
            }
            put_header(out, name, value);
        } else if ((b & 0xE0) == 0x20) {
            // 001xxxxx：动态表尺寸更新。对端可以把它降到任意值（包括 0）。
            std::uint32_t v = 0;
            if (!read_prefix_int(p, len, pos, 5, v)) {
                ok = false;
                break;
            }
            tab.set_limit(static_cast<std::int64_t>(v));
        } else {
            // 111xxxxx 是保留区，规范未定义；跳过 1 字节，避免整块失败。
            ++pos;
        }
    }
    return ok;
}

// ---------------------------------------------------------------------------
// 编码
// ---------------------------------------------------------------------------

int static_name_index(const std::string& name) {
    for (int i = 0; i < 61; ++i) {
        if (name == kStaticTable[i].name) return i + 1;
    }
    return 0;
}

void encode_int(std::vector<std::uint8_t>& out, std::uint32_t v, int prefixBits,
                std::uint8_t firstByte) {
    const std::uint32_t maxPrefix = (1u << prefixBits) - 1u;
    if (v < maxPrefix) {
        out.push_back(static_cast<std::uint8_t>(firstByte | static_cast<std::uint8_t>(v)));
        return;
    }
    out.push_back(static_cast<std::uint8_t>(firstByte | static_cast<std::uint8_t>(maxPrefix)));
    v -= maxPrefix;
    while (v >= 128) {
        out.push_back(static_cast<std::uint8_t>((v & 0x7F) | 0x80));
        v >>= 7;
    }
    out.push_back(static_cast<std::uint8_t>(v));
}

void encode_str_literal(std::vector<std::uint8_t>& out, const std::string& s) {
    encode_int(out, static_cast<std::uint32_t>(s.size()), 7, 0x00);
    out.insert(out.end(), s.begin(), s.end());
}

void encode_header(std::vector<std::uint8_t>& out, const std::string& name,
                   const std::string& value) {
    // 不走增量索引：我们的响应头每条都只发一次，进动态表只会让对端的表反复抖动，
    // 还把两个方向的 HPACK 状态耦合在一起（一处算错，整条连接全错）。
    const int idx = static_name_index(name);
    if (idx > 0) {
        encode_int(out, static_cast<std::uint32_t>(idx), 4, 0x00);
    } else {
        out.push_back(0x00);
        encode_str_literal(out, name);
    }
    encode_str_literal(out, value);
}

}  // namespace

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

namespace {

class ServerImpl;

// ---------------------------------------------------------------------------
// TLS 传输层
// ---------------------------------------------------------------------------
// 这一层的唯一职责是"把 SSL 的非阻塞语义翻译成 poll 驱动"，它不知道帧的存在。
//
// Windows 上的两个关键点：
//  1) SSL_set_fd 的参数是 int，而 net::socket_t 是 intptr_t。强转在两个方向上都危险：
//     SOCKET 是 UINT_PTR，64 位下内核分配的句柄值不保证落在 INT_MAX 以内，
//     截断之后的症状是"握手莫名失败"（还会被误判成网络问题）。
//     所以这里显式做长度比较，装不下就当场报错而不是硬转。之所以不绕道
//     BIO_new_socket + SSL_set_bio，是因为 BIO_new_socket 的参数同样收 int，
//     绕过去只是把同一个截断点挪了个位置，还多出一个要管理生命周期的 BIO。
//  2) 唤醒另一个线程里阻塞的 SSL_read 需要 shutdown(2) 语义，而可移植层只暴露
//     close()。这里用"取消标志 + net::close"来达成同样的效果：关掉 fd 之后
//     poll 会立刻返回错误，SSL_read 随之失败，阻塞线程在一个 poll 片内退出；
//     之后 close() 看到 fd_ == kInvalid 就不会再关第二次。
class TlsTransport {
public:
    TlsTransport() = default;
    ~TlsTransport() { close(); }
    TlsTransport(const TlsTransport&) = delete;
    TlsTransport& operator=(const TlsTransport&) = delete;

    bool connect(const std::string& host, std::uint16_t port, const std::string& sni,
                 int timeout_ms, const std::atomic<bool>& aborted, std::string& error);
    bool write_all(const void* data, std::size_t len);
    // 读满 len 字节。三态：1 = 读满，0 = 只是超时（连接还活着），-1 = 连接不可用。
    // SSL_read 返回 WANT 时只 poll 不"顺手再读一把"：那样探到的正是应用数据，
    // 丢掉它就是整条流错位。
    // first_ms 是"等第一个字节"的预算，stall_ms 是之后"两次读到数据之间"的预算。
    // 两个预算必须分开：帧读到一半卡住不代表对端还活着（边缘发 PING/GOAWAY
    // 远比这快），所以停滞即判死；而 poll() 的调用方要的是"这一段没数据"这个
    // 正常结果，绝不能把它当成故障去重连。
    int read_exact(void* buf, std::size_t len, int first_ms, int stall_ms);
    void note_abort_flag(const std::atomic<bool>* flag) { abortFlag_ = flag; }
    void close();
    // 唤醒另一线程里阻塞的读：关掉 fd 之后 poll 立刻报错、SSL_read 也跟着失败。
    // 只由 abort()/close() 调用，调用之后这条连接就彻底不可用了。
    void shutdown_socket();
    bool valid() const { return fd_ != net::kInvalid; }

    std::string fatal_reason;

private:
    int poll_with_deadline(int timeout_ms, short events) const;
    bool fail(std::string reason);

private:
    net::socket_t fd_ = net::kInvalid;
    SSL_CTX* ctx_ = nullptr;
    SSL* ssl_ = nullptr;
    bool fatal = false;
    // 指向 ServerImpl 的取消标志：不持有它，只读，避免两个对象互相引用。
    const std::atomic<bool>* abortFlag_ = nullptr;
};

bool TlsTransport::fail(std::string reason) {
    if (!fatal) {
        fatal = true;
        fatal_reason = std::move(reason);
    }
    return false;
}

// 等到 fd 可以读/写或者超时。
// 返回 1 = 就绪，0 = 超时，-1 = 出错或连接已经不可用。
int TlsTransport::poll_with_deadline(int timeout_ms, short events) const {
    if (fd_ == net::kInvalid) return -1;
    net::PollFd pfd{fd_, events, 0};
    const int pr = net::poll_fds(&pfd, 1, timeout_ms);
    if (pr == 0) return 0;
    if (pr < 0) return -1;
    if ((pfd.revents & (net::kErr | net::kInvalidFd)) != 0) return -1;
    // 挂断也算"有动静"：对端可能把数据发完才关，此时缓冲区里还有可读的内容，
    // 由 SSL_read 去判断是读到数据还是 EOF 才准确。
    if ((pfd.revents & (events | net::kHangup)) == 0) return 0;
    return 1;
}

bool TlsTransport::connect(const std::string& host, std::uint16_t port, const std::string& sni,
                           int timeout_ms, const std::atomic<bool>& aborted, std::string& error) {
    // TCP 由可移植层负责（非阻塞 connect + 截止时间 + 地址遍历）。
    if (!net::connect_tcp(host, port, timeout_ms, fd_, error)) {
        if (aborted.load()) error = "aborted";
        return false;
    }
    if (fd_ <= static_cast<net::socket_t>(INT_MAX)) {
        // 正常路径：句柄装得进 int，可以直接交给 SSL_set_fd（等价于 BIO_new_socket+SSL_set_bio）。
        if (!net::set_nonblocking(fd_)) {
            error = "cannot switch socket to non-blocking";
            close();
            return false;
        }
    } else {
        // 32 位平台理论上走不到这里（SOCKET 本身就是 32 位），纯属自证：宁可报错也不截断。
        error = "socket handle does not fit SSL_set_fd";
        close();
        return false;
    }

    ctx_ = SSL_CTX_new(TLS_client_method());
    if (!ctx_) {
        error = "SSL_CTX_new failed";
        close();
        return false;
    }
    // 明确要求 TLS1.2 以上：边缘只支持 1.2/1.3，放开更低版本只会给降级留口子。
    SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);
    // 故意不校验证书。这条连接只对"谁来连我们"有意义（对端是我们的隧道边缘），
    // 证书链验证在这里换不来额外安全性，却会把部署绑死在更新根证书上；
    // cloudflared 自己也是这么做的。剩下的身份确认由控制流上的 capnp 注册完成。
    SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, nullptr);
    // 不设 ALPN：边缘不协商协议，主动提 h2 只会让握手多一个可能不匹配的字段。
    SSL_CTX_set_mode(ctx_, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    ssl_ = SSL_new(ctx_);
    if (!ssl_) {
        error = "SSL_new failed";
        close();
        return false;
    }
    // 见类注释：句柄长度已在上面的分支里校验过，这里不会再发生截断。
    if (SSL_set_fd(ssl_, static_cast<int>(fd_)) != 1) {
        error = "SSL_set_fd failed";
        close();
        return false;
    }
    // SNI 必须设：边缘按 SNI 决定回哪张证书，不设的话握手直接失败。
    if (SSL_set_tlsext_host_name(ssl_, sni.c_str()) != 1) {
        error = "SSL_set_tlsext_host_name failed";
        close();
        return false;
    }

    // 握手本身也是非阻塞的：SSL_connect 返回 WANT_READ/WANT_WRITE 就 poll 再试，
    // 一次都不忙等。超时按绝对截止时间算，避免每次 WANT 都重新计时。
    const std::int64_t deadline = now_ms() + (timeout_ms > 0 ? timeout_ms : 15000);
    for (;;) {
        const int rc = SSL_connect(ssl_);
        if (rc == 1) return true;
        const int err = SSL_get_error(ssl_, rc);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            error = std::string("TLS handshake failed: ") +
                    ERR_error_string(ERR_get_error(), nullptr);
            close();
            return false;
        }
        if (aborted.load()) {
            error = "aborted";
            close();
            return false;
        }
        const int left = static_cast<int>(deadline - now_ms());
        if (left <= 0) {
            error = "TLS handshake timed out";
            close();
            return false;
        }
        const short ev = (err == SSL_ERROR_WANT_READ) ? net::kRead : net::kWrite;
        const int slice = left > 100 ? 100 : left;  // 100ms 一片，abort() 才能及时生效
        const int pr = poll_with_deadline(slice, ev);
        if (pr < 0) {
            error = "socket error during TLS handshake";
            close();
            return false;
        }
        // pr == 0：只是这一片超时，回到循环顶部重试（SSL_connect 会再判 WANT）。
    }
}

bool TlsTransport::write_all(const void* data, std::size_t len) {
    if (!ssl_ || fatal) return false;
    const std::uint8_t* p = static_cast<const std::uint8_t*>(data);
    std::size_t off = 0;
    // 写出也该有停滞预算：对端不读的时候 poll 会一直说"没就绪"，
    // 没有预算就是一条永远卡死的转发线程。
    std::int64_t deadline = now_ms() + kWriteStallMs;
    while (off < len) {
        // abort() 已经关掉了 fd：句柄号可能立刻被系统复用给别的 socket，
        // 再让 SSL 顺着它写就是把数据发到别人的连接上。每轮先看取消标志。
        if (abortFlag_ && abortFlag_->load()) {
            fail("aborted");
            return false;
        }
        const int n = SSL_write(ssl_, p + off, static_cast<int>(len - off));
        if (n > 0) {
            off += static_cast<std::size_t>(n);
            deadline = now_ms() + kWriteStallMs;
            continue;
        }
        const int err = SSL_get_error(ssl_, n);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            fail(err == SSL_ERROR_ZERO_RETURN ? "peer closed (tls write)"
                                              : "tls write failed");
            return false;
        }
        // 不能忙等：poll 到就绪再重试。100ms 一片是 abort() 的响应粒度。
        const std::int64_t left = deadline - now_ms();
        if (left <= 0) {
            fail("tls write stalled");
            return false;
        }
        const short ev = (err == SSL_ERROR_WANT_READ) ? net::kRead : net::kWrite;
        const int slice = left > 100 ? 100 : static_cast<int>(left);
        const int pr = poll_with_deadline(slice, ev);
        if (pr < 0) {
            fail("socket error while writing");
            return false;
        }
    }
    return true;
}

int TlsTransport::read_exact(void* buf, std::size_t len, int first_ms, int stall_ms) {
    if (!ssl_ || fatal) return -1;
    std::uint8_t* p = static_cast<std::uint8_t*>(buf);
    std::size_t off = 0;
    // 负的 first_ms 表示"不限时"（调用方已经在外层自己控超时）；
    // 0 表示"只探一下"——绝不能悄悄取成 1ms，否则每个 poll(0) 都会真的睡一下，
    // 中继循环一秒钟只能转几百圈。
    std::int64_t deadline = first_ms < 0 ? INT64_MAX : now_ms() + first_ms;
    while (off < len) {
        // 同上：取消之后绝不能再碰这个 SSL/fd 组合。
        if (abortFlag_ && abortFlag_->load()) {
            fail("aborted");
            return -1;
        }
        const int n = SSL_read(ssl_, p + off, static_cast<int>(len - off));
        if (n > 0) {
            off += static_cast<std::size_t>(n);
            // 一旦真读到东西，剩下的部分按"停滞预算"算：对端既然开了头，
            // 半个帧拖一辈子就是死路。
            deadline = now_ms() + (stall_ms > 0 ? stall_ms : kFrameReadStallMs);
            continue;
        }
        const int err = SSL_get_error(ssl_, n);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            fail(err == SSL_ERROR_ZERO_RETURN ? "peer closed (tls read)" : "tls read failed");
            return -1;
        }
        // 取消要能穿透进阻塞读：abort() 关掉 fd 后 poll 会立刻报错，
        // 这里再兜一层标志判断，免得刚好卡在两次 poll 之间。
        if (abortFlag_ && abortFlag_->load()) {
            fail("aborted");
            return -1;
        }
        const std::int64_t left = deadline - now_ms();
        if (left <= 0) {
            if (off == 0) return 0;  // 一个字节都没读到：只是没数据
            fail("tls read stalled");  // 读到一半没下文：这条连接废了
            return -1;
        }
        const short ev = (err == SSL_ERROR_WANT_READ) ? net::kRead : net::kWrite;
        const int slice = left > 100 ? 100 : static_cast<int>(left);
        const int pr = poll_with_deadline(slice, ev);
        if (pr < 0) {
            fail("socket error while reading");
            return -1;
        }
    }
    return 1;
}

void TlsTransport::shutdown_socket() {
    // 先立取消标志再关 socket：另一个线程可能正卡在 poll()/SSL_read 里，
    // 关掉 fd 之后它会在一个 poll 片内返回，然后看到 fatal 直接退出。
    //
    // 这里直接 net::close 而不是"半关"：netportable 只暴露 close()，而在
    // Windows 上 shutdown(SD_BOTH) 本就不保证能唤醒阻塞的 SSL_read（不同
    // CRT/SDK 行为不一致）。close 是唯一在两个平台上都能立刻让 poll 返回的动作。
    // 所有权仍然唯一：之后 SSL 不再被读写，close() 看到 fd_ == kInvalid
    // 就跳过二次关闭。
    fatal = true;
    if (fd_ != net::kInvalid) {
        net::close(fd_);
        fd_ = net::kInvalid;
    }
}

void TlsTransport::close() {
    // SSL_shutdown 只在连接还活着时才有意义：fd 已经被 abort() 关掉时再去
    // 发 close_notify 只会拿到一个 EWOULDBLOCK 的风控分支，白跑一轮。
    if (ssl_ && fd_ != net::kInvalid) SSL_shutdown(ssl_);
    if (ssl_) {
        SSL_free(ssl_);
        ssl_ = nullptr;
    }
    if (ctx_) {
        SSL_CTX_free(ctx_);
        ctx_ = nullptr;
    }
    if (fd_ != net::kInvalid) {
        net::close(fd_);
        fd_ = net::kInvalid;
    }
}

// ---------------------------------------------------------------------------
// 连接对象
// ---------------------------------------------------------------------------

class ServerImpl : public Server {
public:
    explicit ServerImpl(const Callbacks& cb) : cb_(cb) {}
    ~ServerImpl() override {
        // 析构里再兜一次：调用方可能忘了 close()（比如异常路径），
        // 让 fd 和 SSL 在这里必定被释放。
        close();
    }

    bool connect(const std::string& host, std::uint16_t port, const std::string& sni,
                 int timeout_ms, std::string& error) override;
    bool start_http2(int timeout_ms, std::string& error) override;
    bool poll(int timeout_ms) override;
    bool write_headers(std::uint32_t streamId, const std::string& status,
                       const std::vector<std::pair<std::string, std::string>>& extra,
                       bool end_stream) override;
    bool write_data(std::uint32_t streamId, const std::uint8_t* data, std::size_t len,
                    bool end_stream) override;
    std::size_t write_data_some(std::uint32_t streamId, const std::uint8_t* data, std::size_t len,
                                bool end_stream) override;
    bool send_credit_available(std::uint32_t streamId) override;
    std::size_t send_credit_bytes(std::uint32_t streamId) override;
    bool write_rst_stream(std::uint32_t streamId, std::uint32_t errorCode) override;
    void close() override;
    void abort() override;

private:
    // ---- 发送路径 ----//
    bool send_frame(std::uint8_t type, std::uint8_t flags, std::uint32_t streamId,
                    const std::uint8_t* payload, std::size_t len);
    bool flush_tx();

    // ---- 接收路径 ----//
    // 1 = 读到一个完整帧，0 = 超时，-1 = 连接不可用（对端关闭/TLS 出错）。
    // 三种状态必须分开：把"超时"和"死掉"混成一个 bool，会让对端悄然消失时
    // poll() 永远返回 true 并在上层空转。
    int read_frame(int timeout_ms, std::uint8_t& type, std::uint8_t& flags, std::uint32_t& streamId,
                   std::vector<std::uint8_t>& payload);
    void dispatch(std::uint8_t type, std::uint8_t flags, std::uint32_t streamId,
                  const std::uint8_t* payload, std::size_t len);
    void apply_settings(const std::uint8_t* payload, std::size_t len);
    void deliver_request(std::uint32_t streamId, std::uint8_t flags);
    void grant_recv_credit(std::uint32_t streamId, std::size_t len);
    // 一条流的发送结束后，把它的窗口记账收回去：这类小对象每条流各一份，
    // 一条活几天的连接如果不收，迟早会攒成几万个条目的两三个 map。
    void retire_stream(std::uint32_t streamId);
    // 记住"这条流不能再写"，并给集合一个规模上限。
    void remember_reset(std::uint32_t streamId);

    // ---- 流控 ----//
    std::int64_t* stream_send_window(std::uint32_t streamId) {
        auto it = sendWindow_.find(streamId);
        if (it == sendWindow_.end()) return nullptr;
        return &it->second;
    }
    void trace_credit_wait(std::uint32_t streamId, std::int64_t sw, std::size_t pending);

    // ---- 状态 ----//
    Callbacks cb_;
    TlsTransport tls_;
    HpackTable requestTable_;
    bool started_ = false;
    bool closed_ = false;
    // 本连接是否在"永远收不到新帧"的意义上死掉了。它横跨 poll()/write_*，
    // 让每个调用方都能看到"这条连接不能再用"，而不必去猜 errno。
    bool fatal_ = false;
    std::string fatalReason_;

    // 出站字节先攒在 tx_ 里。逐帧发的话每个 DATA 要两条 TLS 记录（9 字节帧头 + 载荷），
    // 大流量下 CPU 全烧在记录封装上；攒到 32 KB 再刷能省掉一大半。
    std::vector<std::uint8_t> tx_;

    // 入站帧的复用缓冲。每帧 new 一个 vector 就是每 16 KB 一次堆分配。
    std::vector<std::uint8_t> rx_;

    // ---- 流控状态（RFC 7540 s6.9）----//
    // 对端 SETTINGS 里的 INITIAL_WINDOW_SIZE 决定每条流的初始发送窗口，
    // 连接级窗口固定从 65535 起，只能靠 WINDOW_UPDATE 抬高。
    // 不记账就会在一次长下载里越过 64 KB，然后被边缘 RST 掉。
    std::int64_t connSendWindow_ = 65535;
    std::int64_t peerInitialWindow_ = 65535;
    std::map<std::uint32_t, std::int64_t> sendWindow_;
    // 我们已经消费掉、但还没还给对端的接收额度。
    std::int64_t recvConnWindow_ = 65535;
    std::int64_t recvConnCredit_ = 0;
    std::map<std::uint32_t, std::int64_t> recvStreamCredit_;
    // 被对端 RST 掉的流：之后再写 DATA 就是协议违规，整条连接会被拆掉。
    std::set<std::uint32_t> resetStreams_;
    // 限流日志：窗口关闭时每个中继循环都会走到这里，不限流能把磁盘写满。
    std::map<std::uint32_t, std::int64_t> creditWaitLast_;

    // ---- HEADERS 跨 CONTINUATION 组装 ----//
    std::uint32_t contStream_ = 0;
    std::vector<std::uint8_t> contBlock_;

    std::atomic<bool> aborted_{false};
};

// ---------------------------------------------------------------------------
// 帧发送
// ---------------------------------------------------------------------------

// 把一帧追加到发送缓冲。控制帧、以及带 END_STREAM 的 DATA 立刻刷出去：
// 对端正等着它们（SETTINGS/PING/WINDOW_UPDATE），或者流该尽快收尾；
// 纯数据帧才值得攒批。
bool ServerImpl::send_frame(std::uint8_t type, std::uint8_t flags, std::uint32_t streamId,
                            const std::uint8_t* payload, std::size_t len) {
    if (fatal_ || aborted_.load()) return false;
    trace("[h2 tx] %s flags=0x%02x stream=%u len=%zu", frame_name(type), flags, streamId, len);
    const std::size_t base = tx_.size();
    const std::size_t grow = 9 + (payload ? len : 0);
    // 一次 resize 再按下标写：逐字节 push_back 在 16 KB 的帧上要多做一次边界检查。
    tx_.resize(base + grow);
    std::uint8_t* dst = tx_.data() + base;
    dst[0] = static_cast<std::uint8_t>((len >> 16) & 0xFF);
    dst[1] = static_cast<std::uint8_t>((len >> 8) & 0xFF);
    dst[2] = static_cast<std::uint8_t>(len & 0xFF);
    dst[3] = type;
    dst[4] = flags;
    const std::uint32_t sid = streamId & 0x7FFFFFFFu;
    dst[5] = static_cast<std::uint8_t>((sid >> 24) & 0xFF);
    dst[6] = static_cast<std::uint8_t>((sid >> 16) & 0xFF);
    dst[7] = static_cast<std::uint8_t>((sid >> 8) & 0xFF);
    dst[8] = static_cast<std::uint8_t>(sid & 0xFF);
    if (payload && len) std::memcpy(dst + 9, payload, len);

    const bool urgent = (type != kFrameData) || (flags & kFlagEndStream) != 0;
    if (urgent || tx_.size() >= kTxBatchBytes) return flush_tx();
    return true;
}

bool ServerImpl::flush_tx() {
    if (tx_.empty()) return !fatal_;
    if (fatal_) {
        // 连接已经废了，句柄可能已被 abort() 关掉；继续 SSL_write 就是往野指针上写。
        tx_.clear();
        return false;
    }
    const bool ok = tls_.write_all(tx_.data(), tx_.size());
    tx_.clear();
    if (!ok) {
        fatal_ = true;
        if (fatalReason_.empty()) fatalReason_ = tls_.fatal_reason.empty() ? "tls write failed"
                                                                          : tls_.fatal_reason;
        if (cb_.on_error) cb_.on_error(fatalReason_);
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// 帧接收
// ---------------------------------------------------------------------------

int ServerImpl::read_frame(int timeout_ms, std::uint8_t& type, std::uint8_t& flags,
                           std::uint32_t& streamId, std::vector<std::uint8_t>& payload) {
    if (aborted_.load() || fatal_ || !tls_.valid()) return -1;
    // 帧头 9 字节 + 载荷必须按顺序整体读，不能"读到哪算哪"：
    // 半帧留在流里会让后续每一个帧的解释都错位。
    std::uint8_t hdr[9];
    // 帧头是"要不要继续等"的分界线：等不到就是超时（0），等到了却读不完整才判死。
    const int hr = tls_.read_exact(hdr, sizeof(hdr), timeout_ms, kFrameReadStallMs);
    if (hr == 0) return 0;
    if (hr < 0) {
        fatal_ = true;
        if (fatalReason_.empty())
            fatalReason_ = tls_.fatal_reason.empty() ? "peer closed" : tls_.fatal_reason;
        return -1;
    }
    const std::size_t len = (static_cast<std::size_t>(hdr[0]) << 16) |
                            (static_cast<std::size_t>(hdr[1]) << 8) |
                            static_cast<std::size_t>(hdr[2]);
    // 24 位长度字段最多 16 MB-1；先挡住荒谬的长度，否则一次畸形帧就是一次巨量分配。
    if (len > kMaxFramePayload) {
        fatal_ = true;
        fatalReason_ = "frame payload too large";
        if (cb_.on_error) cb_.on_error(fatalReason_);
        return -1;
    }
    type = hdr[3];
    flags = hdr[4];
    streamId = ((static_cast<std::uint32_t>(hdr[5]) << 24) |
                (static_cast<std::uint32_t>(hdr[6]) << 16) |
                (static_cast<std::uint32_t>(hdr[7]) << 8) | static_cast<std::uint32_t>(hdr[8])) &
               0x7FFFFFFFu;
    // 大小必须和本次帧的长度严格一致，不能只扩不缩：派发时调用方递的是
    // payload.size()，多出来的尾部会被当成这一帧的数据送出去（上一帧的残留）。
    // resize 缩小不释放容量，所以大帧仍然复用同一块缓冲，每 16 KB 一次堆分配的
    // 开销照样省掉了。
    if (payload.size() != len) payload.resize(len);
    if (len && tls_.read_exact(payload.data(), len, kFrameReadStallMs, kFrameReadStallMs) != 1) {
        fatal_ = true;
        if (fatalReason_.empty())
            fatalReason_ = tls_.fatal_reason.empty() ? "truncated frame" : tls_.fatal_reason;
        return -1;
    }
    trace("[h2 rx] %s flags=0x%02x stream=%u len=%zu", frame_name(type), flags, streamId, len);
    return 1;
}

void ServerImpl::apply_settings(const std::uint8_t* payload, std::size_t len) {
    // 每个条目 2 字节 id + 4 字节值。
    for (std::size_t off = 0; off + 6 <= len; off += 6) {
        const std::uint16_t id =
            static_cast<std::uint16_t>((static_cast<std::uint16_t>(payload[off]) << 8) |
                                       static_cast<std::uint16_t>(payload[off + 1]));
        const std::uint32_t v = get_u32(payload + off + 2);
        if (id == kSetInitialWindowSize) {
            const std::int64_t next = static_cast<std::int64_t>(v & 0x7FFFFFFFu);
            const std::int64_t delta = next - peerInitialWindow_;
            peerInitialWindow_ = next;
            // RFC 7540 s6.9.2：新的 INITIAL_WINDOW_SIZE 会按差值回溯调整每条已有流的
            // 发送窗口，结果允许是负数（此前已经花掉的额度比新窗口还多）。
            // 这里绝不能在 0 处夹一下——那等于凭空发额度，窗口记账一旦虚高，
            // 对端缓冲区会被我们撑爆，整条连接随之报废。
            for (auto& kv : sendWindow_) kv.second += delta;
            trace("[h2] peer INITIAL_WINDOW_SIZE=%lld (delta %lld)", static_cast<long long>(next),
                  static_cast<long long>(delta));
        } else if (id == kSetHeaderTableSize) {
            // 对端限制的是*我们发送时*的动态表。我们的编码器根本不往动态表里塞
            // 东西，所以这个值对我们只是信息。
            trace("[h2] peer HEADER_TABLE_SIZE=%u", v);
        } else if (id == kSetMaxFrameSize) {
            trace("[h2] peer MAX_FRAME_SIZE=%u", v);
        } else if (id == kSetMaxConcurrentStreams || id == kSetEnablePush) {
            trace("[h2] peer setting 0x%04x=%u", static_cast<unsigned>(id), v);
        }
    }
}

void ServerImpl::deliver_request(std::uint32_t streamId, std::uint8_t flags) {
    Request req;
    req.streamId = streamId;
    std::map<std::string, std::string> hdrs;
    if (!hpack_decode_block(contBlock_.data(), contBlock_.size(), requestTable_, hdrs)) {
        // 解不开的块不能拿去猜：一个错位的头表会让后面所有请求都跟着错。
        // 直接 RST 掉这条流，连接继续活着（边缘自己会重试）。
        trace("[h2] malformed header block on stream=%u", streamId);
        contBlock_.clear();
        contStream_ = 0;
        write_rst_stream(streamId, 1 /* PROTOCOL_ERROR */);
        if (cb_.on_error) cb_.on_error("malformed HPACK block");
        return;
    }
    contBlock_.clear();
    contStream_ = 0;
    auto it = hdrs.find(":method");
    if (it != hdrs.end()) req.method = it->second;
    it = hdrs.find(":path");
    if (it != hdrs.end()) req.path = it->second;
    req.headers = std::move(hdrs);
    // 第一次见到这条流时把发送窗口按对端的初始值建起来；
    // 之后再动它就是流控记账的事，不能在这里覆盖（可能已经花掉一部分）。
    sendWindow_.emplace(streamId, peerInitialWindow_);
    if (cb_.on_request) cb_.on_request(req);
    // HEADERS 自带 END_STREAM 表示"没有 body，请求到此为止"，
    // 之后的 DATA 也不会再来，所以这里就要通知结束。
    if ((flags & kFlagEndStream) != 0 && cb_.on_end) cb_.on_end(streamId);
}

void ServerImpl::grant_recv_credit(std::uint32_t streamId, std::size_t len) {
    if (len == 0) return;
    const std::int64_t n = static_cast<std::int64_t>(len);
    // 接收额度攒够 kRecvGrantAt 才一次性还回去。逐帧还的话连接级窗口永远只有一帧，
    // 大下载会退化成 16 KB/RTT，与 CPU 是否空闲无关。
    recvConnCredit_ += n;
    recvStreamCredit_[streamId] += n;

    // 我们看到的"还剩多少"必须先扣掉这一帧：不扣的话 recvConnWindow_ 只会单调
    // 上涨，一旦顶到上限就再也不还额度，对端的连接窗口被耗尽，整条连接从此卡死。
    recvConnWindow_ -= n;
    if (recvConnCredit_ >= kRecvGrantAt) {
        // 顶到上限就不再往上推，攒着的额度留给下一次（对端会因此早点停下，
        // 这正是我们想要的背压）。
        const std::int64_t room = kRecvConnWindowCap - recvConnWindow_;
        if (room > 0) {
            const std::int64_t grant = recvConnCredit_ < room ? recvConnCredit_ : room;
            std::vector<std::uint8_t> wu;
            put_u32(wu, static_cast<std::uint32_t>(grant));
            send_frame(kFrameWindowUpdate, 0, 0, wu.data(), wu.size());
            recvConnWindow_ += grant;
            recvConnCredit_ -= grant;
        }
    }
    auto it = recvStreamCredit_.find(streamId);
    if (it != recvStreamCredit_.end() && it->second >= kRecvGrantAt) {
        std::vector<std::uint8_t> wu;
        put_u32(wu, static_cast<std::uint32_t>(it->second));
        send_frame(kFrameWindowUpdate, 0, streamId, wu.data(), wu.size());
        it->second = 0;
    }
}

void ServerImpl::dispatch(std::uint8_t type, std::uint8_t flags, std::uint32_t streamId,
                          const std::uint8_t* payload, std::size_t len) {
    switch (type) {
        case kFrameSettings: {
            // 只有非 ACK 的 SETTINGS 需要应答；对端 ACK 我们的 SETTINGS 时
            // 再回一个 ACK 就是握手死循环。
            if ((flags & kFlagAck) == 0) {
                apply_settings(payload, len);
                send_frame(kFrameSettings, kFlagAck, 0, nullptr, 0);
            }
            break;
        }
        case kFrameHeaders: {
            std::size_t off = 0;
            // PADDING 长度字节 + 填充 + PRIORITY 的 5 字节都要跳过，
            // 跳掉的长度必须和载荷核对，越界的帧直接丢（不去读越界内存）。
            if ((flags & kFlagPadded) != 0) {
                if (len == 0) break;
                off += 1;
                if (payload[0] > len - off) break;
                off += payload[0];
            }
            if ((flags & kFlagPriority) != 0) {
                if (len - off < 5) break;
                off += 5;
            }
            if (off > len) break;
            // 一个头块可以合法地拆到多条 CONTINUATION 里；解前缀只会解出垃圾。
            // 必须整块攒齐再交给 HPACK。
            contStream_ = streamId;
            contBlock_.assign(payload + off, payload + len);
            if ((flags & kFlagEndHeaders) != 0) deliver_request(streamId, flags);
            break;
        }
        case kFrameContinuation: {
            // 不是我们正在拼的那条流：无视。混进来的 CONTINUATION
            // 属于协议错误，但为此拆掉整条连接不值得。
            if (streamId != contStream_ || contStream_ == 0) break;
            contBlock_.insert(contBlock_.end(), payload, payload + len);
            if ((flags & kFlagEndHeaders) != 0) deliver_request(streamId, flags);
            break;
        }
        case kFrameData: {
            // DATA 也可以带 PADDED：填充字节属于帧长、要计入流控，但绝不能
            // 当成正文字节交给上层（origin 会收到一串莫名其妙的 0）。
            std::size_t dataOff = 0;
            std::size_t dataLen = 0;
            if (len > 0) {
                dataLen = len;
                if ((flags & kFlagPadded) != 0) {
                    const std::size_t padLen = 1 + static_cast<std::size_t>(payload[0]);
                    // 填充长度比整帧还大说明帧已损坏：正文按空处理，
                    // 但流控额度仍然要还（对端已经把这帧算进窗口了）。
                    dataLen = (padLen <= len) ? len - padLen : 0;
                    dataOff = (dataLen > 0) ? padLen : 0;
                }
            }
            if (dataLen && cb_.on_data) cb_.on_data(streamId, payload + dataOff, dataLen);
            // 流控按帧长（含填充）结算，与正文多少无关。
            grant_recv_credit(streamId, len);
            if ((flags & kFlagEndStream) != 0) {
                // 请求侧收完了，这条流不会再有我们要还的额度；
                // 记账随手清掉，免得一条活几天的连接把它攒成内存泄漏。
                recvStreamCredit_.erase(streamId);
                if (cb_.on_end) cb_.on_end(streamId);
            }
            break;
        }
        case kFrameRstStream: {
            if (len >= 4) {
                trace("[h2] RST_STREAM stream=%u code=%u", streamId, get_u32(payload));
            }
            // 边缘放弃这条流了。务必记住：之后任何 DATA 都会被判协议违规，
            // 顺手把记账清掉，并让上层关掉 origin 侧。
            remember_reset(streamId);
            sendWindow_.erase(streamId);
            recvStreamCredit_.erase(streamId);
            creditWaitLast_.erase(streamId);
            if (cb_.on_reset) cb_.on_reset(streamId);
            break;
        }
        case kFrameWindowUpdate: {
            if (len < 4) break;
            const std::uint32_t inc = get_u32(payload) & 0x7FFFFFFFu;
            if (streamId == 0) {
                connSendWindow_ += static_cast<std::int64_t>(inc);
                if (connSendWindow_ > kMaxWindow) {
                    // 越过 31 位说明我们的记账出了错（额度被重复计入）。
                    // 继续用它只会按"我们以为的窗口"往对端灌数据，与其发垃圾
                    // 不如让监督循环重连。
                    fatal_ = true;
                    fatalReason_ = "connection window overflow";
                    if (cb_.on_error) cb_.on_error(fatalReason_);
                }
            } else {
                // 0 是合法状态（对端暂时没给额度），不能当成"没初始化"而把窗口
                // 重置成初始值——那等于凭空造出对端从未授予的额度。
                auto* sw = stream_send_window(streamId);
                if (!sw) {
                    sw = &sendWindow_.emplace(streamId, peerInitialWindow_).first->second;
                }
                *sw += static_cast<std::int64_t>(inc);
                if (*sw > kMaxWindow) {
                    fatal_ = true;
                    fatalReason_ = "stream window overflow";
                    if (cb_.on_error) cb_.on_error(fatalReason_);
                }
            }
            break;
        }
        case kFramePing: {
            if ((flags & kFlagAck) == 0) {
                // 回显原载荷是规范要求：对端用 ping 值做 RTT 测量。
                send_frame(kFramePing, kFlagAck, 0, payload, len);
            }
            break;
        }
        case kFrameGoAway: {
            // 边缘在退休这条连接，它不会再有新流。立刻标死，让监督循环重连，
            // 而不是等 socket 自己断（那可能要等几十秒）。
            fatal_ = true;
            fatalReason_ = "GOAWAY from edge";
            if (cb_.on_error) cb_.on_error(fatalReason_);
            break;
        }
        case kFramePriority:
        case kFramePushPromise:
        default:
            // 我们不用优先级（边缘也不依赖它），PUSH 我们是服务端不该收。
            break;
    }
}

// ---------------------------------------------------------------------------
// 连接建立与 HTTP/2 前言
// ---------------------------------------------------------------------------

bool ServerImpl::connect(const std::string& host, std::uint16_t port, const std::string& sni,
                         int timeout_ms, std::string& error) {
    if (aborted_.load()) {
        error = "aborted";
        return false;
    }
    // 可移植层要求每个模块在第一次用 socket 之前调用一次 net::init（Windows 上是
    // WSAStartup）。它是幂等的；这里刻意不配对调用 net::shutdown——进程里可能还有
    // 别的模块在用同一份网络层，把引用计数减下去会把它们的 socket 一起废掉。
    if (!net::init(error)) return false;
    tls_.note_abort_flag(&aborted_);
    if (!tls_.connect(host, port, sni, timeout_ms, aborted_, error)) {
        fatal_ = true;
        if (fatalReason_.empty()) fatalReason_ = error;
        return false;
    }
    return true;
}

bool ServerImpl::start_http2(int timeout_ms, std::string& error) {
    // 注意方向：我们是服务端，但*前言由边缘先发*——它和我们一样把自己当客户端拨了出来。
    // 所以这里要"读"前摇，读不到就说明连错了端点。
    std::uint8_t pre[kPrefaceLen];
    const int pr_ = tls_.read_exact(pre, kPrefaceLen, timeout_ms > 0 ? timeout_ms : 15000,
                                   kFrameReadStallMs);
    if (pr_ != 1) {
        error = tls_.fatal_reason.empty() ? "no HTTP/2 preface from edge" : tls_.fatal_reason;
        fatal_ = true;
        return false;
    }
    if (std::memcmp(pre, kPreface, kPrefaceLen) != 0) {
        error = "edge preface mismatch";
        fatal_ = true;
        fatalReason_ = error;
        return false;
    }

    // 我们作为服务端的 SETTINGS。
    std::vector<std::uint8_t> settings;
    // HEADER_TABLE_SIZE = 0：告诉边缘"别用动态表给我编码"，
    // 这从根上去掉了一整类"长连接上动态表不同步"的 bug。
    settings.push_back(0x00);
    settings.push_back(0x01);
    put_u32(settings, 0);
    // 我们允许的边缘并发流数量：边缘会把多个访客请求复用在这条连接上，
    // 给足额以免被它限流。
    settings.push_back(0x00);
    settings.push_back(0x03);
    put_u32(settings, 1000);
    // 每条流的接收窗口我们也开大：16 MB 足够让一个 SSE/WebSocket 在
    // 一次往返里拿到一大批数据。
    settings.push_back(0x00);
    settings.push_back(0x04);
    put_u32(settings, 16u * 1024u * 1024u);
    if (!send_frame(kFrameSettings, 0, 0, settings.data(), settings.size())) {
        error = "send SETTINGS failed";
        fatal_ = true;
        return false;
    }
    // 连接级窗口默认只有 65535，只能靠 WINDOW_UPDATE 抬。开局先抬到 4 MB，
    // 否则无论流窗口多大，整条连接都在等这一个往返。
    {
        std::vector<std::uint8_t> wu;
        put_u32(wu, 4u * 1024u * 1024u);
        if (!send_frame(kFrameWindowUpdate, 0, 0, wu.data(), wu.size())) {
            error = "send initial WINDOW_UPDATE failed";
            fatal_ = true;
            return false;
        }
        recvConnWindow_ += static_cast<std::int64_t>(4u * 1024u * 1024u);
    }

    // 吃掉边缘的 SETTINGS（里面可能有 INITIAL_WINDOW_SIZE，必须在我们发第一帧
    // DATA 之前生效），ACK 掉，然后才进入正常帧循环。
    const std::int64_t deadline = now_ms() + (timeout_ms > 0 ? timeout_ms : 15000);
    for (;;) {
        std::uint8_t type = 0;
        std::uint8_t flags = 0;
        std::uint32_t sid = 0;
        const int left = static_cast<int>(deadline - now_ms());
        if (left <= 0) {
            error = "no SETTINGS frame from edge";
            fatal_ = true;
            return false;
        }
        const int got = read_frame(left, type, flags, sid, rx_);
        if (got < 0) {
            error = fatalReason_.empty() ? "edge closed during HTTP/2 setup" : fatalReason_;
            return false;
        }
        if (got == 0) continue;  // 这一片超时，再看一次剩余时间
        dispatch(type, flags, sid, rx_.data(), rx_.size());
        if (fatal_) {
            error = fatalReason_;
            return false;
        }
        if (type == kFrameSettings && (flags & kFlagAck) == 0) break;
        // 其它帧（例如边缘提前发的 PING）也照常处理，继续等 SETTINGS。
    }
    if (!flush_tx()) {
        error = fatalReason_.empty() ? "flush failed" : fatalReason_;
        return false;
    }
    started_ = true;
    return true;
}

bool ServerImpl::poll(int timeout_ms) {
    if (aborted_.load() || fatal_) return false;
    // 上一轮中继攒在 tx_ 里的尾巴先推出去，否则它可能在这里躺满整个 poll 超时。
    if (!flush_tx()) return false;
    std::uint8_t type = 0;
    std::uint8_t flags = 0;
    std::uint32_t sid = 0;
    const int got = read_frame(timeout_ms, type, flags, sid, rx_);
    if (got < 0) {
        fatal_ = true;
        return false;
    }
    // got == 0 是"这一段没数据"，不是故障：调用方要能区分它和连接已死，
    // 否则对端悄然消失时这里会一直返回 true 让上层空转。
    if (got == 0) return !fatal_;
    dispatch(type, flags, sid, rx_.data(), rx_.size());
    if (!flush_tx()) return false;
    return !fatal_;
}

// ---------------------------------------------------------------------------
// 发送接口
// ---------------------------------------------------------------------------

bool ServerImpl::write_headers(std::uint32_t streamId, const std::string& status,
                               const std::vector<std::pair<std::string, std::string>>& extra,
                               bool end_stream) {
    if (!started_ || fatal_) return false;
    std::vector<std::uint8_t> block;
    // 静态表 8 是 (":status","200")，只有这个值能用索引形式；
    // 其它状态码必须走字面量，否则对端会解出错误的码。
    if (status == "200") {
        encode_int(block, 8, 7, 0x80);
    } else {
        encode_header(block, ":status", status);
    }
    for (const auto& kv : extra) {
        // 不对 content-length 做任何"修正"：调用方（relay）最清楚这条响应
        // 是不是长连接；给它补一个长度反而会毒化 WebSocket。
        encode_header(block, kv.first, kv.second);
    }
    const std::uint8_t fl =
        static_cast<std::uint8_t>(kFlagEndHeaders | (end_stream ? kFlagEndStream : 0));
    const bool ok = send_frame(kFrameHeaders, fl, streamId, block.data(), block.size());
    if (!ok) fatal_ = true;
    return ok;
}

bool ServerImpl::write_data(std::uint32_t streamId, const std::uint8_t* data, std::size_t len,
                            bool end_stream) {
    if (!started_ || fatal_) return false;
    if (resetStreams_.count(streamId)) return false;
    if (len == 0) {
        // 空载荷的 DATA 只承载 END_STREAM，不消耗任何窗口额度。
        const bool ok =
            send_frame(kFrameData, end_stream ? kFlagEndStream : 0, streamId, nullptr, 0);
        if (ok && end_stream) retire_stream(streamId);
        return ok;
    }
    const std::int64_t deadline = now_ms() + 30000;
    std::size_t off = 0;
    while (off < len) {
        auto* sw = stream_send_window(streamId);
        if (!sw) {
            sw = &sendWindow_.emplace(streamId, peerInitialWindow_).first->second;
        }
        if (connSendWindow_ <= 0 || *sw <= 0 || resetStreams_.count(streamId)) {
            // 没有额度只能等对端的 WINDOW_UPDATE，而它只有在我们继续读连接时才会到：
            // 所以这里必须一边 flush 一边读帧，而不是睡过去。
            if (!flush_tx()) return false;
            if (now_ms() >= deadline) {
                trace("[h2] send window unavailable on stream=%u (%zu/%zu sent)", streamId, off,
                      len);
                return false;
            }
            // 这里必须用独立的载荷缓冲：write_data 常常是在 on_data 回调里被
            // 调起来的，此时 rx_ 正被外层 dispatch 当作 DATA 载荷使用，复用它
            // 等于把调用方手上的指针就地重写。
            std::vector<std::uint8_t> waitPayload;
            std::uint8_t type = 0;
            std::uint8_t flags = 0;
            std::uint32_t sid = 0;
            const int got = read_frame(50, type, flags, sid, waitPayload);
            if (got < 0) return false;
            if (got == 0) {
                if (aborted_.load()) return false;
                continue;
            }
            dispatch(type, flags, sid, waitPayload.data(), waitPayload.size());
            if (fatal_ || resetStreams_.count(streamId)) return false;
            continue;
        }
        std::size_t n = len - off;
        if (n > kDataFrameMax) n = kDataFrameMax;
        if (static_cast<std::int64_t>(n) > *sw) n = static_cast<std::size_t>(*sw);
        if (static_cast<std::int64_t>(n) > connSendWindow_)
            n = static_cast<std::size_t>(connSendWindow_);
        if (n == 0) continue;  // 两个窗口都在边界上，回到循环顶部重新等
        const bool last = (off + n >= len);
        const std::uint8_t fl =
            static_cast<std::uint8_t>((last && end_stream) ? kFlagEndStream : 0);
        if (!send_frame(kFrameData, fl, streamId, data + off, n)) return false;
        off += n;
        *sw -= static_cast<std::int64_t>(n);
        connSendWindow_ -= static_cast<std::int64_t>(n);
        if (last && end_stream) retire_stream(streamId);
    }
    return flush_tx();
}

std::size_t ServerImpl::write_data_some(std::uint32_t streamId, const std::uint8_t* data,
                                        std::size_t len, bool end_stream) {
    if (!started_ || fatal_) return static_cast<std::size_t>(-1);
    // 边缘已经 RST 掉这条流：再往它上面写 DATA 是协议违规，
    // 边缘的反应是拆掉整条连接——长下载就会在随机位置"无声"断掉。
    if (resetStreams_.count(streamId)) return static_cast<std::size_t>(-1);
    if (len == 0) {
        if (!send_frame(kFrameData, end_stream ? kFlagEndStream : 0, streamId, nullptr, 0))
            return static_cast<std::size_t>(-1);
        if (end_stream) retire_stream(streamId);
        return 0;
    }
    auto* sw = stream_send_window(streamId);
    if (!sw) sw = &sendWindow_.emplace(streamId, peerInitialWindow_).first->second;
    if (connSendWindow_ <= 0 || *sw <= 0) {
        // 窗口关着的时候每个中继循环都会走到这里，因此这条日志必须限流：
        // 一次长下载能刷出几十万行。
        trace_credit_wait(streamId, *sw, len);
        return 0;  // 调用方保留剩余字节，下一轮再试
    }
    std::size_t n = len;
    if (n > kDataFrameMax) n = kDataFrameMax;
    if (static_cast<std::int64_t>(n) > *sw) n = static_cast<std::size_t>(*sw);
    if (static_cast<std::int64_t>(n) > connSendWindow_)
        n = static_cast<std::size_t>(connSendWindow_);
    if (n == 0) return 0;
    const bool last = (n >= len);
    const std::uint8_t fl = static_cast<std::uint8_t>((last && end_stream) ? kFlagEndStream : 0);
    if (!send_frame(kFrameData, fl, streamId, data, n)) return static_cast<std::size_t>(-1);
    *sw -= static_cast<std::int64_t>(n);
    connSendWindow_ -= static_cast<std::int64_t>(n);
    if (last && end_stream) retire_stream(streamId);
    return n;
}

void ServerImpl::trace_credit_wait(std::uint32_t streamId, std::int64_t sw, std::size_t pending) {
    if (!trace_enabled()) return;
    const std::int64_t now = now_ms();
    auto it = creditWaitLast_.find(streamId);
    if (it != creditWaitLast_.end() && now - it->second < 1000) return;
    creditWaitLast_[streamId] = now;
    trace("[h2] waiting for credit stream=%u conn=%lld sw=%lld pending=%zu", streamId,
          static_cast<long long>(connSendWindow_), static_cast<long long>(sw), pending);
}

bool ServerImpl::send_credit_available(std::uint32_t streamId) {
    if (fatal_ || connSendWindow_ <= 0) return false;
    const auto* sw = stream_send_window(streamId);
    // 还没登记过的流：第一次写入会按对端初始值建窗口，按"有额度"回答，
    // 否则调用方永远等不到第一次写。
    return sw ? *sw > 0 : true;
}

std::size_t ServerImpl::send_credit_bytes(std::uint32_t streamId) {
    if (fatal_ || connSendWindow_ <= 0) return 0;
    const auto* sw = stream_send_window(streamId);
    const std::int64_t streamWindow = sw ? *sw : peerInitialWindow_;
    if (streamWindow <= 0) return 0;
    const std::int64_t credit = streamWindow < connSendWindow_ ? streamWindow : connSendWindow_;
    return static_cast<std::size_t>(credit);
}

void ServerImpl::retire_stream(std::uint32_t streamId) {
    sendWindow_.erase(streamId);
    recvStreamCredit_.erase(streamId);
    creditWaitLast_.erase(streamId);
    // 也记进"不可再写"的集合：END_STREAM/RST 之后对这条流再写 DATA 就是协议违规，
    // 而中继线程手里可能还攥着那批字节。不记的话下一轮 write_data_some 会
    // 重新把窗口建起来照写不误，边缘的反应是拆掉整条连接。
    remember_reset(streamId);
}

void ServerImpl::remember_reset(std::uint32_t streamId) {
    resetStreams_.insert(streamId);
    // 流 id 单调递增、旧流永不复活，所以只需保留最近若干个。一条活几天的连接上
    // 被取消的请求成千上万，无上限地记下去就是内存泄漏。
    while (resetStreams_.size() > 4096) resetStreams_.erase(resetStreams_.begin());
}

bool ServerImpl::write_rst_stream(std::uint32_t streamId, std::uint32_t errorCode) {
    retire_stream(streamId);
    std::vector<std::uint8_t> payload;
    put_u32(payload, errorCode);
    return send_frame(kFrameRstStream, 0, streamId, payload.data(), payload.size());
}

void ServerImpl::abort() {
    // 顺序很重要：先立标志，再关 socket。另一个线程正卡在 poll()/SSL_read 里，
    // 它一旦返回就会看到 aborted_ 并退出，而不是把"连接被关"当成边缘挂掉去重连。
    aborted_.store(true);
    fatal_ = true;
    if (fatalReason_.empty()) fatalReason_ = "aborted";
    tls_.shutdown_socket();
}

void ServerImpl::close() {
    // 幂等：监督循环会显式 close 一次，紧接着析构又跑一次；
    // 第二次释放就是二次释放（可能顺手关掉一个复用了该句柄的无关 socket）。
    if (closed_) return;
    closed_ = true;
    tls_.close();
}

}  // namespace

// ---------------------------------------------------------------------------
// 对外入口
// ---------------------------------------------------------------------------

Server* Server::create(const Callbacks& cb) { return new ServerImpl(cb); }

// 独立的 HPACK 解码入口，只给诊断/测试用：它刻意不复用长连接那份动态表，
// 因为一旦共用，一次调试解码就会把真实解码的表推歪，两边再也对不上。
void decode_hpack(const std::uint8_t* block, std::size_t len,
                  std::map<std::string, std::string>& out) {
    static std::mutex mu;
    static HpackTable tab;
    std::lock_guard<std::mutex> lk(mu);
    hpack_decode_block(block, len, tab, out);
}

}  // namespace ct::h2
