#pragma once
// 主程序侧的隧道插件加载器。
//
// 为什么要这一层：隧道插件在运行时才存在 —— 可能压根没编译出来（没装 OpenSSL），
// 可能被杀毒软件拦下，可能版本不符。而主程序对外的承诺是"装好编译器就能用"，
// 所以这里的每一条失败路径都只能表达成"没有隧道"，不能表达成"程序坏了"：
// 失败只记进 reason_，供 /api/info 展示，主程序照常以纯局域网模式运行。
//
// 本层不包含 OpenSSL 头、不依赖任何第三方库，只用 util::exe_dir / join_path
// 和平台自己的动态库 API（Windows LoadLibraryA / POSIX dlopen）。
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>

#include "api.h"

namespace tunnel {

// 转发调用的失败码。0 是插件自己的"成功"，所以这里用负数，避免和它混。
inline constexpr int kNoPlugin = -1;     // 插件没加载（不是错误）
inline constexpr int kPluginThrew = -2;  // 跨边界抛了异常（插件自身有 bug）

// api.h 没给这些字面量默认值，但插件里要用；放在这里让主程序不必各抄一份。
inline constexpr const char* kDefaultEdgeHost = "region1.v2.argotunnel.com";
inline constexpr std::uint16_t kDefaultEdgePort = 7844;
inline constexpr const char* kDefaultEdgeSni = "h2.cftunnel.com";

// start() 的入参。token 留空 = quick 隧道（插件自己去申请 *.trycloudflare.com）。
struct Options {
    std::string token;
    std::string edgeHost = kDefaultEdgeHost;
    std::uint16_t edgePort = kDefaultEdgePort;
    std::string edgeSni = kDefaultEdgeSni;

    std::string originHost = "127.0.0.1";
    std::uint16_t originPort = 0;  // 0 由插件按惯例处理；建议填本机实际监听端口

    int connectTimeoutMs = 15000;
    int registerTimeoutMs = 20000;

    // quick 隧道凭据的落盘目录，留空则每次启动都重新申请（域名会变）。
    std::string dataDir;
};

// 宿主侧的状态副本。字段与 cochat_tunnel_status 一一对应，但不直接把插件结构体
// 摊给其它模块：谁想看隧道状态都不该顺带依赖 api.h 的内存布局。
struct Status {
    bool loaded = false;
    bool running = false;
    bool connected = false;
    bool registered = false;
    bool quick = false;
    std::uint64_t requestsServed = 0;

    std::string hostname;  // 公网域名（不含 https://）
    std::string location;
    std::string uuid;
    std::string error;

    std::string version;   // 插件自报的版本串

    // 可发布的公网地址 https://<hostname>；没有域名时是空串。
    std::string url() const;
};

// 日志：lvl 0=error 1=warn 2=info 3=debug。回调在插件自己的线程上被调用。
using LogFn = std::function<void(int lvl, const std::string& line)>;
using StatusFn = std::function<void(const Status& st)>;

// 供 /api/info 使用的 JSON 片段（单行）。hostname 为空时 url 为空串。
std::string to_json(const Status& st);

// 把 C 结构体的固定缓冲填满（超长截断、保证 NUL 结尾）。跨 DLL 边界只能传 POD，
// 这两支是唯一做 std::string -> char[N] 的地方，省得每个调用点各写一遍。
void truncate_to(char* dst, std::size_t cap, const std::string& src);

// 用 Options 填好一份 cochat_tunnel_config（补默认值、写 abi/struct_size）。
// 返回值是"哪些字段因超长被截断"的提示，空串表示没有截断。
std::string fill_config(const Options& opts, cochat_tunnel_config& cfg);

class Loader {
public:
    Loader() = default;
    ~Loader();
    Loader(const Loader&) = delete;
    Loader& operator=(const Loader&) = delete;

    // 探测并加载。失败**不是错误**：返回 false，原因记在 reason()，主程序照常运行。
    // 重复调用安全：已加载则直接返回 true。
    bool load(std::string& error);

    // 先 stop 再卸载。没加载时是空操作；卸载后可以再 load()。
    void unload();

    bool available() const;
    std::string reason() const;  // 不可用的原因（给人看的整句中文）
    std::string path() const;    // 实际加载到的库文件路径

    // 状态快照。未加载时 loaded=false、error 为 reason()，其余字段为空。
    Status status() const;
    std::string status_json() const;  // status() 的 JSON 形式

    // 注册回调。start() 之前调用即可；之后再改也安全（插件持有的是本对象指针）。
    // 回调里不要调 stop()：那是在插件线程上 join 它自己。
    void set_callbacks(LogFn log, StatusFn on_status);

    // 启动隧道。返回 0 成功。非 0 时 error 是原因。
    // 0 只代表"参数已校验、监督线程已起"，连接结果靠状态回调 / status()。
    int start(const Options& opts, std::string& error);
    void stop();

    // ---- 给对端文件用的直通（它们不是本类的成员，只能走公开入口）----------
    // 直接持锁访问插件：调用方必须是下面几个新模块自己编译进去的代码
    // （loader.cpp 的 free function / json.cpp），不会在插件回调里调用。
    // 刻意不返回裸函数指针：句柄失效的窗口只有本类知道。
    int call_start(const cochat_tunnel_config& cfg, cochat_tunnel_log_fn log,
                   cochat_tunnel_status_fn on_status, void* user, char* err,
                   std::size_t errlen);
    int call_status(cochat_tunnel_status* out);
    void call_set_log_level(int lvl);

private:
    // 持锁取一份接口指针，锁外再调插件：用锁只保护"指针本身"，不保护插件调用。
    const cochat_tunnel_api* api_snapshot() const;

    // 交接给插件的 user 指针：只能是本对象，两个静态蹦床靠它找回 Loader。
    static void log_trampoline(void* user, int lvl, const char* line);
    static void status_trampoline(void* user, const cochat_tunnel_status* st);


    void* handle_ = nullptr;            // HMODULE / dlopen 句柄
    const cochat_tunnel_api* api_ = nullptr;
    std::string path_;
    std::string reason_ = "未加载";
    std::string version_;

    mutable std::mutex mu_;    // 保护句柄 / 接口指针 / 路径 / 原因
    mutable std::mutex cbMu_;  // 保护回调对象与缓存快照

    LogFn log_;
    StatusFn onStatus_;
    Status cached_;

    // 注意：两个蹦床绝不碰 mu_ —— stop() 会持着 mu_ 去等插件线程退出，一碰就自锁。
};

}  // namespace tunnel
