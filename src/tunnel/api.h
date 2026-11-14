#pragma once
// 隧道插件的 C ABI —— 主程序与动态库之间唯一的契约。
//
// 设计约束（每一条都有原因，改之前先想清楚）：
//   1. 纯 C、POD、固定缓冲：exe 与 DLL 各带一份静态 libstdc++，跨边界传
//      std::string / 异常 / std::function 会直接崩，所以一律用 char[] 与 int。
//   2. abi + struct_size 两个字段：以后加字段不必升 abi，只要老版本能靠
//      struct_size 判断"这个字段存在吗"；abi 只在语义破坏时才 +1。
//   3. 回调函数指针 + user 指针：插件不认识主程序的任何类型。
//   4. 唯一导出符号 cochat_tunnel_entry：其它符号全部隐藏，避免和主程序的
//      静态库符号撞车。
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define COCHAT_TUNNEL_ABI 1u

// ---- 配置 -----------------------------------------------------------------
typedef struct cochat_tunnel_config {
    uint32_t abi;            // 必须 == COCHAT_TUNNEL_ABI
    uint32_t struct_size;    // 本结构体字节数（sizeof），用于向后兼容

    // Cloudflare 命名隧道的连接令牌（dashboard 里那个 base64 串）。
    // 留空 = 自动申请 ad-hoc quick tunnel（*.trycloudflare.com）。
    char token[1024];

    char edge_host[128];     // 默认 region1.v2.argotunnel.com
    uint16_t edge_port;      // 默认 7844
    char edge_sni[128];      // 默认 h2.cftunnel.com

    char origin_host[64];    // 本地要转发的目标，默认 127.0.0.1
    uint16_t origin_port;    // 通常是服务自己的端口

    int connect_timeout_ms;  // 连边缘的超时，默认 15000
    int register_timeout_ms; // 注册超时，默认 20000

    char data_dir[512];      // quick tunnel 凭据缓存放这里
} cochat_tunnel_config;

// ---- 状态 -----------------------------------------------------------------
// 只写不读：主程序通过回调拿快照，不会跨边界持有这份内存。
typedef struct cochat_tunnel_status {
    uint32_t abi;
    uint32_t struct_size;

    int running;             // 监督线程在
    int connected;           // 边缘 TCP+TLS 已通
    int registered;          // registerConnection 已被接受
    int quick;               // 用的是 ad-hoc quick tunnel

    uint64_t requests_served;

    char hostname[256];      // 公网域名（不含 https://）
    char location[64];       // 边缘机房，如 lax13
    char uuid[64];           // 隧道 id
    char error[512];         // 最近一次失败原因
} cochat_tunnel_status;

// ---- 回调 -----------------------------------------------------------------
// 日志：lvl 0=error 1=warn 2=info 3=debug。line 以 NUL 结尾、不含换行。
typedef void (*cochat_tunnel_log_fn)(void* user, int lvl, const char* line);
// 状态变化：每次连接/注册/主机名变化/定期计数时推送。始终在插件自己的线程上调用。
typedef void (*cochat_tunnel_status_fn)(void* user, const cochat_tunnel_status* st);

// ---- 入口 -----------------------------------------------------------------
typedef struct cochat_tunnel_api {
    uint32_t abi;
    uint32_t struct_size;

    const char* (*version)(void);

    // 启动隧道。返回 0 成功；非 0 失败，err 里是原因（errlen 字节，含 NUL）。
    // 非阻塞：立刻返回，连接/注册在插件自己的监督线程里进行，进度靠回调。
    int (*start)(const cochat_tunnel_config* cfg, cochat_tunnel_log_fn log,
                 cochat_tunnel_status_fn on_status, void* user, char* err, size_t errlen);

    // 停止并等待监督线程退出。幂等：没启动也能调。
    void (*stop)(void);

    // 取当前状态快照。返回 0 成功。
    int (*status)(cochat_tunnel_status* out);

    // 日志级别（0..3）。默认 1。
    void (*set_log_level)(int lvl);
} cochat_tunnel_api;

// 动态库唯一导出的符号。abi 不匹配时返回 NULL（主程序据此判定"版本不符"）。
const cochat_tunnel_api* cochat_tunnel_entry(uint32_t abi);

#ifdef __cplusplus
}  // extern "C"
#endif
