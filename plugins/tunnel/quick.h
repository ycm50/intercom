#pragma once
// quick tunnel（无需 Cloudflare 账号的 ad-hoc 隧道）注册与主机名存活性探测。
//
// 注册：POST https://api.trycloudflare.com/tunnel，空 body，返回
//   {result:{id, account_tag, secret, hostname}}
// 把这三元组 base64 成和 dashboard 令牌同构的 {"a","t","s"} 串即可复用同一套连接代码。
//
// 为什么注册完还要探活：API 给了域名不代表 DNS 已经生效。实测新域名常常
// NXDOMAIN 一到两分钟。直接把没生效的域名写进配置并对外发布，等于给用户
// 一个 530 的死链。
#include <cstdint>
#include <string>

namespace ct::quick {

struct Credentials {
    std::string token;     // base64({"a","t","s"})
    std::string hostname;  // *.trycloudflare.com
};

// 是否在缓存里已经有一份还能用的凭据。
// reuse_cached: 上次运行的凭据；仅在 API 不可达时作为兜底使用，
// 否则每次进程重启都注册新隧道会让旧域名失联（边缘只为活着的连接路由）。
bool load_cached(const std::string& data_dir, Credentials& out);

// 申请一个新的 quick tunnel。成功时填 out 并写缓存（data_dir 为空则不写）。
bool register_new(const std::string& data_dir, Credentials& out, std::string& error);

// 域名是否解析（A 与 AAAA 都要问）。返回 false 时 error 里说明是 NXDOMAIN 还是没问到。
bool hostname_resolves(const std::string& host, std::string& error);

// 带重试的探活：新域名发布有延迟，"刚注册"不等于"死的"。
bool hostname_usable(const std::string& host, int attempts, int delay_ms, std::string& error);

}  // namespace ct::quick
