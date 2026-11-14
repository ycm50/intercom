#pragma once
// 内建 TURN 凭证签发。
//
// 为什么需要：WebRTC 只有在双方 NAT 都允许直连时才能点对点。两台手机各自在
// 移动网络后面（对称 NAT）时，STUN 拿到的地址根本连不上，媒体就永远建不起来。
// 这时只能让服务器把音视频原样中转 —— 那就是 TURN。
//
// 为什么不自建 coturn：TURN 要求客户端直连服务器的 UDP 端口，而本项目部署在国内
// 机器上，持续的大流量 UDP 很容易被中间设备限速或阻断；一旦被断，连隧道一起就
// 没得用了。Cloudflare 的 TURN 走的是和隧道同一套边缘网络，国内手机也能连，
// 且不需要本机承担带宽。
//
// 凭证怎么来的：Cloudflare 要求用 Realtime 的 Key ID + API Token 去换一份有时效
// 的 STUN/TURN 账号密码。这个换取动作必须由服务端做 —— 把长期 API Token 下发到
// 浏览器等于把它公开。
#include <string>
#include <vector>

namespace turn {

struct IceServer {
    std::vector<std::string> urls;
    std::string username;
    std::string credential;
};

// 任何一项为空都表示没有配置 TURN，此时照旧只发 STUN。
struct Config {
    std::string key_id;
    std::string api_token;
    int ttl_seconds = 86400;
};

// 从 <data_dir>/turn.json 读配置，读不到再看环境变量 CLOUDFLARE_TURN_KEY_ID /
// CLOUDFLARE_TURN_API_TOKEN。两者都没有时返回 false —— 这是正常状态，不是错误。
bool load_config(const std::string &data_dir, Config &out, std::string &error);

// 向 Cloudflare 换一份临时凭证，缓存到过期前 5 分钟。
// 失败时返回 false；调用方应当降级为只用 STUN，而不是让整个通话失败。
bool fetch_credentials(const Config &cfg, std::vector<IceServer> &out, std::string &error);

std::string ice_servers_json(const std::vector<IceServer> &servers);

// ---- 给管理面板用 ----------------------------------------------------------
//
// 只回显"设置了没有"，绝不回显值：API Token 是长期密钥，进了浏览器就等于泄露。
// 面板只能看到 key_id 的前 4 位 + 是否已配置，足以判断"配没配对"。
std::string status_json(const std::string &data_dir);

// 保存配置。key_id 或 api_token 传空表示"这一项保持原样"，方便只改其中一项。
// 写入后立即让缓存失效，下一次 /api/info 就会用新凭证去换。
bool save_config(const std::string &data_dir, const std::string &key_id,
                 const std::string &api_token, int ttl, std::string &error);

// 删掉配置文件，回到"只用 STUN"。
bool clear_config(const std::string &data_dir, std::string &error);

// 让已缓存的凭证失效（配置变化后必须调，否则还会继续发旧的）。
void invalidate_cache();

}  // namespace turn