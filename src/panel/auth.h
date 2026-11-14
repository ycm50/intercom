#pragma once
// 面板会话与鉴权。
//
// 面板和聊天服务共用同一个账号库（auth::Store），但登录方式不同：
// 聊天走 WebSocket 的自定义协议，面板走普通 HTTP + Cookie。
// 这里只提供"登录换令牌、令牌换身份、注销"这三件事，其它一概不管。
//
// 为什么令牌要落盘：运维重启服务后不该被踢下线。但落盘的是**令牌本身**，
// 不是密码也不含密码；文件权限收紧，泄露也只是一个会话窗口。
#include <cstdint>
#include <string>

namespace panel {

// Cookie 名与有效期（7 天）。改成别的名字会让浏览器里旧 Cookie 失联，
// 所以这两个值要写进注释、不要在别处另写一份。
inline constexpr const char* kCookieName = "chat_admin";
inline constexpr std::int64_t kSessionTtlSeconds = 7 * 24 * 3600;

struct Session {
    std::string token;  // 会话令牌（Cookie 值 / Bearer 值）
    std::string csrf;   // 与 token 绑定的 CSRF 令牌；写操作必须带上
    std::string user;   // 固定是 admin
    std::int64_t expires_at = 0;
};

// 建一个新会话并落盘。失败返回空 Session（token 为空）。
Session create_session(const std::string& data_dir, const std::string& user);

// 校验令牌。
//   require_csrf 为 true 时（即写操作），csrf 必须与令牌绑定的那半一致；
//   GET 请求传 false，避免前端为了读状态还得先拿 CSRF。
// 成功时 out_user 填账号名。令牌不存在/过期/CSRF 不符都返回 false。
bool check_session(const std::string& data_dir, const std::string& token, bool require_csrf,
                   const std::string& csrf, std::string& out_user, Session* out_session = nullptr);

// 取某个令牌绑定的 CSRF（令牌无效时返回空串）。给前端 GET /status 用。
std::string session_csrf(const std::string& data_dir, const std::string& token);

// 注销。幂等：不存在的令牌也返回 true。
void revoke_session(const std::string& data_dir, const std::string& token);

// 从请求里取令牌：优先 Cookie chat_admin，其次 Authorization: Bearer。
// 空串表示没有。
std::string token_from_request(const std::string& cookie_header,
                               const std::string& authorization_header);

}  // namespace panel
