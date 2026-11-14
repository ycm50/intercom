// 管理面板的 HTTP 路由表 —— panel::register_routes 的唯一实现。
//
// 设计要点（改之前先读）：
//   1. 面板和聊天服务共用一个 httplib::Server，只挂在 /admin 前缀下：访问控制
//      （仅回环 / 仅隧道来源）、CSP、超时、默认头全部由主程序那一层继承，
//      这里不造第二套监听，也不重复实现"谁能连进来"的判定。
//   2. 面板只有一页。HTML / CSS / JS 全部由 ui.cpp 内嵌的字符串直接吐出，不走
//      文件系统：现场经常只拷一个可执行文件过去，"缺 public 目录就打不开面板"
//      是纯自找的故障。register_routes 的 public_dir 参数按契约保留，但这里
//      故意不读它 —— 一条"磁盘优先"的分支就够制造"我改的那份为什么不生效"，
//      而面板改外观的频率是几年一次。
//   3. 统一响应形状：成功 {"ok":true,...}，失败 {"ok":false,"error":"人话原因"}。
//      形状集中在本文件的两个助手函数里 —— 字段名一旦写岔（"success" / "msg"），
//      前端只会静默当成成功，没有任何报错线索。
//   4. 所有写接口先鉴权（会话 + CSRF）再动作；未登录一律 401 + JSON，不抛异常。
//      抛出去只会被主程序的异常处理器翻成一段纯文本 500，前端拿到非 JSON 之后
//      除了一句"请求失败"什么也说不出来。
#include "routes.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "../../third_party/httplib.h"
#include "../util.h"
#include "auth.h"   // 面板会话（同目录的 panel/auth.h，不是 ../auth.h）
#include "panel.h"
#include "ui.h"

// 文件级别名而不是在每个命名空间里再写一遍 jsonx::: jsonx:: 只出现在这里
// 和 routes.h 的声明处，两处指的是同一个类型，不会因为写法不同而对不上。
using jsonx::Json;

namespace panel {
namespace routes {

Json ok_reply(Json payload) {
  Json out = Json::object();
  // 只搬顶层字段：面板的约定就是"扁平对象 + ok"，嵌套子结构（info / stats /
  // tunnel）各自成块，不在这一层做递归展开。
  if (payload.is_object()) {
    for (auto it = payload.begin(); it != payload.end(); ++it) out[it.key()] = *it;
  }
  // "ok" 最后写入：调用方即使误传同名字段，也改不出一条"失败的成功响应"。
  out["ok"] = true;
  return out;
}

Json error_reply(const std::string &error) {
  Json out = Json::object();
  out["ok"] = false;
  out["error"] = error.empty() ? std::string("未知错误") : error;
  return out;
}

}  // namespace routes

namespace {

using jsonx::Json;

// 保留名 admin 的拒绝文案。新增 / 删除 / 改名三处共用同一句话：这三种操作对
// admin 的后果不同，但"为什么不行"是同一个理由，换着说法只会让运维以为遇到
// 了三个不同的限制，然后逐个去试。
constexpr const char *kReservedMsg = "面板账号固定为 admin，不可增删改";

// 登录失败统一文案。账号不存在与密码错误必须说同一句话，否则 401 的响应体
// 就成了一个"这台机器上有没有 admin"的探测接口。
constexpr const char *kBadCredentialMsg = "用户名或密码错误";

/* ------------------------------ 响应与鉴权 ------------------------------ */

void reply_json(httplib::Response &res, int status, const Json &body) {
  res.status = status;
  // 面板里的每个数字都来自"此刻的进程"：任何一层缓存都只会显示陈旧状态，
  // 而运维看的就是这一屏数字决定要不要重启。
  res.set_header("Cache-Control", "no-store");
  res.set_content(jsonx::dump(body), "application/json; charset=utf-8");
}

void reply_error(httplib::Response &res, int status, const std::string &msg) {
  reply_json(res, status, routes::error_reply(msg));
}

// 成功响应。payload 里一般是回调给的那句话（message）或某个子结构；
// 按值传是为了把临时 Json 移动进去，省掉一次深拷贝。
void reply_ok(httplib::Response &res, Json payload = Json()) {
  reply_json(res, 200, routes::ok_reply(std::move(payload)));
}

// 宿主回调可能没接线（例如主程序没实现"重启实例"）。统一回 503 + 说明，
// 而不是在回调里解引用空的 std::function —— 那种崩溃会把整个服务带走，
// 而"面板少个按钮"只是少个按钮。
template <typename F>
bool action_ready(const F &fn, httplib::Response &res, const char *what) {
  if (fn) return true;
  reply_error(res, 503, std::string("面板动作未接线：") + what);
  return false;
}

// 请求体必须是 JSON 对象。面板没有一个写接口需要表单编码：接受两种编码就得
// 写两套解析，而唯一的调用方是我们自己那页 JS。
bool parse_body(const httplib::Request &req, Json &out) {
  if (req.body.empty()) return false;
  Json doc;
  if (!Json::parse(req.body, doc) || !doc.is_object()) return false;
  out = doc;
  return true;
}

// 校验会话。GET 不要求 CSRF（否则前端为了读一次状态还得先多走一趟）；写操作
// 一律要求：Cookie 由浏览器自动携带，X-CSRF-Token 只有面板页面自己发得出来，
// "两者同时在场"才是"这个请求确实来自面板"的最小证据。
bool require_auth(const std::string &data_dir, const httplib::Request &req,
                  httplib::Response &res, std::string *out_token = nullptr) {
  const std::string token = token_from_request(req.get_header_value("Cookie"),
                                              req.get_header_value("Authorization"));
  if (out_token != nullptr) *out_token = token;
  std::string user;
  if (check_session(data_dir, token, req.method == "POST",
                    req.get_header_value("X-CSRF-Token"), user)) {
    return true;
  }
  // 用 401 而不是 403：前端只把 401 当成"回登录页"，403 会被显示成
  // "密码错误或无权访问"，运维会去查一个并不存在的权限问题。
  reply_error(res, 401, token.empty() ? "未登录或会话已失效，请重新登录"
                                      : "会话已失效或请求缺少防伪令牌，请刷新页面后重试");
  return false;
}

/* ------------------------------- JSON 归并 ------------------------------- */

// 把宿主回调产出的 JSON 文本整体放进 dst[key]，同时把顶层字段摊平进 dst。
//
// 两种形态都给：前端既要 d.info.uptime 这种成块读法，也要 d.uptime 这种直接
// 读法。只给一种，每加一个字段都得同步改一次前端解析，而这类改动最容易漏。
// 摊平只填 dst 里还没有的键，先到者（info）优先，stats 不会反过来盖掉它。
bool absorb(Json &dst, const std::string &text, const char *key) {
  if (text.empty()) return false;
  Json src;
  if (!Json::parse(text, src) || !src.is_object()) return false;
  // 拷贝一份再摊平：一边遍历 src 一边往 dst 里写，一旦两者来自同一个对象
  // （宿主把 dst 的引用传出来），迭代器就会在下一次插入时失效。
  Json block = Json::object();
  for (auto it = src.begin(); it != src.end(); ++it) {
    block[it.key()] = *it;
    if (dst.find(it.key()) == dst.end()) dst[it.key()] = *it;
  }
  dst[key] = block;
  return true;
}

/* ------------------------------- 页面资源 ------------------------------- */

// 页面带 CSP：面板的脚本与样式全是同源文件，页面里没有一段内联代码
// （ui.cpp 刻意没写内联 style / onclick），所以 default-src 'self' 就够用。
// 不开 'unsafe-inline' 是有意的：一旦开了，将来任何一处注入都能直接在
// 管理员的浏览器里执行。
void serve_page(httplib::Response &res) {
  res.status = 200;
  res.set_header("Cache-Control", "no-store");
  res.set_header("Content-Security-Policy",
                 "default-src 'self'; base-uri 'none'; form-action 'self'; "
                 "frame-ancestors 'none'; img-src 'self' data:");
  res.set_header("X-Frame-Options", "DENY");
  res.set_content(panel_html(), "text/html; charset=utf-8");
}

// 资源是编进可执行文件的，升级后内容会变却不带版本号；让浏览器每次回源，
// 比"教运维手动清缓存"便宜太多。
void serve_asset(httplib::Response &res, const std::string &body, const char *content_type) {
  res.status = 200;
  res.set_header("Cache-Control", "no-store");
  res.set_content(body, content_type);
}

// public_dir 在这里**故意不用**：面板就一个页面，HTML / CSS / JS 全部由 ui.cpp
// 内嵌。多一条"磁盘上有没有同名文件"的分支，就等于多一种"我改了磁盘那份为什么
// 没生效"的现场问题，而它带来的唯一好处是"改样式不用重编译"—— 面板改样式的
// 频率是几年一次，重编译一次的成本远低于解释这个分支。
//
// 参数按契约保留（panel.h 里有它），将来真要支持"覆盖层"时从这里接出去。

/* --------------------------------- 会话 --------------------------------- */

// 请求是否经隧道（https）。给 Cookie 加 Secure 的依据：只在 https 上传，
// 避免同一个 Cookie 顺着明文端口漏出去（服务本身是明文的）。
bool is_secure_request(const httplib::Request &req) {
  return util::to_lower(util::trim(req.get_header_value("X-Forwarded-Proto"))) == "https";
}

void set_session_cookie(httplib::Response &res, const std::string &token,
                        const httplib::Request &req) {
  // Path=/admin：Cookie 只在这棵子树里发，聊天页（/）不必带着管理凭据。
  // SameSite=Strict：面板的每个请求都从面板页面发起，跨站带不进来就够了。
  std::string cookie = std::string(kCookieName) + "=" + token + "; Path=/admin; Max-Age=" +
                       std::to_string(kSessionTtlSeconds) + "; HttpOnly; SameSite=Strict";
  if (is_secure_request(req)) cookie += "; Secure";
  res.set_header("Set-Cookie", cookie);
}

void clear_session_cookie(httplib::Response &res, const httplib::Request &req) {
  // 删除也要原样重复 Path / HttpOnly / SameSite：浏览器按 (名字, 域, 路径) 三者
  // 定位一条 Cookie，属性写得不一致就删不掉，运维点完"退出"刷新一下又回来了。
  std::string cookie = std::string(kCookieName) +
                       "=; Path=/admin; Max-Age=0; "
                       "Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Strict";
  if (is_secure_request(req)) cookie += "; Secure";
  res.set_header("Set-Cookie", cookie);
}

/* --------------------------------- 宿主 --------------------------------- */

// 一次注册、11 条路由共用的只读上下文。用 shared_ptr 而不是给每条 lambda 各
// 拷一份 Host：回调是 std::function，拷 11 份就等于拷 11 组捕获闭包。
struct Context {
  auth::Store *store = nullptr;
  Host host;
  std::string data_dir;
};

/* --------------------------------- 登录 --------------------------------- */

Json login_response_fields(const Session &session) {
  Json out = Json::object();
  out["user"] = session.user;
  out["csrf"] = session.csrf;
  out["expires_at"] = static_cast<long long>(session.expires_at);
  // 前端靠这个字段决定"直接进主界面"还是"留在登录页"。
  out["need_login"] = false;
  out["authed"] = true;
  return out;
}

void handle_login(const Context &ctx, const httplib::Request &req, httplib::Response &res) {
  Json body;
  if (!parse_body(req, body)) {
    reply_error(res, 400, "请求体不是 JSON 对象");
    return;
  }

  // 前端两套字段名都发（pass / password），这里两个都认，且优先 pass（聊天协议
  // 用的就是 pass，面板沿用同一个名字对脚本更友好）。少一个字段就得让"改前端
  // 还是改后端"成为一个每次都要重新讨论的问题。
  const std::string user = util::to_lower(util::trim(jsonx::str(body, "user")));
  const std::string password = jsonx::str(body, "pass", jsonx::str(body, "password"));
  if (password.empty()) {
    reply_error(res, 400, "请输入密码");
    return;
  }
  if (user.empty()) {
    // 空用户名不当作"admin 的默认值"：默认值会让任何一次笔误都变成一次登录尝试。
    reply_error(res, 401, kBadCredentialMsg);
    return;
  }
  if (!is_reserved_user(user)) {
    // 面板只有 admin 一个账号，别的名字一律按"用户名或密码错误"处理，
    // 不给出"该账号不能登录面板"这种可以拿来枚举的差异化提示。
    reply_error(res, 401, kBadCredentialMsg);
    return;
  }

  auth::Store *store = ctx.store;
  if (store == nullptr) {
    reply_error(res, 503, "面板没有拿到账号库，无法校验登录");
    return;
  }
  // 账号文件可能刚被命令行 --passwd 改过：先热加载再验，免得"命令行改了密码，
  // 面板却说密码错"，而两份状态其实只是没同步。
  store->reload_if_changed();
  const auth::Status st = store->verify(kAdminUser, password);
  // 审计：谁、从哪个 IP、什么时候、成没成功。面板是最该留痕的地方 ——
  // "谁删了一个账号"事后无迹可查，比丢一次登录严重得多。
  // 只记 IP 与结果，绝不记密码。
  const std::string ip = req.get_header_value("CF-Connecting-IP").empty()
                             ? req.remote_addr
                             : req.get_header_value("CF-Connecting-IP");
  auto audit = [&](const std::string &what) {
    if (ctx.host.log) ctx.host.log("面板 " + what + " ip=" + ip);
  };

  if (st == auth::Status::Locked) {
    audit("登录被锁定（失败次数过多）");
    reply_error(res, 429, auth::status_text(st));
    return;
  }
  if (st != auth::Status::Ok) {
    // NoUser 与 BadPassword 合并成同一句（见 kBadCredentialMsg 的注释）；
    // IoError 也只是"验证不了"，对客户端而言仍然等于凭据无效。
    audit("登录失败（密码错误或账号不存在）");
    reply_error(res, 401, kBadCredentialMsg);
    return;
  }

  const Session session = create_session(ctx.data_dir, kAdminUser);
  if (session.token.empty()) {
    // 随机源不可用时 create_session 返回空令牌。此时绝不能退化成"给个固定令牌"。
    reply_error(res, 500, "无法创建会话：系统安全随机源不可用");
    return;
  }
  set_session_cookie(res, session.token, req);
  audit("登录成功");
  reply_ok(res, login_response_fields(session));
}

void handle_logout(const Context &ctx, const httplib::Request &req, httplib::Response &res) {
  // 除登录外一律先鉴权（含注销）：不鉴权就能打的写接口，等于给"跨站把管理员
  // 踢下线"开了一扇门，而这类请求在日志里看起来跟正常退出没有区别。
  std::string token;
  const bool authed = require_auth(ctx.data_dir, req, res, &token);
  // 无论鉴权是否通过，都把这次带来的令牌作废并清掉 Cookie：注销必须幂等。
  // 否则"会话刚好过期时点退出"会留下一个仍然活着的令牌，而用户以为已经退了。
  if (!token.empty()) revoke_session(ctx.data_dir, token);
  clear_session_cookie(res, req);
  if (!authed) return;  // 401 已经由 require_auth 写好
  Json out = Json::object();
  out["need_login"] = true;
  reply_ok(res, out);
}

/* --------------------------------- 状态 --------------------------------- */

void handle_status(const Context &ctx, const httplib::Request &req, httplib::Response &res) {
  // 未登录一律 401 + 统一错误形状（而不是 200 + 一份假数据）：前端把 401 当成
  // "回登录页"，把"没登录"和"服务正常"混成同一个 200 只会让登录页多写一段
  // 猜测逻辑。也不发"临时 CSRF"：CSRF 必须与某个会话绑定，凭空发一个校验时
  // 找不到对应会话，等于把校验变成一次永远失败的仪式。
  //
  // GET 不要求 CSRF（require_auth 只对 POST 校验），否则前端为了读一次状态
  // 还得先多走一趟。
  std::string token;
  if (!require_auth(ctx.data_dir, req, res, &token)) return;

  Json out = Json::object();
  out["user"] = std::string(kAdminUser);
  out["authed"] = true;
  out["need_login"] = false;
  out["data_dir"] = ctx.data_dir;
  // GET 每次回一份当前令牌绑定的 CSRF：前端刷新页面后不必重新登录也能继续写。
  out["csrf"] = session_csrf(ctx.data_dir, token);

  // info / stats 分两路回调：一个说"这个进程是什么"，一个说"它干了多少活"，
  // 生命周期和刷新频率都不一样，合成一个回调只会让两边都不敢改。
  const bool have_info = absorb(out, ctx.host.info_json ? ctx.host.info_json() : std::string(),
                                "info");
  if (ctx.host.stats_json) {
    // stats 摊平后不能盖掉 info 的同名字段（info 才是权威口径）。
    absorb(out, ctx.host.stats_json(), "stats");
  }

  // 隧道：优先用专门的 tunnel_json；宿主没接线时退回 info 里那份（main.cpp 的
  // /api/info 本来就带 tunnel 子对象，两个来源说的是同一件事）。
  Json tunnel = Json::object();
  if (ctx.host.tunnel_json) {
    Json parsed;
    if (Json::parse(ctx.host.tunnel_json(), parsed) && parsed.is_object()) tunnel = parsed;
  }
  if (tunnel.empty() && have_info) {
    auto it = out.find("tunnel");
    if (it != out.end() && it->is_object()) tunnel = *it;
  }
  // 前端只认 url / state / source 这三个键（其余随便它加）。缺键时补空串而不是
  // 留 undefined：留 undefined 会让页面显示 "undefined"，而补空串只会显示 "—"。
  for (const char *key : {"url", "state", "source"}) {
    if (tunnel.find(key) == tunnel.end()) tunnel[key] = std::string();
  }
  out["tunnel"] = tunnel;

  reply_ok(res, out);
}

/* --------------------------------- 实例 --------------------------------- */

void handle_instances(const Context &ctx, const httplib::Request &, httplib::Response &res) {
  if (!ctx.host.instances_json) {
    reply_error(res, 503, "面板动作未接线：实例列表");
    return;
  }
  const std::string text = ctx.host.instances_json();
  Json src;
  if (!Json::parse(text, src)) {
    // 回调给的不是 JSON：明确报错，而不是悄悄回一个空列表 —— 空列表会被读成
    // "本机没有实例在跑"，那是完全不同的一件事。
    reply_error(res, 500, "实例列表不是合法 JSON");
    return;
  }

  Json out = Json::object();
  if (src.is_array()) {
    out["list"] = src;
  } else if (src.is_object()) {
    // 宿主的回调可能已经包了 {"list": [...]} 或 {"instances": [...]}；原样透传，
    // 同时保证 list 一定存在，前端不必猜是哪一种形状。
    for (auto it = src.begin(); it != src.end(); ++it) out[it.key()] = *it;
    auto list = src.find("list");
    if (list == src.end() || !list->is_array()) {
      auto alt = src.find("instances");
      if (alt != src.end() && alt->is_array()) out["list"] = *alt;
      else out["list"] = Json::array();
    }
  } else {
    out["list"] = Json::array();
  }
  reply_ok(res, out);
}

/* --------------------------------- 账号 --------------------------------- */

void handle_users(const Context &ctx, const httplib::Request &, httplib::Response &res) {
  if (ctx.store == nullptr) {
    reply_error(res, 503, "面板没有拿到账号库，无法列出账号");
    return;
  }
  // 账号列表由 admin.cpp 的 accounts_json 统一产出：它已经刻意剔掉了 salt / hash，
  // 路由层若自己再拼一份，就等于给"密钥材料漏进页面"开了第二个入口。
  const Json list = accounts_json(*ctx.store);
  Json out = Json::object();
  out["list"] = list;
  out["count"] = static_cast<long long>(list.size());
  reply_ok(res, out);
}

// 把动作回调的结果原样回给前端：成功带一句"做了什么"，失败带那句人话原因。
void report_action(httplib::Response &res, const std::pair<bool, std::string> &result) {
  if (result.first) {
    Json out = Json::object();
    out["message"] = result.second;
    reply_ok(res, out);
    return;
  }
  reply_error(res, 400, result.second);
}

void handle_user_add(const Context &ctx, const httplib::Request &req, httplib::Response &res) {
  Json body;
  if (!parse_body(req, body)) {
    reply_error(res, 400, "请求体不是 JSON 对象");
    return;
  }
  const std::string user = util::to_lower(util::trim(jsonx::str(body, "user")));
  // 保留名判定放在路由层而不是只靠回调：界面上的按钮可以被改，这里这道门不会。
  // 用户名比较必须大小写不敏感（auth 层就是这么落盘的），所以走 is_reserved_user。
  if (is_reserved_user(user)) {
    reply_error(res, 400, kReservedMsg);
    return;
  }
  if (user.empty()) {
    reply_error(res, 400, "用户名不能为空");
    return;
  }
  if (!action_ready(ctx.host.add_user, res, "新建账号")) return;
  const auto ret = ctx.host.add_user(user, util::trim(jsonx::str(body, "display")),
                                     jsonx::str(body, "password"));
  if (ctx.host.log) ctx.host.log("面板 新建账号 " + user + (ret.first ? " 成功" : " 失败"));
  report_action(res, ret);
}

void handle_user_del(const Context &ctx, const httplib::Request &req, httplib::Response &res) {
  Json body;
  if (!parse_body(req, body)) {
    reply_error(res, 400, "请求体不是 JSON 对象");
    return;
  }
  const std::string user = util::to_lower(util::trim(jsonx::str(body, "user")));
  // 删 admin 等于把唯一的入口删掉：服务不会退出，但面板从此没人能登，
  // 而现场没有任何自救手段（唯一的通道就是那个面板）。
  if (is_reserved_user(user)) {
    reply_error(res, 400, kReservedMsg);
    return;
  }
  if (user.empty()) {
    reply_error(res, 400, "用户名不能为空");
    return;
  }
  if (!action_ready(ctx.host.del_user, res, "删除账号")) return;
  // 删除是最需要留痕的动作：账号没了就没了，事后没人能还原"谁删的、什么时候"。
  const auto ret = ctx.host.del_user(user);
  if (ctx.host.log) ctx.host.log("面板 删除账号 " + user + (ret.first ? " 成功" : " 失败"));
  report_action(res, ret);
}

void handle_user_rename(const Context &ctx, const httplib::Request &req, httplib::Response &res) {
  Json body;
  if (!parse_body(req, body)) {
    reply_error(res, 400, "请求体不是 JSON 对象");
    return;
  }
  const std::string from = util::to_lower(util::trim(jsonx::str(body, "from")));
  const std::string to = util::to_lower(util::trim(jsonx::str(body, "to")));
  // 两个方向都要拦：源是 admin 会把入口改名，目标是 admin 会抢走那个名字。
  if (is_reserved_user(from) || is_reserved_user(to)) {
    reply_error(res, 400, kReservedMsg);
    return;
  }
  if (from.empty() || to.empty()) {
    reply_error(res, 400, "新旧用户名都不能为空");
    return;
  }
  if (!action_ready(ctx.host.rename_user, res, "账号改名")) return;
  const auto ret = ctx.host.rename_user(from, to);
  if (ctx.host.log) {
    ctx.host.log("面板 账号改名 " + from + " -> " + to + (ret.first ? " 成功" : " 失败"));
  }
  report_action(res, ret);
}

void handle_user_passwd(const Context &ctx, const httplib::Request &req, httplib::Response &res) {
  Json body;
  if (!parse_body(req, body)) {
    reply_error(res, 400, "请求体不是 JSON 对象");
    return;
  }
  const std::string user = util::to_lower(util::trim(jsonx::str(body, "user")));
  if (user.empty()) {
    reply_error(res, 400, "用户名不能为空");
    return;
  }
  // 改密码**不拦** admin：面板没有别的重置入口，拦了就等于运维永远没法轮换
  // 自己的口令，只能回到命令行 —— 而这正是面板想省掉的那一步。
  if (!action_ready(ctx.host.set_password, res, "修改密码")) return;
  // 只记"改过谁的密码"，绝不记明文。
  const auto ret = ctx.host.set_password(user, jsonx::str(body, "password"));
  if (ctx.host.log) ctx.host.log("面板 修改密码 " + user + (ret.first ? " 成功" : " 失败"));
  report_action(res, ret);
}

/* --------------------------------- 日志 --------------------------------- */

long long clamp_lines(const std::string &raw) {
  if (raw.empty()) return 200;
  long long n = 0;
  for (char c : raw) {
    if (c < '0' || c > '9') return 200;  // 非数字一律回默认值，不做部分解析
    if (n > 100000) return 200;
    n = n * 10 + (c - '0');
  }
  // 上限跟 main.cpp 的环形缓冲容量对齐：要更多本来也没有。
  if (n <= 0) return 200;
  if (n > 500) return 500;
  return n;
}

void handle_logs(const Context &ctx, const httplib::Request &req, httplib::Response &res) {
  if (!ctx.host.logs_json) {
    reply_error(res, 503, "面板动作未接线：日志缓冲");
    return;
  }
  const long long want = clamp_lines(req.get_param_value("lines"));

  const std::string text = ctx.host.logs_json();
  Json src;
  Json lines = Json::array();
  if (Json::parse(text, src)) {
    if (src.is_array()) {
      lines = src;
    } else if (src.is_object()) {
      // 宿主的回调可能给 {"lines": [...]}、{"list": [...]} 或 {"log": "多行文本"}，
      // 三种都认：这层适配比让两个模块为"日志长什么样"来回改签名便宜。
      for (auto it = src.begin(); it != src.end(); ++it) {
        if (it->is_array()) {
          lines = *it;
          break;
        }
      }
      if (lines.empty()) {
        auto it = src.find("log");
        if (it == src.end()) it = src.find("text");
        if (it != src.end() && it->is_string()) lines.push_back(*it);
      }
    }
  }

  // 只回最后 want 条：环形缓冲里存的是最新的，日志页要看的也是最新的；
  // 一次把 500 行拉给一个手机浏览器，纯粹是在浪费流量。
  Json out = Json::array();
  const size_t total = lines.size();
  const size_t skip = total > static_cast<size_t>(want) ? total - static_cast<size_t>(want) : 0;
  for (size_t i = skip; i < total; ++i) out.push_back(lines[i]);

  Json reply = Json::object();
  reply["lines"] = out;
  reply["count"] = static_cast<long long>(out.size());
  reply["total"] = static_cast<long long>(total);
  reply_ok(res, reply);
}

/* --------------------------------- 重启 --------------------------------- */

bool numeric_pid(const std::string &pid) {
  if (pid.empty() || pid.size() > 10) return false;  // pid 不会长到 10 位
  for (char c : pid) {
    if (c < '0' || c > '9') return false;
  }
  return pid != "0";
}

void handle_restart(const Context &ctx, const httplib::Request &req, httplib::Response &res) {
  Json body;
  if (!parse_body(req, body)) {
    reply_error(res, 400, "请求体不是 JSON 对象");
    return;
  }
  // pid 在这里只做"形状"校验：它是要交给系统去杀进程的，非数字值会在下游被
  // 当成"没给 pid"从而重启一个无关实例，所以宁可现在就拒。
  const std::string pid = util::trim(jsonx::str(body, "pid"));
  if (!numeric_pid(pid)) {
    reply_error(res, 400, "pid 必须是正整数");
    return;
  }
  if (!action_ready(ctx.host.restart_instance, res, "重启实例")) return;

  // 【先回响应，再动作】重启目标很可能就是本进程（面板就跑在这个进程里）。
  // 同步调用的话，restart_instance 会在发出 HTTP 响应之前把进程结束掉，
  // 浏览器看到的是"连接被重置"，用户完全不知道是成功了还是点坏了。
  //
  // 所以：立刻回 200，让 httplib 把响应写出去，然后在一个分离线程里稍等一下
  // 再真正执行重启。线程是 detached 的 —— 目标进程（可能就是自己）马上要退出，
  // join 它毫无意义，而且会拖住响应。
  if (ctx.host.log) ctx.host.log("面板 重启实例 pid=" + pid);
  reply_ok(res, [] {
    Json o = Json::object();
    o["message"] = "已发出重启，几秒后本页面刷新即可";
    return o;
  }());

  // 捕获 chain（含 restart 回调）而不是 ctx 的引用：线程要活过这个请求的处理
  // 栈帧，捕引用会悬垂。
  std::function<std::pair<bool, std::string>(const std::string &)> restart = ctx.host.restart_instance;
  std::thread([restart, pid]() {
    // 留够时间让响应真正写回网络。太短会把响应截断，太长用户会觉得点了没反应。
    std::this_thread::sleep_for(std::chrono::milliseconds(600));
    (void)restart(pid);
  }).detach();
}

/* ------------------------------ TURN 配置 ------------------------------ */

void handle_turn_get(const Context &ctx, httplib::Response &res) {
  if (!ctx.host.turn_status_json) {
    reply_error(res, 503, "面板动作未接线：TURN 状态");
    return;
  }
  Json out = Json::object();
  Json parsed;
  if (Json::parse(ctx.host.turn_status_json(), parsed) && parsed.is_object()) {
    out = parsed;
  }
  reply_ok(res, out);
}

void handle_turn_save(const Context &ctx, const httplib::Request &req, httplib::Response &res) {
  if (!ctx.host.turn_save) {
    reply_error(res, 503, "面板动作未接线：TURN 保存");
    return;
  }
  Json body;
  if (!parse_body(req, body)) {
    reply_error(res, 400, "请求体不是 JSON 对象");
    return;
  }
  // 空串表示"这一项保持原样"，所以两种空都要区分：字段缺失 = 不改，
  // 字段存在且非空 = 改。前端只会填用户真正输入的框。
  const std::string key_id = jsonx::str(body, "key_id");
  const std::string api_token = jsonx::str(body, "api_token");
  int ttl = static_cast<int>(jsonx::num(body, "ttl", 86400));

  const auto ret = ctx.host.turn_save(key_id, api_token, ttl);
  if (ctx.host.log) {
    // 只记"改过"，绝不记值。
    ctx.host.log(std::string("面板 更新 TURN 配置 ") + (ret.first ? "成功" : "失败"));
  }
  report_action(res, ret);
}

void handle_turn_clear(const Context &ctx, httplib::Response &res) {
  if (!ctx.host.turn_clear) {
    reply_error(res, 503, "面板动作未接线：TURN 清除");
    return;
  }
  const auto ret = ctx.host.turn_clear();
  if (ctx.host.log) ctx.host.log(std::string("面板 清除 TURN 配置 ") + (ret.first ? "成功" : "失败"));
  report_action(res, ret);
}

/* -------------------------------- 注册 -------------------------------- */

}  // namespace

bool register_routes(void *srv_as_httplib_server, const Host &host, const std::string &public_dir,
                     const std::string &data_dir, std::string &error) {
  error.clear();
  if (srv_as_httplib_server == nullptr) {
    error = "面板注册失败：服务器对象为空";
    return false;
  }
  // 契约把服务器做成 void*，是为了让 panel.h 不必包含 httplib.h（那个头文件
  // 有几十万行）；这里唯一一次 static_cast 换回来的就是类型安全。
  httplib::Server *srv = static_cast<httplib::Server *>(srv_as_httplib_server);

  std::shared_ptr<Context> ctx = std::make_shared<Context>();
  ctx->store = host.store;
  ctx->host = host;
  (void)public_dir;  // 见上面 serve_asset 附近的说明：静态资源不走文件系统
  // 会话要落盘到 <data_dir>/admin-sessions.json。主程序默认数据目录就是
  // exe 同级的 data；这里跟着走，宁可落到一个可预期的位置，也不要写到
  // "进程被从哪里拉起就变成哪"的当前工作目录里。
  ctx->data_dir = data_dir.empty() ? util::join_path(util::exe_dir(), "data") : data_dir;
  if (!ctx->data_dir.empty() && !util::file_exists(ctx->data_dir)) {
    std::string ignored;
    // 目录建不出来不是致命错误：auth.cpp 落盘失败时会把错误吞掉并继续用内存表，
    // 面板照常可用，只是重启后要重新登录一次。
    util::make_dirs(ctx->data_dir, ignored);
  }

  /* ---------------- 页面 ---------------- */
  // /admin 与 /admin/ 都挂：httplib 的模式匹配是一条一条比的，一条模式只认一个
  // 路径，"少一个斜杠就 404"是最常见也最难解释的一类面板故障。
  srv->Get(routes::kPage, [](const httplib::Request &, httplib::Response &res) {
    serve_page(res);
  });
  srv->Get(routes::kPageSlash, [](const httplib::Request &, httplib::Response &res) {
    serve_page(res);
  });
  // 样式与脚本直接把 ui.cpp 里的字符串 set_content 出去：set_content 收的是
  // const std::string&，那几个函数的返回值本身就是引用，所以这里零拷贝。
  srv->Get(routes::kCss, [](const httplib::Request &, httplib::Response &res) {
    serve_asset(res, panel_css(), "text/css; charset=utf-8");
  });
  srv->Get(routes::kJs, [](const httplib::Request &, httplib::Response &res) {
    serve_asset(res, panel_js(), "text/javascript; charset=utf-8");
  });

  /* ---------------- 接口 ---------------- */
  // 登录是唯一不鉴权的写接口；也正因为如此，它是全表唯一一个必须自己校验
  // 请求体形状的地方（其余接口在 require_auth 里已经先被拦住一次）。
  srv->Post(routes::kLogin, [ctx](const httplib::Request &req, httplib::Response &res) {
    handle_login(*ctx, req, res);
  });
  srv->Post(routes::kLogout, [ctx](const httplib::Request &req, httplib::Response &res) {
    handle_logout(*ctx, req, res);
  });

  srv->Get(routes::kStatus, [ctx](const httplib::Request &req, httplib::Response &res) {
    handle_status(*ctx, req, res);
  });
  // GET 也一律鉴权：账号列表、实例命令行、日志缓冲全是运维内部信息，未登录
  // 就能读到的话，"要密码才能进面板"就只剩一层装饰。
  // 状态接口例外 —— 它自己就在登录前被前端调用，用它来判断"该显示登录页还是
  // 主界面"，所以它自己处理未登录情形（回 401 + need_login）。
  srv->Get(routes::kInstances, [ctx](const httplib::Request &req, httplib::Response &res) {
    if (!require_auth(ctx->data_dir, req, res)) return;
    handle_instances(*ctx, req, res);
  });
  srv->Get(routes::kUsers, [ctx](const httplib::Request &req, httplib::Response &res) {
    if (!require_auth(ctx->data_dir, req, res)) return;
    handle_users(*ctx, req, res);
  });
  srv->Get(routes::kLogs, [ctx](const httplib::Request &req, httplib::Response &res) {
    if (!require_auth(ctx->data_dir, req, res)) return;
    handle_logs(*ctx, req, res);
  });

  // 写接口在动作前统一过一遍 require_auth：把"鉴权"写在每条路由的第一行，
  // 是唯一能保证"以后新加的动作不会忘了鉴权"的写法 —— 忘了就少一行，看得见。
  srv->Post(routes::kUserAdd, [ctx](const httplib::Request &req, httplib::Response &res) {
    if (!require_auth(ctx->data_dir, req, res)) return;
    handle_user_add(*ctx, req, res);
  });
  srv->Post(routes::kUserDel, [ctx](const httplib::Request &req, httplib::Response &res) {
    if (!require_auth(ctx->data_dir, req, res)) return;
    handle_user_del(*ctx, req, res);
  });
  srv->Post(routes::kUserRename, [ctx](const httplib::Request &req, httplib::Response &res) {
    if (!require_auth(ctx->data_dir, req, res)) return;
    handle_user_rename(*ctx, req, res);
  });
  srv->Post(routes::kUserPasswd, [ctx](const httplib::Request &req, httplib::Response &res) {
    if (!require_auth(ctx->data_dir, req, res)) return;
    handle_user_passwd(*ctx, req, res);
  });
  srv->Post(routes::kRestart, [ctx](const httplib::Request &req, httplib::Response &res) {
    if (!require_auth(ctx->data_dir, req, res)) return;
    handle_restart(*ctx, req, res);
  });

  // TURN：GET 只读状态（掩码），POST 保存，DELETE 清除。
  // 「清除」单独一个动词而不是 POST 一个空值：空值在保存语义里表示"不改这一项"，
  // 用它来删除会让"想删掉"变成"什么也没发生"。
  srv->Get(routes::kTurn, [ctx](const httplib::Request &req, httplib::Response &res) {
    if (!require_auth(ctx->data_dir, req, res)) return;
    handle_turn_get(*ctx, res);
  });
  srv->Post(routes::kTurn, [ctx](const httplib::Request &req, httplib::Response &res) {
    if (!require_auth(ctx->data_dir, req, res)) return;
    handle_turn_save(*ctx, req, res);
  });
  srv->Delete(routes::kTurn, [ctx](const httplib::Request &req, httplib::Response &res) {
    if (!require_auth(ctx->data_dir, req, res)) return;
    handle_turn_clear(*ctx, res);
  });

  return true;
}

}  // namespace panel
