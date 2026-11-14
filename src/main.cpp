// 局域网对讲机 —— 服务端入口
// ---------------------------------------------------------------------------
// 只有局域网 / cloudflared 隧道可以访问；启动时创建的监听 socket 带「仅允许本机
// 回环连接」标记，因此公网 IP 直连在 TCP 握手阶段就会被系统拒绝，只有本机上的
// cloudflared 能连进来。
// 编译宏由 CMake 提供：CPPHTTPLIB_THREAD_POOL_COUNT
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "../third_party/httplib.h"
#include "auth.h"
#include "hub.h"
#include "json.h"
#include "protocol.h"
#include "util.h"

// 由 CMake 生成：把 public/index.html 以字节数组形式嵌进可执行文件，
// 这样安装脚本只需分发一个二进制，找不到 public 目录也能正常提供前端。
#if defined(__has_include)
#if __has_include("embedded_public.h")
#include "embedded_public.h"
#define INTERCOM_HAS_EMBEDDED_PUBLIC 1
#endif
#endif

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>
#endif

namespace {

struct Config {
  int port = 8080;
  std::string bind_host = "127.0.0.1";
  bool loopback_only = true;
  // TLS 由 cloudflared 边缘终结，服务端只跑明文 HTTP（无需证书、无需 OpenSSL）
  std::string data_dir = "data";
  std::string accounts_dir;  // 空表示 ~/.intercom
  std::string public_dir = "public";
};

Config g_cfg;
auth::Store *g_store = nullptr;
hub::Hub g_hub;
std::atomic<int64_t> g_started_at{0};
std::atomic<unsigned long long> g_msg_count{0};
std::atomic<unsigned long long> g_media_count{0};
std::atomic<unsigned long long> g_signal_count{0};
std::mutex g_token_mu;
std::map<std::string, std::string> g_tokens;  // token -> user
std::mutex g_pending_mu;

struct PendingCall {
  std::string from;
  std::string to;
  std::string media;
  int64_t deadline = 0;
};
std::map<std::string, PendingCall> g_pending;  // 被叫 user -> 来电信息（含超时）

// 通话中对方掉线时，保留房间一段时间等待重连（避免「通话状态不可保持」）
struct DetachedRoom {
  std::string room;
  std::string survivor;   // 仍在线的 user
  std::string media;
  int64_t deadline = 0;
};
std::mutex g_detached_mu;
std::map<std::string, DetachedRoom> g_detached;  // key: 掉线的 user


/* ------------------------------ 小工具 ------------------------------ */

void log_line(const std::string &msg) {
  std::string line = "[" + util::now_string() + "] " + msg + "\n";
  std::fputs(line.c_str(), stdout);
  std::fflush(stdout);
}

std::string make_token() { return util::random_token(24); }

std::string issue_token(const std::string &user) {
  std::string token = make_token();
  std::lock_guard<std::mutex> lk(g_token_mu);
  g_tokens[token] = user;
  // 控制内存中的 token 数量
  if (g_tokens.size() > 512) {
    auto it = g_tokens.begin();
    g_tokens.erase(it);
  }
  return token;
}

bool resolve_token(const std::string &token, std::string &user) {
  std::lock_guard<std::mutex> lk(g_token_mu);
  auto it = g_tokens.find(token);
  if (it == g_tokens.end()) return false;
  user = it->second;
  return true;
}

std::string client_ip(const httplib::Request &req) {
  auto it = req.headers.find("CF-Connecting-IP");
  if (it != req.headers.end()) return it->second;
  return req.remote_addr;
}

/* ------------------------------ 业务处理 ------------------------------ */

struct Session {
  std::shared_ptr<hub::Peer> peer;
  bool authed = false;
  std::string user;
  std::string display;
  std::string ip;
};

void send_json(const std::shared_ptr<hub::Peer> &peer, const jsonx::Json &j) {
  if (!peer || !peer->send) return;
  peer->send(jsonx::dump(j) + "\n");
}

jsonx::Json err(const std::string &reason) {
  jsonx::Json j;
  j["t"] = "error";
  j["reason"] = reason;
  return j;
}

void broadcast_users() {
  jsonx::Json j;
  j["t"] = "users";
  jsonx::Json list = jsonx::Json::array();
  for (const auto &u : g_hub.online()) {
    jsonx::Json item;
    item["user"] = u.user;
    item["display"] = u.display;
    item["busy"] = u.busy;
    list.push_back(item);
  }
  j["list"] = list;
  g_hub.broadcast_all(jsonx::dump(j) + "\n");
}

void handle_auth(Session &s, const jsonx::Json &msg) {
  if (s.authed) {
    send_json(s.peer, err("已登录"));
    return;
  }
  std::string user = util::to_lower(util::trim(jsonx::str(msg, "user")));
  std::string pass = jsonx::str(msg, "pass");
  std::string token = jsonx::str(msg, "token");
  std::string reason;

  if (!token.empty()) {
    std::string tu;
    if (!resolve_token(token, tu)) {
      jsonx::Json j;
      j["t"] = "auth-fail";
      j["reason"] = "登录凭据已失效，请重新输入密码";
      send_json(s.peer, j);
      return;
    }
    user = tu;
  } else {
    if (user.empty() || pass.empty()) {
      jsonx::Json j;
      j["t"] = "auth-fail";
      j["reason"] = "请输入用户名与密码";
      send_json(s.peer, j);
      return;
    }
    g_store->reload_if_changed();  // 命令行新注册的账号无需重启即可登录
    auth::Status st = g_store->verify(user, pass);
    if (st != auth::Status::Ok) {
      jsonx::Json j;
      j["t"] = "auth-fail";
      j["reason"] = auth::status_text(st);
      send_json(s.peer, j);
      log_line("登录失败 user=" + user + " ip=" + s.ip + " 原因=" + auth::status_text(st));
      return;
    }
  }

  // 找到展示名
  g_store->reload_if_changed();
  std::string display = user;
  for (const auto &a : g_store->list()) {
    if (a.user == user) {
      display = a.display.empty() ? user : a.display;
      break;
    }
  }

  s.authed = true;
  s.user = user;
  s.display = display;
  s.peer->user = user;
  s.peer->display = display;

  std::shared_ptr<hub::Peer> replaced;
  g_hub.put_online(s.peer, replaced);
  if (replaced && replaced->close) {
    log_line("账号重复登录，踢掉旧连接 user=" + user);
    replaced->close(4001, "账号在其它设备登录");
  }

  std::string new_token = issue_token(user);
  jsonx::Json ok;
  ok["t"] = "auth-ok";
  ok["user"] = user;
  ok["display"] = display;
  ok["token"] = new_token;
  send_json(s.peer, ok);

  // 若刚才是在通话中掉线，重连后自动回到原房间
  DetachedRoom resume;
  bool has_resume = false;
  {
    std::lock_guard<std::mutex> lk(g_detached_mu);
    auto it = g_detached.find(user);
    if (it != g_detached.end()) {
      if (g_hub.room_exists(it->second.room) && g_hub.rejoin_room(s.peer, it->second.room)) {
        resume = it->second;
        has_resume = true;
      }
      g_detached.erase(it);
    }
  }
  if (has_resume) {
    jsonx::Json rj;
    rj["t"] = "call-resume";
    rj["room"] = resume.room;
    rj["peer"] = resume.survivor;
    rj["media"] = resume.media;
    send_json(s.peer, rj);
    auto survivor = g_hub.by_user(resume.survivor);
    if (survivor) {
      jsonx::Json sj;
      sj["t"] = "call-peer-back";
      sj["peer"] = user;
      send_json(survivor, sj);
    }
    log_line("通话重连成功 user=" + user + " 房间=" + resume.room.substr(0, 8));
  }

  log_line("登录成功 user=" + user + " 在线=" + std::to_string(g_hub.online_count()));
  broadcast_users();  // 立即把最新在线列表推给所有人

}

void handle_call(Session &s, const jsonx::Json &msg) {
  std::string target = util::to_lower(util::trim(jsonx::str(msg, "to")));
  std::string media = jsonx::str(msg, "media", "audio");
  if (media != "audio" && media != "video") media = "audio";
  if (target.empty() || target == s.user) {
    send_json(s.peer, err("被叫账号无效"));
    return;
  }
  auto peer_b = g_hub.by_user(target);
  if (!peer_b) {
    jsonx::Json j;
    j["t"] = "call-fail";
    j["reason"] = "对方不在线";
    send_json(s.peer, j);
    return;
  }
  if (g_hub.busy(s.user) || g_hub.busy(target)) {
    jsonx::Json j;
    j["t"] = "call-fail";
    j["reason"] = "对方正在通话中";
    send_json(s.peer, j);
    return;
  }
  {
    std::lock_guard<std::mutex> lk(g_pending_mu);
    g_pending[target] = PendingCall{s.user, target, media,
                                    util::now_sec() + 45};
  }
  jsonx::Json j;
  j["t"] = "incoming";
  j["from"] = s.user;
  j["display"] = s.display;
  j["media"] = media;
  send_json(peer_b, j);
  log_line("来电 " + s.user + " -> " + target + " (" + media + ")");
}

void start_call(const std::string &caller, const std::string &callee,
                const std::string &media) {
  auto a = g_hub.by_user(caller);
  auto b = g_hub.by_user(callee);
  if (!a || !b) return;
  std::string room = g_hub.create_room(a, b, media);
  if (room.empty()) return;

  jsonx::Json ja;
  ja["t"] = "call-start";
  ja["peer"] = callee;
  ja["display"] = b->display;
  ja["media"] = media;
  ja["initiator"] = true;
  send_json(a, ja);

  jsonx::Json jb;
  jb["t"] = "call-start";
  jb["peer"] = caller;
  jb["display"] = a->display;
  jb["media"] = media;
  jb["initiator"] = false;
  send_json(b, jb);

  log_line("通话开始 " + caller + " <-> " + callee + " (" + media + ")");
  broadcast_users();
}

void handle_accept(Session &s) {
  PendingCall pc;
  bool found = false;
  {
    std::lock_guard<std::mutex> lk(g_pending_mu);
    auto it = g_pending.find(s.user);
    if (it != g_pending.end()) {
      pc = it->second;
      g_pending.erase(it);
      found = true;
    }
  }
  if (!found) {
    jsonx::Json j;
    j["t"] = "call-fail";
    j["reason"] = "来电已失效";
    send_json(s.peer, j);
    return;
  }
  start_call(pc.from, pc.to, pc.media);
}

void detach_room(const std::string &user, const std::string &reason) {
  {
    std::lock_guard<std::mutex> lk(g_detached_mu);
    g_detached.erase(user);
  }
  auto p = g_hub.by_user(user);
  if (!p || p->room.empty()) return;
  std::string room = p->room;
  std::string media = g_hub.room_media(room);
  std::string other = g_hub.room_peer_id(room, p->id);
  if (other.empty()) {
    g_hub.leave_room(p->id);
    return;
  }
  auto other_peer = g_hub.by_id(other);
  std::string survivor = other_peer ? other_peer->user : std::string();
  {
    std::lock_guard<std::mutex> lk(g_detached_mu);
    g_detached[user] = DetachedRoom{room, survivor, media, util::now_sec() + 90};
  }
  if (other_peer && other_peer->send) {
    jsonx::Json j;
    j["t"] = "call-peer-lost";
    j["reason"] = reason;
    j["peer"] = user;
    send_json(other_peer, j);
  }
  log_line("通话对方掉线 user=" + user + "，保留房间 90 秒等待重连");
}

void end_call(const std::string &user, const std::string &reason) {
  {
    std::lock_guard<std::mutex> lk(g_pending_mu);
    for (auto it = g_pending.begin(); it != g_pending.end();) {
      if (it->first == user || it->second.from == user) it = g_pending.erase(it);
      else ++it;
    }
  }
  auto p = g_hub.by_user(user);
  if (!p || p->room.empty()) return;
  std::string room = p->room;
  jsonx::Json j;
  j["t"] = "call-end";
  j["reason"] = reason;
  g_hub.broadcast(room, jsonx::dump(j) + "\n");
  g_hub.leave_room(p->id);
  auto peers = g_hub.room_peers(room);
  for (auto &other : peers) g_hub.leave_room(other->id);
  log_line("通话结束 " + user + " 原因=" + reason);
  broadcast_users();
}

void handle_reject(Session &s) {
  std::string from;
  {
    std::lock_guard<std::mutex> lk(g_pending_mu);
    auto it = g_pending.find(s.user);
    if (it != g_pending.end()) {
      from = it->second.from;
      g_pending.erase(it);
    }
  }
  if (from.empty()) return;
  auto caller = g_hub.by_user(from);
  if (caller) {
    jsonx::Json j;
    j["t"] = "call-fail";
    j["reason"] = "对方已拒绝";
    send_json(caller, j);
  }
}

void handle_signal(Session &s, const jsonx::Json &msg) {
  if (s.peer->room.empty()) return;
  auto it = msg.find("data");
  if (it == msg.end() || !it->is_object()) return;
  g_signal_count++;
  jsonx::Json j;
  j["t"] = "signal";
  j["from"] = s.user;
  j["display"] = s.display;
  j["data"] = *it;
  g_hub.broadcast(s.peer->room, jsonx::dump(j) + "\n", s.peer->id);
}

// 文字消息：按 `to` 定向转发给在线用户，服务端不保存
void handle_chat(Session &s, const jsonx::Json &msg) {
  std::string to = util::to_lower(util::trim(jsonx::str(msg, "to")));
  auto target = g_hub.by_user(to);
  if (!target) {
    send_json(s.peer, err("对方不在线"));
    return;
  }
  std::string text = jsonx::str(msg, "text");
  if (text.size() > static_cast<size_t>(proto::kMaxTextLength)) text.resize(proto::kMaxTextLength);
  if (util::trim(text).empty()) return;
  g_msg_count++;
  jsonx::Json j;
  j["t"] = "chat";
  j["from"] = s.user;
  j["display"] = s.display;
  j["text"] = text;
  j["ts"] = util::now_sec();
  long long ttl = jsonx::num(msg, "ttl", 0);
  if (ttl > 0) j["ttl"] = ttl;
  send_json(target, j);
}

// 语音 / 视频 / 图片消息：解码校验后原样转发，服务端不落盘、不缓存
void handle_media(Session &s, const jsonx::Json &msg) {
  std::string to = util::to_lower(util::trim(jsonx::str(msg, "to")));
  auto target = g_hub.by_user(to);
  if (!target) {
    send_json(s.peer, err("对方不在线"));
    return;
  }
  std::string kind = jsonx::str(msg, "kind", "file");
  std::string data = jsonx::str(msg, "data");
  std::string raw;
  if (!util::b64_decode(data, raw)) {
    send_json(s.peer, err("媒体数据编码错误"));
    return;
  }
  if (raw.size() > proto::kMaxMediaBytes) {
    send_json(s.peer, err("语音/视频消息过大（上限 12MB）"));
    return;
  }
  g_media_count++;
  jsonx::Json j;
  j["t"] = "media";
  j["from"] = s.user;
  j["display"] = s.display;
  j["kind"] = kind;
  j["name"] = jsonx::str(msg, "name").substr(0, 120);
  j["mime"] = jsonx::str(msg, "mime", "application/octet-stream").substr(0, 80);
  j["size"] = static_cast<long long>(raw.size());
  j["duration"] = jsonx::num(msg, "duration", 0);
  j["caption"] = jsonx::str(msg, "caption").substr(0, 200);
  j["data"] = data;  // 原样转发，服务端不保存
  j["ts"] = util::now_sec();
  send_json(target, j);
}

void handle_ws_message(Session &s, const std::string &raw) {
  jsonx::Json msg;
  if (!jsonx::parse(raw, msg) || !msg.is_object()) {
    send_json(s.peer, err("消息格式错误"));
    return;
  }
  std::string t = jsonx::str(msg, "t");
  if (t.empty()) return;

  if (!s.authed && t != "auth") {
    send_json(s.peer, err("请先登录"));
    return;
  }

  if (t == "auth") {
    handle_auth(s, msg);
  } else if (t == "users") {
    jsonx::Json j;
    j["t"] = "users";
    jsonx::Json list = jsonx::Json::array();
    for (const auto &u : g_hub.online()) {
      jsonx::Json item;
      item["user"] = u.user;
      item["display"] = u.display;
      item["busy"] = u.busy;
      list.push_back(item);
    }
    j["list"] = list;
    send_json(s.peer, j);
  } else if (t == "call") {
    handle_call(s, msg);
  } else if (t == "accept") {
    handle_accept(s);
  } else if (t == "reject") {
    handle_reject(s);
  } else if (t == "hangup") {
    end_call(s.user, "hangup");
  } else if (t == "signal") {
    handle_signal(s, msg);
  } else if (t == "chat") {
    handle_chat(s, msg);
  } else if (t == "media") {
    handle_media(s, msg);
  } else if (t == "typing") {
    auto target = g_hub.by_user(util::to_lower(util::trim(jsonx::str(msg, "to"))));
    if (!target) return;
    jsonx::Json j;
    j["t"] = "typing";
    j["from"] = s.user;
    j["state"] = jsonx::boolean(msg, "state");
    send_json(target, j);
  } else if (t == "ping") {
    jsonx::Json j;
    j["t"] = "pong";
    j["ts"] = static_cast<long long>(util::now_ms());
    send_json(s.peer, j);
  } else {
    send_json(s.peer, err("未知指令: " + t));
  }
}

/* ------------------------------ HTTP ------------------------------ */

jsonx::Json ice_config();


void handle_info(const httplib::Request &req, httplib::Response &res) {
  jsonx::Json j;
  j["name"] = "局域网对讲机";
  j["uptime"] = static_cast<long long>(util::now_sec() - g_started_at.load());
  j["online"] = static_cast<long long>(g_hub.online_count());
  j["rooms"] = static_cast<long long>(g_hub.room_count());
  j["messages"] = static_cast<long long>(g_msg_count.load());
  j["media"] = static_cast<long long>(g_media_count.load());
  j["signals"] = static_cast<long long>(g_signal_count.load());
  j["secure"] = req.headers.count("X-Forwarded-Proto") > 0;
  j["loopback_only"] = g_cfg.loopback_only;
  j["client_ip"] = client_ip(req);
  j["ice"] = ice_config();
  res.set_content(jsonx::dump(j), "application/json; charset=utf-8");
  res.set_header("Cache-Control", "no-store");
}

void handle_media_probe(const httplib::Request &req, httplib::Response &res) {
  // 只统计体积，不保留任何内容
  size_t n = req.body.size();
  log_line("上传探测 " + std::to_string(n) + " 字节（已丢弃）");
  jsonx::Json j;
  j["ok"] = true;
  j["received"] = static_cast<long long>(n);
  j["stored"] = false;
  res.set_content(jsonx::dump(j), "application/json; charset=utf-8");
  res.set_header("Cache-Control", "no-store");
}

// ICE 服务器配置：默认公共 STUN；如需穿透对称 NAT，可在 data/ice.json 里配置 TURN
// ICE 服务器配置：默认公共 STUN；如需穿透对称 NAT，在 data/ice.json 里配置 TURN。
// 每次请求都检查文件修改时间，改完配置刷新页面即可生效，不必重启服务。
jsonx::Json ice_config() {
  static std::mutex mu;
  static jsonx::Json cached;
  static std::string cached_stamp;
  static bool loaded = false;
  std::lock_guard<std::mutex> lk(mu);

  std::string path = util::join_path(g_cfg.data_dir, "ice.json");
  std::string stamp = "none";
  std::error_code ec;
  auto ts = std::filesystem::last_write_time(path, ec);
  if (!ec) stamp = std::to_string(ts.time_since_epoch().count());

  if (loaded && stamp == cached_stamp) return cached;

  jsonx::Json result;
  jsonx::Json list = jsonx::Json::array();
  std::string text;
  if (stamp != "none" && util::file_exists(path) && util::read_file(path, text)) {
    jsonx::Json doc;
    if (jsonx::parse(text, doc) && doc.is_object()) {
      auto it = doc.find("iceServers");
      if (it != doc.end() && it->is_array() && !it->empty()) {
        result["iceServers"] = *it;
        cached = result;
        cached_stamp = stamp;
        loaded = true;
        log_line("已载入自定义 ICE 配置: " + path);
        return cached;
      }
    }
    log_line("提示: " + path + " 解析失败，使用默认 STUN");
  }

  list.push_back({{"urls", "stun:stun.cloudflare.com:3478"}});
  list.push_back({{"urls", "stun:stun.l.google.com:19302"}});
  result["iceServers"] = list;
  cached = result;
  cached_stamp = stamp;
  loaded = true;
  return cached;
}

bool is_loopback(const std::string &ip) {
  if (ip.empty()) return true;  // 拿不到来源地址时不拦（例如 UNIX socket）
  if (ip == "::1" || ip == "127.0.0.1") return true;
  return ip.rfind("127.", 0) == 0;
}

// cloudflared 的请求一定带这些头；外部直连不会带
bool looks_like_cloudflared(const httplib::Request &req) {
  return req.headers.count("CF-Ray") > 0 || req.headers.count("CF-Connecting-IP") > 0 ||
         req.headers.count("Cf-Worker") > 0 || req.headers.count("X-Forwarded-Proto") > 0;
}

// 只允许 cloudflared 与本机回环访问；即使误开 --bind 0.0.0.0，外部 IP 也会被拒绝
bool allow_request(const httplib::Request &req, httplib::Response &res) {
  if (is_loopback(req.remote_addr) || looks_like_cloudflared(req)) return true;
  res.status = 403;
  res.set_content("403 仅允许通过 cloudflared 隧道访问", "text/plain; charset=utf-8");
  log_line("拒绝非隧道来源访问 " + req.remote_addr + " " + req.path);
  return false;
}

void configure_server(httplib::Server &srv) {
  srv.set_pre_routing_handler([](const httplib::Request &req, httplib::Response &res) {
    return allow_request(req, res) ? httplib::Server::HandlerResponse::Unhandled
                                   : httplib::Server::HandlerResponse::Handled;
  });
  srv.set_exception_handler([](const httplib::Request &req, httplib::Response &res,
                               std::exception_ptr ep) {
    std::string what = "unknown";
    try {
      if (ep) std::rethrow_exception(ep);
    } catch (const std::exception &e) {
      what = e.what();
    } catch (...) {
      what = "非标准异常";
    }
    log_line("请求异常 " + req.path + " 原因=" + what);
    res.status = 500;
    res.set_content("500 内部错误: " + what, "text/plain; charset=utf-8");
  });
  srv.set_payload_max_length(64u * 1024 * 1024);
  srv.set_read_timeout(120, 0);
  srv.set_write_timeout(120, 0);
  srv.set_idle_interval(0, 100000);
  srv.set_websocket_ping_interval(proto::kHeartbeatSeconds);
  srv.set_websocket_max_missed_pongs(2);

  srv.set_file_extension_and_mimetype_mapping("html", "text/html; charset=utf-8");
  srv.set_file_extension_and_mimetype_mapping("js", "application/javascript; charset=utf-8");
  srv.set_file_extension_and_mimetype_mapping("css", "text/css; charset=utf-8");
  srv.set_file_extension_and_mimetype_mapping("svg", "image/svg+xml");
  srv.set_file_extension_and_mimetype_mapping("webmanifest", "application/manifest+json");
  srv.set_file_extension_and_mimetype_mapping("json", "application/json; charset=utf-8");

  // 统一声明：本服务不收集、不存储任何消息内容
  srv.set_default_headers({
      {"Cache-Control", "no-store"},
      {"X-Content-Type-Options", "nosniff"},
      {"Referrer-Policy", "no-referrer"},
  });

  srv.Get("/api/info", handle_info);
  srv.Post("/api/media/probe", handle_media_probe);

  srv.WebSocket("/ws", [](const httplib::Request &req, httplib::ws::WebSocket &ws) {
    Session s;
    s.ip = client_ip(req);
    s.peer = std::make_shared<hub::Peer>();
    s.peer->id = util::random_token(8);
    s.peer->joined_at = util::now_sec();
    s.peer->send = [&ws](const std::string &text) {
      ws.send(text);
      return true;
    };
    s.peer->close = [&ws](uint16_t code, const std::string &reason) {
      httplib::ws::CloseStatus st = httplib::ws::CloseStatus::Normal;
      switch (code) {
        case 4001: st = httplib::ws::CloseStatus::PolicyViolation; break;
        case 1001: st = httplib::ws::CloseStatus::GoingAway; break;
        default: st = httplib::ws::CloseStatus::Normal; break;
      }
      ws.close(st, reason);
    };

    jsonx::Json hello;
    hello["t"] = "hello";
    hello["ip"] = client_ip(req);
    hello["secure"] = req.headers.count("X-Forwarded-Proto") > 0;
    send_json(s.peer, hello);

    ws.set_read_timeout(proto::kHeartbeatSeconds * 2 + 5, 0);

    std::string msg;
    while (true) {
      auto r = ws.read(msg);
      if (r == httplib::ws::ReadResult::Text) {
        handle_ws_message(s, msg);
      } else if (r == httplib::ws::ReadResult::Binary) {
        send_json(s.peer, err("不支持二进制帧"));
      } else if (r == httplib::ws::ReadResult::Timeout) {
        continue;
      } else {
        break;
      }
    }

    if (s.authed) {
      detach_room(s.user, "disconnect");
      g_hub.remove_online(s.peer->id);
      log_line("下线 user=" + s.user + " 在线=" + std::to_string(g_hub.online_count()));
      broadcast_users();
    }
  });

  // 前端：优先用磁盘上的 public/index.html（便于改样式后刷新即可见），
  // 找不到就用编译时内嵌的那一份，保证单文件二进制也能独立运行。
  srv.Get("/", [](const httplib::Request &, httplib::Response &res) {
    res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
    std::string disk = util::join_path(g_cfg.public_dir, "index.html");
    std::string html;
    if (util::file_exists(disk) && util::read_file(disk, html)) {
      res.set_content(html, "text/html; charset=utf-8");
      return;
    }
#if defined(INTERCOM_HAS_EMBEDDED_PUBLIC)
    res.set_content(
        std::string(reinterpret_cast<const char *>(embedded::kIndexHtml), embedded::kIndexHtmlLen),
        "text/html; charset=utf-8");
#else
    res.status = 500;
    res.set_content("500 未找到前端文件（public/index.html）", "text/plain; charset=utf-8");
#endif
  });

  srv.Get("/index.html", [](const httplib::Request &req, httplib::Response &res) {
    (void)req;
    res.status = 302;
    res.set_header("Location", "/");
  });

  // 其余静态资源（如以后加了图标/样式）仍从 public 目录取
  srv.set_mount_point("/", g_cfg.public_dir);
}

/* ------------------------------ 后台任务 ------------------------------ */

void start_background_tasks() {
  std::thread([] {
    for (;;) {
      std::this_thread::sleep_for(std::chrono::seconds(1));
      int64_t now = util::now_sec();
      std::vector<PendingCall> expired;
      {
        std::lock_guard<std::mutex> lk(g_pending_mu);
        for (auto it = g_pending.begin(); it != g_pending.end();) {
          if (it->second.deadline <= now) {
            expired.push_back(it->second);
            it = g_pending.erase(it);
          } else {
            ++it;
          }
        }
      }
      // 通话掉线保留超时 -> 真正结束
      std::vector<DetachedRoom> dead;
      {
        std::lock_guard<std::mutex> lk(g_detached_mu);
        for (auto it = g_detached.begin(); it != g_detached.end();) {
          if (it->second.deadline <= now) {
            dead.push_back(it->second);
            it = g_detached.erase(it);
          } else {
            ++it;
          }
        }
      }
      for (const auto &room : dead) {
        auto survivor = g_hub.by_user(room.survivor);
        if (survivor) {
          jsonx::Json j;
          j["t"] = "call-end";
          j["reason"] = "peer-timeout";
          send_json(survivor, j);
          g_hub.leave_room(survivor->id);
        }
        log_line("重连超时，通话结束 房间=" + room.room.substr(0, 8));
        broadcast_users();
      }

      for (const auto &call : expired) {
        auto caller = g_hub.by_user(call.from);
        if (!caller) continue;
        jsonx::Json j;
        j["t"] = "call-fail";
        j["reason"] = "对方无应答";
        send_json(caller, j);
        auto callee = g_hub.by_user(call.to);
        if (callee) {
          jsonx::Json jc;
          jc["t"] = "incoming-cancel";
          jc["from"] = call.from;
          send_json(callee, jc);
        }
        log_line("来电超时 " + call.from + " -> " + call.to);
      }
    }
  }).detach();
}

/* ------------------------------ 命令行参数 ------------------------------ */

#if defined(_WIN32)
// Windows 上 argv 是 ANSI 代码页，中文会乱码；改为从宽字符命令行取 UTF-8 参数
std::vector<std::string> utf8_args() {
  std::vector<std::string> out;
  int argc = 0;
  LPWSTR *wargv = ::CommandLineToArgvW(::GetCommandLineW(), &argc);
  if (!wargv) return out;
  for (int i = 0; i < argc; ++i) {
    int len = ::WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, nullptr, 0, nullptr, nullptr);
    std::string s;
    if (len > 1) {
      s.resize(static_cast<size_t>(len - 1));
      ::WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, &s[0], len, nullptr, nullptr);
    }
    out.push_back(s);
  }
  ::LocalFree(wargv);
  return out;
}
#endif

/* ------------------------------ 端口监听 ------------------------------ */

}  // namespace

/* ------------------------------ 主函数 ------------------------------ */

static void print_usage() {
  std::printf(
      "用法:\n"
      "  intercom-server.exe [选项]\n\n"
      "选项:\n"
      "  --port <端口>        监听端口，默认 8080\n"
      "  --bind <地址>        监听地址，默认 127.0.0.1（仅本机）\n"
      "  --allow-lan          允许局域网直连（需要 --bind 0.0.0.0）\n"

      "  --data <目录>        数据目录，默认 exe 同级的 data\n"
      "  --accounts <目录>    账号目录，默认 主目录/~/.intercom\n"
      "  --public <目录>      前端目录，默认 exe 同级的 public\n"

      "  --add <用户名> [密码] [--display 展示名]   注册账号（省略密码则交互输入）\n"
      "  --passwd <用户名> [密码]        修改密码（省略密码则交互输入）\n"
      "  --un <旧用户> <新用户>          修改用户名\n"
      "  --del <用户>                    删除账号\n"
      "  --list                          列出账号\n"
      "  --help                          显示本帮助\n");
}

// 从标准输入读一行作为密码（不回显控制依赖终端，这里简单读取整行）
static std::string read_password_stdin() {
  std::fputs("请输入密码（回车结束）: ", stderr);
  std::fflush(stderr);
  std::string line;
  int c;
  while ((c = std::fgetc(stdin)) != EOF && c != '\n') {
    if (c != '\r') line.push_back(static_cast<char>(c));
  }
  return line;
}

static int run_cli(const std::vector<std::string> &argv) {
  size_t argc = argv.size();
  std::string accounts_dir;
  for (size_t i = 1; i < argc; ++i) {
    if (argv[i] == "--accounts" && i + 1 < argc) {
      accounts_dir = argv[++i];
      if (!std::filesystem::path(accounts_dir).is_absolute()) {
        accounts_dir = util::join_path(util::exe_dir(), accounts_dir);
      }
    }
  }
  auth::Store store(accounts_dir);  // 空串表示默认 ~/.intercom
  std::string err;
  if (!store.load(err)) {
    std::fprintf(stderr, "错误: %s\n", err.c_str());
    return 2;
  }

  int rc = 0;
  for (size_t i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--add" && i + 1 < argc) {
      std::string user = argv[++i];
      std::string pass;
      std::string display;
      if (i + 1 < argc && argv[i + 1] != "--display") {
        pass = argv[++i];
      } else {
        pass = read_password_stdin();   // 交互输入，密码里可以有空格
      }
      if (i + 1 < argc && argv[i + 1] == "--display" && i + 2 < argc) {
        i++;  // --display
        display = argv[++i];
      } else if (!pass.empty() && i + 1 < argc && argv[i + 1] != "--display" &&
                 !argv[i + 1].empty() && argv[i + 1][0] != '-') {
        // 兼容旧写法：--add 用户名 密码 展示名
        display = argv[++i];
      }
      auth::Status st = store.create(user, display, pass, err);
      if (st == auth::Status::Ok) std::printf("已注册用户 %s（%s）\n", user.c_str(), (display.empty() ? user.c_str() : display.c_str()));
      else {
        std::fprintf(stderr, "注册失败: %s\n", auth::status_text(st));
        rc = 1;
      }
    } else if (a == "--passwd" && i + 1 < argc) {
      std::string user = argv[++i];
      std::string pass;
      if (i + 1 < argc) pass = argv[++i]; else pass = read_password_stdin();
      auth::Status st = store.set_password(user, pass, err);
      if (st == auth::Status::Ok) std::printf("已修改密码 %s\n", user.c_str());
      else {
        std::fprintf(stderr, "修改失败: %s\n", auth::status_text(st));
        rc = 1;
      }
    } else if (a == "--un" && i + 2 < argc) {
      std::string oldu = argv[++i];
      std::string newu = argv[++i];
      auth::Status st = store.rename(oldu, newu, err);
      if (st == auth::Status::Ok)
        std::printf("已重命名 %s -> %s\n", oldu.c_str(), newu.c_str());
      else {
        std::fprintf(stderr, "重命名失败: %s\n", auth::status_text(st));
        rc = 1;
      }
    } else if (a == "--del" && i + 1 < argc) {
      std::string user = argv[++i];
      auth::Status st = store.remove(user, err);
      if (st == auth::Status::Ok) std::printf("已删除用户 %s\n", user.c_str());
      else {
        std::fprintf(stderr, "删除失败: %s\n", auth::status_text(st));
        rc = 1;
      }
    } else if (a == "--list") {
      // 只输出用户名，一行一个，便于脚本处理
      for (const auto &u : store.list()) {
        std::printf("%s\n", u.user.c_str());
      }
    }
  }
  return rc;
}

int main(int argc, char **argv) {
#if defined(_WIN32)
  ::SetConsoleOutputCP(CP_UTF8);  // 控制台中文输出
  WSADATA wsa;
  if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
    std::fprintf(stderr, "WSAStartup 失败\n");
    return 1;
  }
  (void)argc;
  (void)argv;
  const std::vector<std::string> args = utf8_args();
#else
  std::vector<std::string> args;
  for (int i = 0; i < argc; ++i) args.push_back(argv[i]);
#endif
  const size_t nargs = args.size();

  for (size_t i = 1; i < nargs; ++i) {
    const std::string &a = args[i];
    if (a == "--help" || a == "-h") {
      print_usage();
      return 0;
    }
  }

  // 命令行账号管理
  for (size_t i = 1; i < nargs; ++i) {
    const std::string &a = args[i];
    if (a == "--add" || a == "--passwd" || a == "--un" || a == "--del" || a == "--list") {
      return run_cli(args);
    }
  }

  for (size_t i = 1; i < nargs; ++i) {
    const std::string &a = args[i];
    if (a == "--port" && i + 1 < nargs) g_cfg.port = std::atoi(args[++i].c_str());
    else if (a == "--bind" && i + 1 < nargs) g_cfg.bind_host = args[++i];
    else if (a == "--data" && i + 1 < nargs) g_cfg.data_dir = args[++i];
    else if (a == "--accounts" && i + 1 < nargs) g_cfg.accounts_dir = args[++i];
    else if (a == "--public" && i + 1 < nargs) g_cfg.public_dir = args[++i];
    else if (a == "--allow-lan") g_cfg.loopback_only = false;
  }
  if (g_cfg.loopback_only) {
    g_cfg.bind_host = "127.0.0.1";
  } else if (g_cfg.bind_host == "127.0.0.1") {
    g_cfg.bind_host = "0.0.0.0";
  }

  std::string exe_base = util::exe_dir();
  if (!std::filesystem::path(g_cfg.data_dir).is_absolute()) {
    g_cfg.data_dir = util::join_path(exe_base, g_cfg.data_dir);
  }
  if (!std::filesystem::path(g_cfg.public_dir).is_absolute()) {
    g_cfg.public_dir = util::join_path(exe_base, g_cfg.public_dir);
  }
  if (!g_cfg.accounts_dir.empty() && !std::filesystem::path(g_cfg.accounts_dir).is_absolute()) {
    g_cfg.accounts_dir = util::join_path(exe_base, g_cfg.accounts_dir);
  }

  auth::Store store(g_cfg.accounts_dir);
  std::string err;
  if (!store.load(err)) {
    std::fprintf(stderr, "错误: %s\n", err.c_str());
    return 2;
  }
  g_store = &store;
  g_started_at = util::now_sec();

  httplib::Server server;

  configure_server(server);
  start_background_tasks();

  std::printf("\n  局域网对讲机 服务端\n");
  std::printf("  监听      http://%s:%d（对外 https 由 cloudflared 提供）\n", g_cfg.bind_host.c_str(),
              g_cfg.port);
  std::printf("  前端      %s\n", g_cfg.public_dir.c_str());
  std::printf("  账号目录  %s\n", store.dir().c_str());
  std::printf("  访问控制  %s\n",
              g_cfg.loopback_only ? "仅本机回环（只能经 cloudflared 隧道访问，公网 IP 无法直连）"
                                  : "已允许局域网/公网直连（--allow-lan）");
  std::printf("  存储策略  聊天内容、语音、视频全部只在内存中转发，不写入磁盘\n\n");

  if (!server.listen(g_cfg.bind_host.c_str(), g_cfg.port)) {
    std::fprintf(stderr, "错误: 无法监听 %s:%d\n", g_cfg.bind_host.c_str(), g_cfg.port);
    return 2;
  }
  return 0;
}