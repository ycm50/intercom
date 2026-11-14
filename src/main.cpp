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
#include <deque>
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
#include "instances.h"
#include "json.h"
#include "passwd.h"
#include "protocol.h"
#include "panel/panel.h"
#include "restart.h"
#include "tunnel/loader.h"
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
  // 隧道来源：auto（默认，有 --tunnel-url 就用它）/ off / url
  // 端口占用时可临时换端口，--cur/--res 都靠自述文件看到真实值。
  std::string tunnel_mode = "auto";
  std::string tunnel_url;         // --tunnel-url <公网地址>
  std::string tunnel_source;      // 实际生效的来源：plugin / cli / 空
  // 内建隧道插件：--tunnel 打开（不装插件也能跑，只是没有隧道）
  bool tunnel_enable = false;
  std::string tunnel_token;       // 命名隧道的连接令牌；空 = quick 隧道
};

Config g_cfg;
auth::Store *g_store = nullptr;
// 内建隧道插件。面板的隧道读数要反映"此刻"的真实状态（含插件注册到的域名），
// 而不是启动命令行里 --tunnel-url 写了什么 —— 后者只是一个静态声明。
// 声明成全局指针是因为面板回调注册得比插件加载早，只能按"调用时再读"取。
tunnel::Loader *g_tunnel_loader = nullptr;
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

// 日志环形缓冲：面板要能看到"刚才发生了什么"，而 stdout 已经被重定向到文件
// 或 systemd journal，浏览器拿不到。只留最近 kLogRing 行，不落盘。
constexpr size_t kLogRing = 500;
std::mutex g_log_mu;
std::deque<std::string> g_log_ring;

void log_line(const std::string &msg) {
  std::string line = "[" + util::now_string() + "] " + msg;
  std::fputs((line + "\n").c_str(), stdout);
  std::fflush(stdout);
  std::lock_guard<std::mutex> lk(g_log_mu);
  g_log_ring.push_back(line);
  // 只丢最老的：面板日志的价值在于"最近发生的事"，不是完整历史
  // （完整历史在 stdout / journal 里）。
  while (g_log_ring.size() > kLogRing) g_log_ring.pop_front();
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
  // 隧道状态：--cur 与 --res 直接读这里。url 非空 = 此刻真的能对外访问；
  // configured 为真但 url 为空 = 配了隧道但没连上（别把死链当成可用地址）。
  {
    jsonx::Json t;
    t["url"] = g_cfg.tunnel_url;
    t["source"] = g_cfg.tunnel_source;
    t["configured"] = !g_cfg.tunnel_url.empty() || g_cfg.tunnel_mode != "off";
    t["state"] = g_cfg.tunnel_url.empty()
                     ? (g_cfg.tunnel_mode == "off" ? "隧道已关闭" : "隧道未建立")
                     : "已连接";
    j["tunnel"] = t;
  }
  j["pid"] = static_cast<long long>(
#if defined(_WIN32)
      ::GetCurrentProcessId()
#else
      ::getpid()
#endif
  );
  j["started_at"] = static_cast<long long>(g_started_at.load());
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
      "  cochat [选项]\n\n"
      "服务:\n"
      "  --port <端口>        监听端口，默认 8080\n"
      "  --bind <地址>        监听地址，默认 127.0.0.1（仅本机）\n"
      "  --allow-lan          允许局域网直连（需要 --bind 0.0.0.0）\n"
      "  --data <目录>        数据目录，默认 exe 同级的 data\n"
      "  --accounts <目录>    账号目录，默认 主目录/~/.intercom\n"
      "  --public <目录>      前端目录，默认 exe 同级的 public\n"
      "  --tunnel-url <地址>  记录对外公网地址（https://xxx.trycloudflare.com），\n"
      "                       供 --cur 显示、供手机端检查；地址只是「现在对外是什么」，\n"
      "                       不改变服务本身的监听\n"
      "  --no-tunnel          明确声明没有隧道（--cur 会显示「隧道已关闭」）\n"
      "  --tunnel             启用内建隧道插件（编了插件才可用；缺插件时只是没有隧道）\n"
      "  --tunnel-token <令牌> 命名隧道的连接令牌；给了它自动启用隧道，留空则用 quick 隧道\n"
      "\n"
      "查看与运维:\n"
      "  --cur                列出本机正在运行的实例及其公网地址\n"
      "                       加 --data <目录> 只看那一个实例；配 --port 直连指定端口\n"
      "  --res [pid]          重启一个正在运行的实例；不给 pid 时重启 pid 最小的那个。\n"
      "                       systemd 托管的走 systemctl restart，手工启动的按原命令行重放\n"
      "\n"
      "账号管理:\n"
      "  --add <用户名> [密码] [--display 展示名]   注册账号（省略密码则交互输入）\n"
      "  --passwd <用户名> [新密码]      修改密码（省略密码则交互输入）\n"
      "  --passwd --check <用户名> [密码] 核对密码：账号文件 + 运行中的服务两头都验\n"
      "  --un <旧用户> <新用户>          修改用户名\n"
      "  --del <用户>                    删除账号\n"
      "  --list                          列出账号\n"
      "  --help, -h                      显示本帮助\n");
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
      // admin 是面板账号，只能改密码，不能新建/删除/改名。命令行这一层也要拦，
      // 否则运维一条 --del admin 就永久失去面板入口，而服务还在跑、无法自救。
      if (panel::is_reserved_user(user)) {
        std::fprintf(stderr,
                     "error: %s 是面板保留账号，不能用 --add 新建/覆盖。改密码请用 "
                     "--passwd %s\n",
                     panel::kAdminUser, panel::kAdminUser);
        rc = 1;
        continue;
      }
      auth::Status st = store.create(user, display, pass, err);
      if (st == auth::Status::Ok) std::printf("已注册用户 %s（%s）\n", user.c_str(), (display.empty() ? user.c_str() : display.c_str()));
      else {
        std::fprintf(stderr, "注册失败: %s\n", auth::status_text(st));
        rc = 1;
      }
    } else if (a == "--passwd") {
      // --passwd 已经统一交给 app::run_passwd_cli 处理（见 main 的预扫描），
      // 这里再出现说明它和别的账号管理参数写在了同一行，明确拒绝而不是猜。
      std::fprintf(stderr, "error: --passwd 不能和 --add/--del/--un 混用\n");
      return 2;
    } else if (a == "--un" && i + 2 < argc) {
      std::string oldu = argv[++i];
      std::string newu = argv[++i];
      // 源和目标都要拦：admin -> other 会让面板失去账号，
      // other -> admin 会占用保留名，两种都是把自己锁在门外。
      if (panel::is_reserved_user(oldu) || panel::is_reserved_user(newu)) {
        std::fprintf(stderr,
                     "error: %s 是面板保留账号，不能改名（源或目标都不行）\n",
                     panel::kAdminUser);
        rc = 1;
        continue;
      }
      auth::Status st = store.rename(oldu, newu, err);
      if (st == auth::Status::Ok)
        std::printf("已重命名 %s -> %s\n", oldu.c_str(), newu.c_str());
      else {
        std::fprintf(stderr, "重命名失败: %s\n", auth::status_text(st));
        rc = 1;
      }
    } else if (a == "--del" && i + 1 < argc) {
      std::string user = argv[++i];
      if (panel::is_reserved_user(user)) {
        std::fprintf(stderr,
                     "error: %s 是面板保留账号，不能删除（否则再也进不去 /admin）\n",
                     panel::kAdminUser);
        rc = 1;
        continue;
      }
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

  // ---- 运维类参数必须在加载账号库、绑定端口之前处理 ----
  // 它们要么是来"看"一个已经跑着的实例，要么是来"重启"它；先启动自己再发现
  // 端口被占，会得到一条看不懂的"无法监听"错误。
  {
    bool cur_requested = false;
    bool res_requested = false;
    bool passwd_requested = false;
    bool check_only = false;
    bool force = false;
    std::string res_pid;
    std::string cur_data;
    std::string accounts_dir;
    int cur_port = 0;
    std::vector<std::string> passwd_args;

    for (size_t i = 1; i < nargs; ++i) {
      const std::string &a = args[i];
      if (a == "--cur") {
        cur_requested = true;
      } else if (a == "--res") {
        // --res <pid> 重启指定实例；--res 单独出现时重启 pid 最小的那个。
        // 非数字参数是打错了，不是"没给 pid"——静默回退会重启一个无关实例。
        res_requested = true;
        if (i + 1 < nargs && args[i + 1].rfind("--", 0) != 0) {
          const std::string &v = args[i + 1];
          bool numeric = !v.empty();
          for (char c : v) {
            if (c < '0' || c > '9') {
              numeric = false;
              break;
            }
          }
          if (!numeric) {
            std::fprintf(stderr, "error: --res 需要数字 pid，收到 '%s'\n", v.c_str());
            return 2;
          }
          res_pid = args[++i];
        }
      } else if (a == "--passwd") {
        passwd_requested = true;
        while (i + 1 < nargs && args[i + 1].rfind("--", 0) != 0) passwd_args.push_back(args[++i]);
      } else if (a == "--check") {
        check_only = true;
      } else if (a == "--force") {
        force = true;
      } else if (a == "--accounts" && i + 1 < nargs) {
        accounts_dir = args[++i];
        if (!std::filesystem::path(accounts_dir).is_absolute()) {
          accounts_dir = util::join_path(util::exe_dir(), accounts_dir);
        }
      } else if (a == "--data" && i + 1 < nargs) {
        cur_data = args[++i];
      } else if (a == "--port" && i + 1 < nargs) {
        cur_port = std::atoi(args[++i].c_str());
      } else if (!a.empty() && a[0] != '-') {
        // 裸位置参数只可能是 --passwd 的「用户名 密码」；--passwd 后面紧跟
        // --check 时，它们不会被 --passwd 那个分支吃走，所以在这里收。
        passwd_args.push_back(a);
      }
    }
    if (cur_requested) return app::print_current_tunnels(cur_data, cur_port);
    if (res_requested) return app::restart_instance(res_pid);
    if (passwd_requested) {
      return app::run_passwd_cli(accounts_dir, passwd_args, check_only, force);
    }
  }

  // 命令行账号管理
  for (size_t i = 1; i < nargs; ++i) {
    const std::string &a = args[i];
    if (a == "--add" || a == "--un" || a == "--del" || a == "--list") {
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
    else if (a == "--tunnel-url" && i + 1 < nargs) {
      g_cfg.tunnel_url = args[++i];
      g_cfg.tunnel_mode = "url";
      g_cfg.tunnel_source = "cli";
    } else if (a == "--no-tunnel") {
      g_cfg.tunnel_mode = "off";
      g_cfg.tunnel_url.clear();
      g_cfg.tunnel_source.clear();
      g_cfg.tunnel_enable = false;
    } else if (a == "--tunnel") {
      // 打开内建隧道插件。插件不存在时不是错误：主程序照常跑，只是没有隧道。
      g_cfg.tunnel_enable = true;
      if (g_cfg.tunnel_mode == "off") g_cfg.tunnel_mode = "auto";
    } else if (a == "--tunnel-token" && i + 1 < nargs) {
      // 命名隧道的连接令牌；给了它就自动打开隧道，省得写两个参数。
      g_cfg.tunnel_token = args[++i];
      g_cfg.tunnel_enable = true;
      if (g_cfg.tunnel_mode == "off") g_cfg.tunnel_mode = "auto";
    }
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

  // 自述文件：让 cochat --cur / --res 看得见"这个进程是怎么被启动的"。
  // Windows 上读不到别人的命令行，这份文件是 --res 原样重启的唯一依据，
  // 所以失败要显式说出来，而不是悄悄没有。
  {
    std::string cwd;
    std::error_code ec;
    cwd = std::filesystem::current_path(ec).string();
    if (ec) cwd.clear();
    std::string rec_err;
    if (!app::write_instance_record(args.empty() ? std::string("cochat") : args[0], args, cwd,
                                    g_cfg.data_dir, g_cfg.bind_host, g_cfg.port, g_cfg.tunnel_url,
                                    rec_err)) {
      std::fprintf(stderr, "警告: 无法写入实例自述（--cur/--res 会看不到本进程）: %s\n",
                   rec_err.c_str());
    } else {
      app::prune_instance_records();
    }
  }

  std::printf("\n  局域网对讲机 服务端\n");
  std::printf("  监听      http://%s:%d（对外 https 由 cloudflared 提供）\n", g_cfg.bind_host.c_str(),
              g_cfg.port);
  std::printf("  前端      %s\n", g_cfg.public_dir.c_str());
  std::printf("  账号目录  %s\n", store.dir().c_str());
  std::printf("  访问控制  %s\n",
              g_cfg.loopback_only ? "仅本机回环（只能经 cloudflared 隧道访问，公网 IP 无法直连）"
                                  : "已允许局域网/公网直连（--allow-lan）");
  if (!g_cfg.tunnel_url.empty()) {
    std::printf("  公网地址  %s\n", g_cfg.tunnel_url.c_str());
  } else if (g_cfg.tunnel_mode == "off") {
    std::printf("  公网地址  （已声明没有隧道，--cur 会显示「隧道已关闭」）\n");
  } else {
    std::printf("  公网地址  （未配置；起了隧道后用 --tunnel-url 告知，--cur 才看得到）\n");
  }
  std::printf("  存储策略  聊天内容、语音、视频全部只在内存中转发，不写入磁盘\n\n");

  // 隧道加载器必须在面板接线之前声明：面板的隧道读数是"调用时再取"，
  // 但它拿的是这个对象的地址，对象得先存在。
  tunnel::Loader tunnel_loader;
  g_tunnel_loader = &tunnel_loader;

  // ---- 管理面板 ------------------------------------------------------------
  // 面板挂在同一个 httplib::Server 的 /admin 前缀下，因此"仅回环/仅隧道来源"
  // 这条访问控制、CSP 头、超时全部自动继承，不需要为它再造一套监听。
  //
  // admin 账号：第一次启动自动建一个随机密码并打印一次；已存在则绝不覆盖。
  // 面板装不起来不是错误 —— 聊天服务照常提供。
  {
    std::string gen_pwd;
    std::string admin_err;
    if (!panel::ensure_admin(store, gen_pwd, admin_err)) {
      std::fprintf(stderr, "警告: 无法保证面板账号可用: %s\n", admin_err.c_str());
    } else if (!gen_pwd.empty()) {
      // 不用方框：中文字符宽度不固定，框线在终端里永远对齐不了，
      // 反而让密码那一行看起来像排版坏了。分行打印更清楚。
      std::printf("\n  ── 管理面板 ─────────────────────────────────\n");
      std::printf("  地址      /admin\n");
      std::printf("  账号      admin\n");
      std::printf("  密码      %s\n", gen_pwd.c_str());
      std::printf("  ────────────────────────────────────────────\n");
      std::printf("  这串密码只显示这一次。改密码：\n");
      std::printf("    cochat --passwd admin          （命令行）\n");
      std::printf("    面板内「账号」标签下的「改密」  （登录之后）\n\n");
      log_line("管理面板账号已创建：admin");
    }

    panel::Host host;
    host.store = &store;
    // info/stats：面板要看到和服务自己一致的读数，所以复用同一批原子量，
    // 而不是另算一份（两份数字对不上会让运维怀疑哪边是对的）。
    // 这两个直接读全局量、不捕获局部变量：回调会被面板长期持有，
    // 捕引用会在 main 返回后悬垂；而且这些全局量本来就是唯一真相。
    host.info_json = []() {
      jsonx::Json j;
      j["name"] = "局域网对讲机";
      j["uptime"] = static_cast<long long>(util::now_sec() - g_started_at.load());
      j["online"] = static_cast<long long>(g_hub.online_count());
      j["rooms"] = static_cast<long long>(g_hub.room_count());
      j["bind"] = g_cfg.bind_host + ":" + std::to_string(g_cfg.port);
      j["data_dir"] = g_cfg.data_dir;
      j["accounts_dir"] = g_store ? g_store->dir() : std::string();
      j["loopback_only"] = g_cfg.loopback_only;
      // 面板要显示"这台机器什么时候起来的"：给绝对时间戳，格式化交给前端
      // （前端按浏览器时区渲染，服务端只保证给出一个无歧义的 Unix 秒）。
      j["started_at"] = static_cast<long long>(g_started_at.load());
      j["pid"] = static_cast<long long>(
#if defined(_WIN32)
          ::GetCurrentProcessId()
#else
          ::getpid()
#endif
      );
      return jsonx::dump(j);
    };
    host.stats_json = []() {
      jsonx::Json j;
      j["messages"] = static_cast<long long>(g_msg_count.load());
      j["media"] = static_cast<long long>(g_media_count.load());
      j["signals"] = static_cast<long long>(g_signal_count.load());
      return jsonx::dump(j);
    };
    host.tunnel_json = []() {
      jsonx::Json t;
      // 插件在位时以它为准：它知道"此刻"连没连上、域名是什么。
      // g_cfg 里的 tunnel_url 只在没有插件（外部 cloudflared）时才有意义。
      if (g_tunnel_loader != nullptr && g_tunnel_loader->available()) {
        const tunnel::Status st = g_tunnel_loader->status();
        t["url"] = st.url();
        t["source"] = st.url().empty() ? std::string() : std::string("plugin");
        t["configured"] = true;
        t["plugin"] = true;
        t["version"] = st.version;
        if (st.connected && st.registered) {
          t["state"] = "已连接";
        } else if (st.connected) {
          t["state"] = "已连边缘，注册中";
        } else if (!st.error.empty()) {
          t["state"] = "连接失败：" + st.error;
        } else {
          t["state"] = "正在连接";
        }
      } else {
        t["url"] = g_cfg.tunnel_url;
        t["source"] = g_cfg.tunnel_source;
        t["configured"] = !g_cfg.tunnel_url.empty() || g_cfg.tunnel_mode != "off";
        t["plugin"] = false;
        t["state"] = g_cfg.tunnel_url.empty()
                         ? (g_cfg.tunnel_mode == "off" ? "隧道已关闭" : "隧道未建立")
                         : "已连接（外部 cloudflared）";
      }
      return jsonx::dump(t);
    };
    host.instances_json = []() {
      // 实例列表直接复用 --cur 的那套发现逻辑（含自述文件与活体探测），
      // 面板自己再扫一遍 /proc 只会得到另一份可能不一致的结果。
      jsonx::Json arr = jsonx::Json::array();
      for (auto inst : app::discover_instances()) {
        // 面板上的"状态"就是 --cur 那一列，所以复用同一个探测函数：
        // 面板自己再打一次 /api/info 只会得到另一份可能不一致的结果。
        app::describe_instance(inst);
        jsonx::Json o;
        o["pid"] = static_cast<long long>(inst.pid);
        o["port"] = inst.port;
        o["url"] = inst.public_url;
        o["state"] = inst.state;
        o["data_dir"] = inst.data_dir;
        std::string cmd;
        for (size_t i = 0; i < inst.argv.size(); ++i) cmd += (i ? " " : "") + inst.argv[i];
        o["argv"] = cmd;
        arr.push_back(o);
      }
      return jsonx::dump(arr);
    };
    host.logs_json = []() {
      jsonx::Json arr = jsonx::Json::array();
      std::lock_guard<std::mutex> lk(g_log_mu);
      for (const auto &line : g_log_ring) arr.push_back(jsonx::Json(line));
      return jsonx::dump(arr);
    };
    host.log = [](const std::string &line) { log_line(line); };
    host.restart_instance = [](const std::string &pid) {
      // 面板里的"重启"复用 --res 的实现：同样先验 pid 仍是 cochat，同样区分
      // systemd 托管与手工启动。这里不另写一套，否则两处规则迟早分叉。
      const int rc = app::restart_instance(pid);
      return std::make_pair(rc == 0, rc == 0 ? "已发出重启" : "重启失败，详见服务端日志");
    };
    // 账号动作集中在 panel::install_account_actions 里填（保留名规则只写一处）。
    panel::install_account_actions(store, host);

    std::string panel_err;
    if (!panel::register_routes(static_cast<void *>(&server), host, g_cfg.public_dir,
                                g_cfg.data_dir, panel_err)) {
      std::printf("  管理面板  未启用（%s）\n", panel_err.c_str());
    } else {
      std::printf("  管理面板  http://%s:%d/admin\n", g_cfg.bind_host.c_str(), g_cfg.port);
    }
  }

  // 先 bind 再起隧道，最后才 accept：隧道要连的 origin 就是本进程这个端口，
  // 端口还没绑上就去转发，头几个请求必然 502。bind_to_port + listen_after_bind
  // 正好把"端口已被占用"和"开始接请求"拆成两步。
  if (!server.bind_to_port(g_cfg.bind_host.c_str(), g_cfg.port)) {
    app::remove_instance_record();
    std::fprintf(stderr, "错误: 无法监听 %s:%d（端口被占用？用 cochat --cur 看有没有实例在跑）\n",
                 g_cfg.bind_host.c_str(), g_cfg.port);
    return 2;
  }

  // ---- 内建隧道插件 --------------------------------------------------------
  // 加载失败一律不是错误：可能没编插件（缺 OpenSSL）、可能被安全软件拦下、
  // 可能版本不符。这三种都只表达成"没有隧道"，服务照样提供局域网访问。
  if (g_cfg.tunnel_enable && g_cfg.tunnel_mode != "off") {
    std::string load_err;
    if (!tunnel_loader.load(load_err)) {
      std::printf("  内建隧道  未启用（%s）\n", tunnel_loader.reason().c_str());
    } else {
      // 排障开关：COCHAT_TUNNEL_LOG=3 打开 debug 级进度（平时只打 error/warn，
      // 否则一条健康隧道会把服务端输出刷满）。
      const char *tlog = std::getenv("COCHAT_TUNNEL_LOG");
      const int tunnel_lvl = tlog != nullptr ? std::atoi(tlog) : 1;
      tunnel_loader.call_set_log_level(tunnel_lvl);
      tunnel_loader.set_callbacks(
          [tunnel_lvl](int lvl, const std::string &line) {
            if (lvl <= tunnel_lvl) std::fprintf(stderr, "[tunnel] %s\n", line.c_str());
          },
          [](const tunnel::Status &st) {
            // 边缘给出域名后同步进 /api/info，--cur 就能看到公网地址。
            if (!st.hostname.empty()) {
              g_cfg.tunnel_url = "https://" + st.hostname;
              g_cfg.tunnel_source = "plugin";
            }
          });

      tunnel::Options opts;
      opts.token = g_cfg.tunnel_token;
      opts.originPort = static_cast<std::uint16_t>(g_cfg.port);
      opts.dataDir = g_cfg.data_dir;
      std::string err;
      if (tunnel_loader.start(opts, err) != 0) {
        std::printf("  内建隧道  启动失败（%s）\n", err.c_str());
      } else {
        std::printf("  内建隧道  已启动（%s），公网地址注册完成后用 --cur 查看\n",
                    g_cfg.tunnel_token.empty() ? "quick 隧道" : "命名隧道");
      }
    }
  }

  const bool listened = server.listen_after_bind();
  // listen 返回意味着服务该退出了：这时才撤掉自述文件（启动期间它正是
  // --cur 能看见本进程的依据，早删就等于自己没有实例记录）。
  app::remove_instance_record();
  tunnel_loader.stop();
  if (!listened) {
    std::fprintf(stderr, "错误: 监听失败（%s:%d）\n", g_cfg.bind_host.c_str(), g_cfg.port);
    return 2;
  }
  return 0;
}