#include "auth.h"

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "../crypto.h"
#include "../json.h"
#include "../util.h"

#if !defined(_WIN32)
#include <sys/stat.h>
#endif

namespace panel {

namespace {

// 令牌和 CSRF 各取 32 字节安全随机（十六进制后 64 字符）。
// 为什么是 32 而不是 16：两者都是不记名凭证，多 16 字节的代价是零，
// 而暴破空间直接从 2^128 抬到 2^256，再也不必论证"够不够"。
constexpr size_t kTokenBytes = 32;

// 同时存活的会话上限。面板的实际使用者是"同一个人 + 一两个脚本"，
// 128 已经宽裕；没有上限的话每次登录追加一条，过期条目虽会被清理，
// 活跃条目仍能无限增长，落盘文件也就跟着长。
constexpr size_t kMaxSessions = 128;

constexpr const char *kSessionsFile = "admin-sessions.json";

/* --------------------------- 内存会话表 --------------------------- */

// 进程内只有一张表：一个进程只服务一个 data_dir（多开就是多进程）。
// 落盘文件是真相来源（重启后要能捡回来），内存表只是它的缓存 ——
// 所以每次写都要落盘，每次读都要确认缓存与当前 data_dir 对得上。
struct Table {
  std::mutex mu;
  std::string dir;        // 缓存对应的 data_dir
  bool loaded = false;    // dir 里的 loaded 为 false 表示还没从磁盘读过
  std::vector<Session> rows;
};

// 函数内 static：C++11 起初始化本身线程安全，不需要手写的双检锁。
// 面板并发度极低（就是一个人在点页面），一把粗锁足够，也比"按 data_dir
// 分桶锁"少一大片竞争窗口。
Table &table() {
  static Table t;
  return t;
}

/* ----------------------------- 基础工具 ----------------------------- */

// 恒定时间比较：src/crypto.h 只有哈希/随机数，没有 compare 原语；
// auth.cpp 里那份是文件内部 static 函数、不导出。所以这里自己写一份：
// 逐字节累加异或差，不做"不同就提前 return" —— 那条提前返回的分支
// 本身就是"前几位相同"的时间侧信道。
// 长度不等直接 false：令牌长度是编译期常量，隐藏"长度不对"没有意义。
bool constant_time_equals(const std::string &a, const std::string &b) {
  if (a.size() != b.size()) return false;
  unsigned char diff = 0;
  for (size_t i = 0; i < a.size(); ++i) {
    diff |= static_cast<unsigned char>(a[i] ^ b[i]);
  }
  return diff == 0;
}

// 令牌必须来自 crypto::random_bytes（Windows 走 BCryptGenRandom，POSIX 走
// getrandom），绝不能用 rand()/时间戳这类弱源：弱源能被猜中，就等于把
// 管理权限交给猜中的人。随机源失败时返回空串，由调用方当作"登录失败"，
// 不做任何"退化成可预测值"的降级。
std::string random_hex() {
  unsigned char raw[kTokenBytes];
  if (!crypto::random_bytes(raw, sizeof(raw))) return std::string();
  return util::hex_encode(raw, sizeof(raw));
}

std::string sessions_path(const std::string &data_dir) {
  return util::join_path(data_dir, kSessionsFile);
}

// 落盘文件里装的是活令牌：读到它就能直接冒充 admin（连密码都不用）。
// POSIX 上收成 0600；Windows 下不加 ACL —— 服务本来就以运维自己的账号
// 运行，手工 DACL 一旦写错就是"换个账号启动后再也进不去"的现场事故。
void restrict_permissions(const std::string &path) {
#if defined(_WIN32)
  (void)path;  // 见上：Windows 用默认权限，只在此说明原因
#else
  ::chmod(path.c_str(), S_IRUSR | S_IWUSR);
#endif
}

// 从落盘文件解析会话；格式坏掉就当作"没有会话"（宁可让运维重新登录，
// 也不能把半个 JSON 读成一条合法会话）。过期判断留给调用方统一做。
bool parse_rows(const std::string &text, std::vector<Session> &out) {
  jsonx::Json root;
  if (!jsonx::Json::parse(text, root) || !root.is_object()) return false;
  auto it = root.find("sessions");
  if (it == root.end() || !it->is_array()) return false;

  for (const auto &item : *it) {
    if (!item.is_object()) continue;
    Session s;
    s.token = jsonx::str(item, "token");
    s.csrf = jsonx::str(item, "csrf");
    s.user = jsonx::str(item, "user");
    s.expires_at = jsonx::num(item, "expires_at");
    // 缺字段的条目一律丢弃：文件可能被外部改写（备份恢复、手工编辑），
    // 半个会话比没有会话更危险 —— 空 CSRF 会让写操作绕过 CSRF 校验。
    if (s.token.empty() || s.csrf.empty() || s.user.empty() || s.expires_at <= 0) continue;
    out.push_back(std::move(s));
  }
  return true;
}

// 落盘失败只返回 false 不抛：磁盘满、目录只读都会走到这里，而这时内存表
// 仍然有效、服务照常可用。把"写不进去"升级成"登录失败"只会让运维彻底
// 进不去面板，代价远大于"重启后需要重新登录一次"。
bool save_rows(const std::string &data_dir, const std::vector<Session> &rows) {
  // 用 jsonx 的对象而不是手拼字符串：token 是纯十六进制虽然安全，
  // 但 user 是外部输入（未来若允许别的账号进面板，手拼就会破 JSON）。
  jsonx::Json root = jsonx::Json::object();
  jsonx::Json arr = jsonx::Json::array();
  for (const auto &s : rows) {
    jsonx::Json o = jsonx::Json::object();
    o["token"] = s.token;
    o["csrf"] = s.csrf;
    o["user"] = s.user;
    o["expires_at"] = jsonx::Json(static_cast<long long>(s.expires_at));
    arr.push_back(o);
  }
  root["sessions"] = arr;

  std::string path = sessions_path(data_dir);
  // 原子写：面板可能正好在服务端被杀的一瞬间落盘，半截文件会让下次启动
  // 把所有会话读废（虽不致命，但"所有人都被踢下线"很难查）。
  std::string err;
  if (!util::write_file_atomic(path, root.dump(), err)) return false;
  restrict_permissions(path);
  return true;
}

// 确保内存表对应 data_dir。切换 data_dir 时整表丢弃：否则 A 实例的令牌
// 会在 B 实例上通过校验 —— 两个实例本是两个独立服务，不该共享管理会话。
void ensure_loaded(Table &t, const std::string &data_dir) {
  if (t.loaded && t.dir == data_dir) return;
  t.dir = data_dir;
  t.rows.clear();
  std::string text;
  if (util::read_file(sessions_path(data_dir), text)) {
    if (!parse_rows(text, t.rows)) t.rows.clear();
  }
  t.loaded = true;
}

// 清掉过期条目。返回是否真的有变化 —— 调用方靠它决定要不要写回磁盘，
// 否则每个 GET /status 都会触发一次文件写。
bool prune(Table &t, std::int64_t now) {
  size_t before = t.rows.size();
  std::vector<Session> keep;
  keep.reserve(before);
  for (auto &s : t.rows) {
    if (s.expires_at > now) keep.push_back(std::move(s));
  }
  t.rows = std::move(keep);
  return t.rows.size() != before;
}

// 按令牌找会话。返回的是表内元素的指针，只在持锁期间有效（调用方都在
// lock_guard 的生存期内用它，不会有指针逃逸）。
Session *find(Table &t, const std::string &token, std::int64_t now) {
  for (auto &s : t.rows) {
    if (s.expires_at <= now) continue;
    if (constant_time_equals(s.token, token)) return &s;
  }
  return nullptr;
}

}  // namespace

/* ------------------------------ 会话生命周期 ------------------------------ */

Session create_session(const std::string &data_dir, const std::string &user) {
  Session s;
  s.token = random_hex();
  s.csrf = random_hex();
  s.user = user;
  std::int64_t now = util::now_sec();
  s.expires_at = now + kSessionTtlSeconds;
  // 随机源失败时不能"拿时间戳顶上"：那等于把令牌变成可猜的。
  if (s.token.empty() || s.csrf.empty()) return Session();

  Table &t = table();
  std::lock_guard<std::mutex> lk(t.mu);
  ensure_loaded(t, data_dir);
  prune(t, now);  // 顺手清干净，写回时文件里就只剩活着的会话
  if (t.rows.size() >= kMaxSessions) {
    // 淘汰最早到期的：它最接近过期，丢它损失的可用时间最少。
    size_t victim = 0;
    for (size_t i = 1; i < t.rows.size(); ++i) {
      if (t.rows[i].expires_at < t.rows[victim].expires_at) victim = i;
    }
    t.rows.erase(t.rows.begin() + static_cast<std::ptrdiff_t>(victim));
  }
  t.rows.push_back(s);
  // 登录必须落盘：这就是"重启后不用重新登录"的全部实现。
  save_rows(data_dir, t.rows);
  return s;
}

bool check_session(const std::string &data_dir, const std::string &token, bool require_csrf,
                   const std::string &csrf, std::string &out_user, Session *out_session) {
  out_user.clear();
  // 空令牌提前返回：否则 token="" 会去匹配表里"任何空令牌"的记录，
  // 而空令牌是"没带 Cookie"的取值，绝不能算通过。
  if (token.empty()) return false;

  std::int64_t now = util::now_sec();
  Table &t = table();
  std::lock_guard<std::mutex> lk(t.mu);
  ensure_loaded(t, data_dir);
  bool changed = prune(t, now);

  Session *found = find(t, token, now);
  if (found == nullptr) {
    if (changed) save_rows(data_dir, t.rows);  // 顺手把过期项写掉
    return false;
  }

  // CSRF 与令牌是同一次登录发的，但走两条通道：Cookie 由浏览器自动携带，
  // 自定义头不会 —— 能带上 X-CSRF-Token 就说明请求来自面板页面本身，
  // 而不是某个跨站表单。比较也必须恒定时间，否则等于把 CSRF 变成可暴破的。
  if (require_csrf && !constant_time_equals(found->csrf, csrf)) return false;

  out_user = found->user;
  if (out_session) *out_session = *found;
  // 只有真的清掉了过期条目才写回：check 是热路径（每个非登录请求都过一次），
  // 每次都落盘等于把每个 GET 都变成一次磁盘写入。
  if (changed) save_rows(data_dir, t.rows);
  return true;
}

std::string session_csrf(const std::string &data_dir, const std::string &token) {
  if (token.empty()) return std::string();
  std::int64_t now = util::now_sec();
  Table &t = table();
  std::lock_guard<std::mutex> lk(t.mu);
  ensure_loaded(t, data_dir);
  // 内存里顺手清掉过期项即可：读接口不落盘（GET /status 不该有写副作用），
  // 真正的文件清理由登录 / 注销时的那次写回完成。
  (void)prune(t, now);
  Session *found = find(t, token, now);
  if (found == nullptr) return std::string();
  return found->csrf;
}

void revoke_session(const std::string &data_dir, const std::string &token) {
  if (token.empty()) return;
  std::int64_t now = util::now_sec();
  Table &t = table();
  std::lock_guard<std::mutex> lk(t.mu);
  ensure_loaded(t, data_dir);
  prune(t, now);

  std::vector<Session> keep;
  keep.reserve(t.rows.size());
  bool removed = false;
  for (auto &s : t.rows) {
    if (constant_time_equals(s.token, token)) {
      removed = true;
      continue;
    }
    keep.push_back(std::move(s));
  }
  t.rows = std::move(keep);
  // 幂等：令牌本就不存在时不必写盘（没变化），但也不能报错 ——
  // 注销是"让当前会话失效"，什么样的失败都不该拦住用户退出。
  if (removed) save_rows(data_dir, t.rows);
}

/* ------------------------------ 请求头解析 ------------------------------ */

std::string token_from_request(const std::string &cookie_header,
                               const std::string &authorization_header) {
  // 先查 Cookie（浏览器路径）。Cookie 值里可能有 base64 的 + / =，
  // 所以正确做法是"按 ; 切出各个 pair，再取每个 pair 第一个 = 之后的部分"，
  // 不能按 = 全局切（会把值里的 padding 切碎），也不能因为值里有 = 就当成
  // 多个键值对。RFC 6265 保证值里不含 ;，所以按 ; 切是安全的。
  for (const std::string &raw : util::split(cookie_header, ';')) {
    std::string pair = util::trim(raw);
    if (pair.empty()) continue;
    size_t eq = pair.find('=');
    if (eq == std::string::npos) continue;
    if (util::trim(pair.substr(0, eq)) != kCookieName) continue;
    std::string value = util::trim(pair.substr(eq + 1));
    // 引号包裹（"..."）也是合法 Cookie 语法，剥掉再返回：
    // 前端若用 document.cookie 手工拼，很容易带上引号。
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
      value = value.substr(1, value.size() - 2);
    }
    if (!value.empty()) return value;
  }

  // 再查 Authorization（脚本路径，curl -H "Authorization: Bearer xxx"）。
  // 方案名大小写不敏感（各家客户端写法并不统一），令牌本身原样保留。
  std::string auth = util::trim(authorization_header);
  const std::string scheme = "bearer";
  if (auth.size() <= scheme.size()) return std::string();
  if (util::to_lower(auth.substr(0, scheme.size())) != scheme) return std::string();
  std::string rest = util::trim(auth.substr(scheme.size()));
  return rest;
}

}  // namespace panel
