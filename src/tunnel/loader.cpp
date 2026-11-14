// 主程序侧的插件加载：探测 -> 动态加载 -> 校验 ABI -> 转发调用。
//
// 三条硬约束贯穿本文件：
//   1. 任何一步失败都只是"没有隧道"：失败原因攒进 reason_ 交给 /api/info，
//      不抛异常、不往 stderr 乱写，主程序照常服务局域网。
//   2. 插件是另一个编译单元的产物，它交回的是一张函数指针表，布局可能与我们的
//      头文件不同，所以每次取用前都校验 abi / struct_size / 必需函数。
//   3. 卸载必须先 stop：监督线程还活着就把库从地址空间里摘掉，等于在自己的
//      指令流上拆地板。
#include "tunnel/loader.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <string>
#include <system_error>
#include <vector>

#include "util.h"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace tunnel {

namespace {

#if defined(_WIN32)
// 入口返回的是插件里的 static 对象地址，DLL 卸载后即失效，所以只在加载期间取一次。
using RawHandle = HMODULE;
constexpr const char* kEnvVar = "COCHAT_TUNNEL_LIB";

const std::vector<std::string>& lib_names() {
  // CMake 在 Windows 上把 PREFIX 设成空，产物就是 cochat-tunnel.dll。
  static const std::vector<std::string> kNames{"cochat-tunnel.dll"};
  return kNames;
}

RawHandle open_lib(const std::string& path, std::string& error) {
  HMODULE h = ::LoadLibraryA(path.c_str());
  if (h == nullptr) {
    const DWORD code = ::GetLastError();
    error = "加载失败（Windows 错误 " + std::to_string(static_cast<unsigned long>(code)) + "：" +
            std::system_category().message(static_cast<int>(code)) + "）";
  }
  return h;
}

void close_lib(RawHandle h) {
  if (h != nullptr) ::FreeLibrary(h);
}

std::string symbol_error() {
  return "找不到导出符号 cochat_tunnel_entry（插件不是按 api.h 编出来的？）";
}

void* raw_symbol(RawHandle h, const char* name) { return reinterpret_cast<void*>(::GetProcAddress(h, name)); }
#else
using RawHandle = void*;
constexpr const char* kEnvVar = "COCHAT_TUNNEL_LIB";

const std::vector<std::string>& lib_names() {
  // CMake 的产物带 lib 前缀；开发/打包时有人手工改名成不带前缀的形式也要能找到。
  static const std::vector<std::string> kNames{"libcochat-tunnel.so", "cochat-tunnel.so"};
  return kNames;
}

RawHandle open_lib(const std::string& path, std::string& error) {
  void* h = ::dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
  if (h == nullptr) {
    const char* why = ::dlerror();
    error = std::string("加载失败（") + (why != nullptr ? why : "dlerror 未给出原因") + "）";
  }
  return h;
}

void close_lib(RawHandle h) {
  if (h != nullptr) ::dlclose(h);
}

std::string symbol_error() {
  return "找不到导出符号 cochat_tunnel_entry（插件不是按 api.h 编出来的？）";
}

void* raw_symbol(RawHandle h, const char* name) { return ::dlsym(h, name); }
#endif

// 入口签名：abi 不匹配时插件返回 nullptr，主程序据此区分"版本不符"与"加载失败"。
using EntryFn = const cochat_tunnel_api* (*)(std::uint32_t);

// 插件交回的界面是否可信：abi 必须完全一致（语义一变才升 abi），结构体不能比我们
// 知道的短（更长意味着未来加了字段，允许），核心函数指针不能缺。
bool validate_api(const cochat_tunnel_api* api, std::string& error) {
  if (api == nullptr) {
    error = "插件拒绝了这个 abi（cochat_tunnel_entry 返回空指针）";
    return false;
  }
  if (api->abi != COCHAT_TUNNEL_ABI) {
    error = "插件自报 abi " + std::to_string(api->abi) + "，本程序是 " +
            std::to_string(COCHAT_TUNNEL_ABI);
    return false;
  }
  if (api->struct_size < sizeof(cochat_tunnel_api)) {
    error = "插件交回的接口表比 api.h 短（" + std::to_string(api->struct_size) + " < " +
            std::to_string(sizeof(cochat_tunnel_api)) + "），布局对不上";
    return false;
  }
  if (api->version == nullptr || api->start == nullptr || api->stop == nullptr ||
      api->status == nullptr) {
    error = "插件接口表缺少必需函数（version/start/stop/status）";
    return false;
  }
  return true;
}

// 状态结构体里的 char[N] 同样只按字段宽度扫描，不假设对方一定以 NUL 结尾。
std::string field_str(const char* p, std::size_t cap) {
  if (p == nullptr) return std::string();
  std::size_t n = 0;
  while (n < cap && p[n] != '\0') ++n;
  return std::string(p, n);
}

std::string json_escape(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 8);
  for (const char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof buf, "\\u%04x",
                        static_cast<unsigned>(static_cast<unsigned char>(c)));
          out += buf;
        } else {
          out += c;
        }
    }
  }
  return out;
}

Status convert(const cochat_tunnel_status& raw) {
  // 逐字段赋值，绝不整体 memcpy：插件的 struct_size 可能比我们大，多出来的字段
  // 不在我们的内存布局里。
  Status st;
  st.loaded = true;
  st.running = raw.running != 0;
  st.connected = raw.connected != 0;
  st.registered = raw.registered != 0;
  st.quick = raw.quick != 0;
  st.requestsServed = raw.requests_served;
  st.hostname = field_str(raw.hostname, sizeof raw.hostname);
  st.location = field_str(raw.location, sizeof raw.location);
  st.uuid = field_str(raw.uuid, sizeof raw.uuid);
  st.error = field_str(raw.error, sizeof raw.error);
  return st;
}

// 一次加载尝试的结果，只为拼 reason_ 用。
struct Attempt {
  std::string path;
  std::string error;
};

// 把尝试记录拼成一句人话：这东西会原样出现在 /api/info，是用户唯一的线索。
std::string join_attempts(const std::vector<Attempt>& attempts, const std::string& head) {
  std::string why = head;
  for (std::size_t i = 0; i < attempts.size(); ++i) {
    why += (i == 0 ? "：" : "；");
    why += attempts[i].path + " " + attempts[i].error;
  }
  why += "；将以纯局域网模式运行";
  return why;
}

}  // namespace

std::string Status::url() const { return hostname.empty() ? std::string() : "https://" + hostname; }

std::string to_json(const Status& st) {
  // 状态一句话：先看可不可用，再按"注册 > 连接 > 线程在"的强弱顺序判断 ——
  // 注册成功必然蕴含前两者，反过来读会显示成"连接中"。
  std::string state = "未运行";
  if (!st.loaded) {
    state = "插件不可用";
  } else if (st.registered) {
    state = "已注册";
  } else if (st.connected) {
    state = "已连接边缘";
  } else if (st.running) {
    state = "连接中";
  }

  std::string out = "{";
  out += "\"loaded\":";
  out += st.loaded ? "true" : "false";
  out += ",\"running\":";
  out += st.running ? "true" : "false";
  out += ",\"connected\":";
  out += st.connected ? "true" : "false";
  out += ",\"registered\":";
  out += st.registered ? "true" : "false";
  out += ",\"quick\":";
  out += st.quick ? "true" : "false";
  out += ",\"requests\":" + std::to_string(static_cast<unsigned long long>(st.requestsServed));
  out += ",\"hostname\":\"" + json_escape(st.hostname) + "\"";
  out += ",\"url\":\"" + json_escape(st.url()) + "\"";
  out += ",\"location\":\"" + json_escape(st.location) + "\"";
  out += ",\"uuid\":\"" + json_escape(st.uuid) + "\"";
  out += ",\"version\":\"" + json_escape(st.version) + "\"";
  out += ",\"state\":\"" + json_escape(state) + "\"";
  out += ",\"error\":\"" + json_escape(st.error) + "\"}";
  return out;
}

void truncate_to(char* dst, std::size_t cap, const std::string& src) {
  if (dst == nullptr || cap == 0) return;
  const std::size_t n = src.size() < cap - 1 ? src.size() : cap - 1;
  if (n > 0) std::memcpy(dst, src.data(), n);
  dst[n] = '\0';
}

std::string fill_config(const Options& opts, cochat_tunnel_config& cfg) {
  cfg = cochat_tunnel_config{};
  cfg.abi = COCHAT_TUNNEL_ABI;
  // struct_size 填我们这份头文件的真实大小：插件据此只写它认识的字段。
  cfg.struct_size = static_cast<std::uint32_t>(sizeof cfg);

  std::string warnings;
  // 超长字段照样填（截断后仍可用），但要说出来：静默截断会让用户对着一个少了
  // 半截的令牌猜半天。
  auto put = [&](char* dst, std::size_t cap, const std::string& src, const char* what) {
    truncate_to(dst, cap, src);
    if (!src.empty() && src.size() >= cap) warnings += std::string("；") + what + " 过长已截断";
  };

  put(cfg.token, sizeof cfg.token, opts.token, "令牌");
  put(cfg.edge_host, sizeof cfg.edge_host, opts.edgeHost, "边缘地址");
  cfg.edge_port = opts.edgePort != 0 ? opts.edgePort : kDefaultEdgePort;
  put(cfg.edge_sni, sizeof cfg.edge_sni, opts.edgeSni, "边缘 SNI");
  put(cfg.origin_host, sizeof cfg.origin_host, opts.originHost, "origin 地址");
  cfg.origin_port = opts.originPort;  // 0 留给插件判（它有自己的默认值）
  cfg.connect_timeout_ms = opts.connectTimeoutMs;
  cfg.register_timeout_ms = opts.registerTimeoutMs;
  put(cfg.data_dir, sizeof cfg.data_dir, opts.dataDir, "数据目录");
  return warnings;
}

Loader::~Loader() { unload(); }

const cochat_tunnel_api* Loader::api_snapshot() const {
  std::lock_guard<std::mutex> lk(mu_);
  return api_;
}

void Loader::log_trampoline(void* user, int lvl, const char* line) {
  if (user == nullptr || line == nullptr) return;
  Loader* self = static_cast<Loader*>(user);
  LogFn fn;
  {
    std::lock_guard<std::mutex> lk(self->cbMu_);
    fn = self->log_;
  }
  if (!fn) return;
  // 上层回调抛出去会穿过插件的栈帧（另一个 libstdc++）：那是未定义行为，会直接
  // 终止进程。日志回调里出问题只能就地吞掉。
  try {
    fn(lvl, std::string(line));
  } catch (...) {
  }
}

void Loader::status_trampoline(void* user, const cochat_tunnel_status* st) {
  if (user == nullptr || st == nullptr) return;
  Loader* self = static_cast<Loader*>(user);
  Status snap = convert(*st);
  StatusFn fn;
  {
    std::lock_guard<std::mutex> lk(self->cbMu_);
    self->cached_ = snap;
    fn = self->onStatus_;
  }
  if (!fn) return;
  try {
    fn(snap);
  } catch (...) {
  }
}

bool Loader::load(std::string& error) {
  {
    std::lock_guard<std::mutex> lk(mu_);
    if (api_ != nullptr) {
      error.clear();
      return true;  // 已加载：重复 load 不必再来一遍
    }
  }

  // 探测顺序：exe 同目录 -> exe 同目录/plugins -> 环境变量显式路径。
  // 环境变量放最后：它是"开发者临时指一个别的构建"，不该压过随程序分发的那个。
  std::vector<Attempt> attempts;
  const std::string base = util::exe_dir();
  std::vector<std::string> dirs;
  if (!base.empty()) {
    dirs.push_back(base);
    dirs.push_back(util::join_path(base, "plugins"));
  }

  RawHandle found = nullptr;
  std::string foundPath;

  for (const auto& dir : dirs) {
    for (const auto& name : lib_names()) {
      const std::string candidate = util::join_path(dir, name);
      if (!util::file_exists(candidate)) continue;
      std::string why;
      RawHandle h = open_lib(candidate, why);
      if (h == nullptr) {
        attempts.push_back({candidate, why});
        continue;
      }
      found = h;
      foundPath = candidate;
      break;
    }
    if (found != nullptr) break;
  }

  // 环境变量：既可以给文件路径，也可以给目录（目录仍按平台惯例的文件名找）。
  if (found == nullptr) {
    const char* override_path = std::getenv(kEnvVar);
    if (override_path != nullptr && *override_path != '\0') {
      const std::string given(override_path);
      std::vector<std::string> candidates;
      if (util::file_exists(given)) {
        candidates.push_back(given);
      } else {
        for (const auto& name : lib_names()) candidates.push_back(util::join_path(given, name));
      }
      for (const auto& candidate : candidates) {
        std::string why;
        RawHandle h = open_lib(candidate, why);
        if (h == nullptr) {
          attempts.push_back({candidate, why});
          continue;
        }
        found = h;
        foundPath = candidate;
        break;
      }
    }
  }

  if (found == nullptr) {
    std::string head = "未找到隧道插件";
    if (attempts.empty()) {
      head += "（已查过 " + base + " 与 " + util::join_path(base, "plugins") + "，其中没有 " +
              lib_names().front() + "）";
    }
    const std::string why = join_attempts(attempts, head);
    {
      std::lock_guard<std::mutex> lk(mu_);
      reason_ = why;
    }
    error = why;
    return false;
  }

  void* sym = raw_symbol(found, "cochat_tunnel_entry");
  if (sym == nullptr) {
    close_lib(found);
    const std::vector<Attempt> attempts2{{foundPath, symbol_error()}};
    const std::string why = join_attempts(attempts2, "插件无法使用");
    {
      std::lock_guard<std::mutex> lk(mu_);
      reason_ = why;
    }
    error = why;
    return false;
  }

  EntryFn entry = reinterpret_cast<EntryFn>(sym);
  const cochat_tunnel_api* api = nullptr;
  try {
    api = entry(COCHAT_TUNNEL_ABI);
  } catch (...) {
    api = nullptr;  // C ABI 原则上不抛，但插件是别人的代码，不能假设
  }

  std::string refuse;
  if (!validate_api(api, refuse)) {
    close_lib(found);
    const std::vector<Attempt> attempts2{{foundPath, refuse}};
    const std::string why = join_attempts(attempts2, "插件版本不符");
    {
      std::lock_guard<std::mutex> lk(mu_);
      reason_ = why;
    }
    error = why;
    return false;
  }

  std::string version;
  try {
    const char* v = api->version();
    if (v != nullptr) version = v;
  } catch (...) {
    version.clear();  // 版本串只是展示用，取不到不该让整次加载失败
  }

  {
    std::lock_guard<std::mutex> lk(mu_);
    handle_ = found;
    api_ = api;
    path_ = foundPath;
    version_ = version;
    reason_.clear();  // 加载成功：reason 不再表示"不可用"
  }
  {
    // 缓存快照也要跟上，否则第一次状态回调到达前 status() 会报"未加载"。
    std::lock_guard<std::mutex> lk(cbMu_);
    cached_ = Status{};
    cached_.loaded = true;
    cached_.version = version;
  }
  error.clear();
  return true;
}

void Loader::unload() {
  const cochat_tunnel_api* api = nullptr;
  void* handle = nullptr;
  {
    std::lock_guard<std::mutex> lk(mu_);
    api = api_;
    handle = handle_;
  }
  // 先停机再卸载：监督线程还在跑时卸载库，它会走进已解除映射的代码。
  if (api != nullptr) {
    try {
      api->stop();
    } catch (...) {
    }
  }
  {
    std::lock_guard<std::mutex> lk(mu_);
    api_ = nullptr;
    handle_ = nullptr;
    path_.clear();
    version_.clear();
    reason_ = "未加载";
  }
  if (handle != nullptr) close_lib(static_cast<RawHandle>(handle));
  {
    std::lock_guard<std::mutex> lk(cbMu_);
    cached_ = Status{};
  }
}

bool Loader::available() const { return api_snapshot() != nullptr; }

std::string Loader::reason() const {
  std::lock_guard<std::mutex> lk(mu_);
  return reason_;
}

std::string Loader::path() const {
  std::lock_guard<std::mutex> lk(mu_);
  return path_;
}

void Loader::set_callbacks(LogFn log, StatusFn on_status) {
  std::lock_guard<std::mutex> lk(cbMu_);
  log_ = std::move(log);
  onStatus_ = std::move(on_status);
}

Status Loader::status() const {
  Status out;
  {
    std::lock_guard<std::mutex> lk(cbMu_);
    out = cached_;
  }
  {
    std::lock_guard<std::mutex> lk(mu_);
    out.version = version_;
    if (api_ == nullptr) {
      out.loaded = false;
      out.running = false;
      out.connected = false;
      out.registered = false;
      out.error = reason_;
      return out;
    }
    cochat_tunnel_status raw{};
    raw.abi = COCHAT_TUNNEL_ABI;
    // struct_size 由我们填：它描述"我分配了多大"，插件据此只写前缀。
    raw.struct_size = static_cast<std::uint32_t>(sizeof raw);
    int rc = -1;
    try {
      rc = api_->status(&raw);
    } catch (...) {
      rc = -1;
    }
    if (rc != 0) {
      out.loaded = false;
      out.error = "插件取状态失败（status 返回 " + std::to_string(rc) + "）";
      return out;
    }
    out = convert(raw);
    out.version = version_;
    return out;
  }
}

std::string Loader::status_json() const { return to_json(status()); }
int Loader::start(const Options& opts, std::string& error) {
  const cochat_tunnel_api* api = api_snapshot();
  if (api == nullptr) {
    // 没有插件不是错误：主程序必须能在这种状态下照常服务局域网。
    error = reason();
    return kNoPlugin;
  }
  cochat_tunnel_config cfg{};
  const std::string warnings = fill_config(opts, cfg);
  char err[512] = {0};
  const int rc = call_start(cfg, &Loader::log_trampoline, &Loader::status_trampoline,
                            static_cast<void*>(this), err, sizeof err);
  if (rc != 0) {
    error = err[0] != '\0' ? std::string(err) : "插件拒绝启动（返回 " + std::to_string(rc) + "）";
    return rc;
  }
  error = warnings;
  return 0;
}

void Loader::stop() {
  const cochat_tunnel_api* api = api_snapshot();
  if (api == nullptr) return;
  try {
    api->stop();
  } catch (...) {
  }
  {
    // 停机后插件不会再有回调；快照留 running=false，免得 /api/info 显示还在跑。
    std::lock_guard<std::mutex> lk(cbMu_);
    cached_.running = false;
    cached_.connected = false;
    cached_.registered = false;
  }
}

// 三个直通函数共用一条规矩：锁只用来"不出把接口指针用坏"。这里的调用都在
// 本进程自己的线程上、且插件不会反过来回调本类，所以持锁调用不会自锁；
// 唯一的例外是插件内部的日志/状态回调，它们只碰 cbMu_，见两个蹦床。
int Loader::call_start(const cochat_tunnel_config& cfg, cochat_tunnel_log_fn log,
                       cochat_tunnel_status_fn on_status, void* user, char* err,
                       std::size_t errlen) {
  const cochat_tunnel_api* api = api_snapshot();
  if (api == nullptr) return kNoPlugin;
  try {
    std::lock_guard<std::mutex> lk(mu_);
    // start() 按契约是非阻塞的（校验参数 + 起监督线程就返回），因此在这里持锁
    // 等它是安全的，也不会把插件的连接过程拖进锁里。
    return api->start(&cfg, log, on_status, user, err, errlen);
  } catch (...) {
    // 跨编译器边界的异常：只报告，绝不让主程序崩在隧道启动上。
    return kPluginThrew;
  }
}

int Loader::call_status(cochat_tunnel_status* out) {
  if (out == nullptr) return -1;
  const cochat_tunnel_api* api = api_snapshot();
  if (api == nullptr) return kNoPlugin;
  try {
    std::lock_guard<std::mutex> lk(mu_);
    return api->status(out);
  } catch (...) {
    return kPluginThrew;
  }
}

void Loader::call_set_log_level(int lvl) {
  const cochat_tunnel_api* api = api_snapshot();
  if (api == nullptr || api->set_log_level == nullptr) return;
  try {
    std::lock_guard<std::mutex> lk(mu_);
    api->set_log_level(lvl);
  } catch (...) {
  }
}

}  // namespace tunnel
