#include "instances.h"

#include "../third_party/httplib.h"
#include "json.h"
#include "util.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>
#else
#include <dirent.h>
#include <signal.h>
#include <unistd.h>
#include <cerrno>
#endif

namespace app {

namespace {

std::string g_record_path;  // 本进程的自述文件路径（退出时删除）

long self_pid() {
#if defined(_WIN32)
  return static_cast<long>(::GetCurrentProcessId());
#else
  return static_cast<long>(::getpid());
#endif
}

}  // namespace

// pid 还活着吗。Windows 上用 SYNCHRONIZE + 零超时等待，POSIX 上 kill(pid, 0)。
bool process_alive(long pid) {
  if (pid <= 0) return false;
#if defined(_WIN32)
  HANDLE h = ::OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                           static_cast<DWORD>(pid));
  if (!h) return false;  // 打不开就当作不存在：--cur 只列能确认的实例
  const DWORD rc = ::WaitForSingleObject(h, 0);
  ::CloseHandle(h);
  return rc == WAIT_TIMEOUT;
#else
  return ::kill(static_cast<pid_t>(pid), 0) == 0 || errno == EPERM;
#endif
}

// 取进程的可执行文件名。拿不到就返回空，调用方要按"不确定"处理。
std::string process_image_name(long pid) {
  if (pid <= 0) return std::string();
#if defined(_WIN32)
  HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
  if (!h) return std::string();
  wchar_t buf[MAX_PATH * 2];
  DWORD len = static_cast<DWORD>(sizeof(buf) / sizeof(buf[0]));
  std::string out;
  if (::QueryFullProcessImageNameW(h, 0, buf, &len)) {
    const int need = ::WideCharToMultiByte(CP_UTF8, 0, buf, static_cast<int>(len), nullptr, 0,
                                           nullptr, nullptr);
    if (need > 0) {
      out.resize(static_cast<size_t>(need));
      ::WideCharToMultiByte(CP_UTF8, 0, buf, static_cast<int>(len), &out[0], need, nullptr, nullptr);
    }
  }
  ::CloseHandle(h);
  return out;
#else
  char link[4096];
  const std::string path = "/proc/" + std::to_string(pid) + "/exe";
  const ssize_t n = ::readlink(path.c_str(), link, sizeof(link) - 1);
  if (n <= 0) return std::string();
  link[n] = '\0';
  return std::string(link);
#endif
}

namespace {

std::string base_name(const std::string &p) {
  const auto slash = p.find_last_of("\\/");
  return slash == std::string::npos ? p : p.substr(slash + 1);
}

}  // namespace

// cochat / cochat.exe / cochat-linux-amd64 都算；cochatx 不算。
bool looks_like_cochat_name(const std::string &exe) {
  std::string name = util::to_lower(base_name(exe));
  if (name.size() > 4 && name.compare(name.size() - 4, 4, ".exe") == 0) name.resize(name.size() - 4);
  if (name == "cochat") return true;
  return name.size() > 6 && name.compare(0, 6, "cochat") == 0 &&
         (name[6] == '-' || name[6] == '_' || name[6] == '.');
}

namespace {

bool looks_like_cochat(const std::string &exe) { return looks_like_cochat_name(exe); }

// 统一的路径比较：相对路径按当前工作目录展开，反斜杠统一成正斜杠。
std::string normalize_path(const std::string &p) {
  if (p.empty()) return p;
  std::error_code ec;
  std::filesystem::path fp(p);
  if (!fp.is_absolute()) {
    fp = std::filesystem::absolute(fp, ec);
    if (ec) return p;
  }
  std::string s = fp.lexically_normal().string();
  std::replace(s.begin(), s.end(), '\\', '/');
  while (s.size() > 1 && s.back() == '/') s.pop_back();
#if defined(_WIN32)
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
#endif
  return s;
}

std::string read_all(const std::string &path) {
  std::string out;
  std::ifstream in(path.c_str(), std::ios::binary);
  if (!in) return out;
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

#if !defined(_WIN32)
// 下面两个只在扫描 /proc 时用得到；Windows 上读不到别的进程命令行。
bool parse_args_info(const std::vector<std::string> &argv, std::string &data_dir,
                     std::string &bind_host, int &port, bool &port_known) {
  port_known = false;
  for (size_t i = 1; i < argv.size(); ++i) {
    if (argv[i] == "--port" && i + 1 < argv.size()) {
      port = std::atoi(argv[i + 1].c_str());
      port_known = true;
    } else if (argv[i] == "--bind" && i + 1 < argv.size()) {
      bind_host = argv[i + 1];
    } else if (argv[i] == "--data" && i + 1 < argv.size()) {
      data_dir = argv[i + 1];
    }
  }
  return port_known;
}
#endif

// 读取一个 <pid>.json 自述文件。返回 false 表示文件损坏或不是 cochat 的。
bool load_record(const std::string &path, Instance &out) {
  const std::string text = read_all(path);
  if (text.empty()) return false;
  jsonx::Json j;
  if (!jsonx::parse(text, j) || !j.is_object()) return false;
  out.pid = static_cast<long>(jsonx::num(j, "pid", 0));
  if (out.pid <= 0) return false;
  out.exe = jsonx::str(j, "exe");
  out.cwd = jsonx::str(j, "cwd");
  out.data_dir = jsonx::str(j, "data_dir");
  out.bind_host = jsonx::str(j, "bind_host");
  out.port = static_cast<int>(jsonx::num(j, "port", 8080));
  out.port_known = true;
  out.public_url = jsonx::str(j, "tunnel_url");
  out.tunnel_source = jsonx::str(j, "tunnel_source");
  out.started_at = jsonx::num(j, "started_at", 0);
  auto it = j.find("argv");
  if (it != j.end() && it->is_array()) {
    for (const auto &v : *it)
      if (v.is_string()) out.argv.push_back(v.as_string());
  }
  if (out.argv.empty()) out.argv.push_back(out.exe);
  out.alive = process_alive(out.pid);
  out.from_record = true;
  return true;
}

#if !defined(_WIN32)
std::vector<std::string> split_nul(const std::string &raw) {
  std::vector<std::string> out;
  std::string cur;
  for (char c : raw) {
    if (c == '\0') {
      out.push_back(cur);
      cur.clear();
    } else {
      cur.push_back(c);
    }
  }
  if (!cur.empty()) out.push_back(cur);
  return out;
}
#endif

#if !defined(_WIN32)
void scan_proc(std::vector<Instance> &found) {
  DIR *dir = ::opendir("/proc");
  if (!dir) return;
  const long self = self_pid();
  while (dirent *ent = ::readdir(dir)) {
    const char *name = ent->d_name;
    if (name[0] < '0' || name[0] > '9') continue;
    long pid = 0;
    // 不用 std::strtol：glibc 2.38+ 会把它重定向到 __isoc23_strtol，
    // 在 Debian 12 上就是"符号找不到、程序起不来"（详见 util.h 的说明）。
    if (!util::parse_long(name, pid)) continue;
    if (pid == self) continue;
    if (std::any_of(found.begin(), found.end(), [pid](const Instance &i) { return i.pid == pid; }))
      continue;  // 自述文件里已经有了
    const std::string base = std::string("/proc/") + name + "/";
    std::vector<std::string> args = split_nul(read_all(base + "cmdline"));
    if (args.empty() || !looks_like_cochat(args[0])) continue;

    Instance inst;
    inst.pid = pid;
    inst.argv = args;
    inst.exe = args[0];
    char link[4096];
    const ssize_t n = ::readlink((base + "cwd").c_str(), link, sizeof(link) - 1);
    if (n > 0) {
      link[n] = '\0';
      inst.cwd = link;
    }
    parse_args_info(inst.argv, inst.data_dir, inst.bind_host, inst.port, inst.port_known);
    if (!inst.port_known) inst.port = 8080;
    inst.alive = true;
    found.push_back(std::move(inst));
  }
  ::closedir(dir);
}
#else
// Windows 上读不到别的进程的命令行，只能列出 pid；端口与数据目录来自自述文件。
void scan_toolhelp(std::vector<Instance> &found) {
  HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) return;
  PROCESSENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  const DWORD self = ::GetCurrentProcessId();
  if (::Process32FirstW(snap, &entry)) {
    do {
      if (entry.th32ProcessID == self) continue;
      std::wstring wide(entry.szExeFile);
      std::string exe;
      for (wchar_t wc : wide) exe.push_back(wc < 128 ? static_cast<char>(wc) : '?');
      if (!looks_like_cochat(exe)) continue;
      const long pid = static_cast<long>(entry.th32ProcessID);
      if (std::any_of(found.begin(), found.end(),
                      [pid](const Instance &i) { return i.pid == pid; }))
        continue;
      Instance inst;
      inst.pid = pid;
      inst.exe = exe;
      inst.argv.push_back(exe);
      inst.alive = true;
      found.push_back(std::move(inst));
    } while (::Process32NextW(snap, &entry));
  }
  ::CloseHandle(snap);
}
#endif

}  // namespace

// 问活着的进程自己：隧道通不通、地址是多少。只有它知道。
InstanceProbe probe_instance(int port) {
  InstanceProbe probe;
  if (port <= 0) return probe;
  httplib::Client cli("127.0.0.1", port);
  cli.set_connection_timeout(1, 0);
  cli.set_read_timeout(2, 0);
  // 本地命令行给自己发一个只有命令行才会带的头，将来若 /api/info 收紧权限，
  // 这里不需要再改（浏览器导航拿不到这个头）。
  httplib::Headers headers;
  headers.emplace("X-Intercom-Cli", "1");
  auto res = cli.Get("/api/info", headers);
  if (!res || res->status != 200) {
    if (res) probe.status = res->status;
    return probe;
  }
  jsonx::Json j;
  if (!jsonx::parse(res->body, j) || !j.is_object()) return probe;
  probe.ok = true;
  probe.status = 200;
  auto t = j.find("tunnel");
  if (t != j.end() && t->is_object()) {
    probe.tunnel_url = jsonx::str(*t, "url");
    probe.tunnel_state = jsonx::str(*t, "state");
    probe.tunnel_source = jsonx::str(*t, "source");
    probe.tunnel_configured = jsonx::boolean(*t, "configured", false);
  }
  return probe;
}

// 补上"此刻状态"。单独暴露出来而不是塞进 discover_instances：--res 只需要
// pid 和 argv，为每个实例都发一次 HTTP 探测纯属浪费，而探测还可能因为实例
// 卡住而拖慢重启。
void describe_instance(Instance &inst) {
  // 自述文件里的地址先兜底：进程重启或暂时连不上时它仍然是"上次对外的地址"。
  std::string fallback = inst.public_url;
  const InstanceProbe probe = probe_instance(inst.port);
  if (probe.ok) {
    if (!probe.tunnel_url.empty()) inst.public_url = probe.tunnel_url;
    if (!probe.tunnel_state.empty()) inst.state = probe.tunnel_state;
    if (!probe.tunnel_source.empty()) inst.tunnel_source = probe.tunnel_source;
    inst.alive = true;
    if (inst.state.empty()) inst.state = probe.tunnel_configured ? "隧道已配置未连接" : "无隧道";
  } else if (!fallback.empty()) {
    inst.state = "无响应（地址来自自述文件）";
    inst.public_url = fallback;
  } else {
    inst.state = probe.status == 403 ? "拒绝访问（需要登录）" : "无响应";
  }
}

namespace {

void print_row(const Instance &inst) {
  std::string url = inst.public_url.empty() ? "(无隧道)" : inst.public_url;
  std::printf("%-8ld %-6d %-46s %-24s", inst.pid, inst.port, url.c_str(), inst.state.c_str());
  if (!inst.tunnel_source.empty()) std::printf(" [%s]", inst.tunnel_source.c_str());
  std::printf("\n");
  if (!inst.data_dir.empty()) std::printf("         数据目录 %s\n", inst.data_dir.c_str());
  if (inst.argv.size() > 1) {
    std::printf("         命令行  ");
    for (size_t i = 0; i < inst.argv.size(); ++i) std::printf("%s%s", i ? " " : "", inst.argv[i].c_str());
    std::printf("\n");
  }
}

}  // namespace

std::string instances_dir() {
  return util::join_path(util::join_path(util::home_dir(), ".intercom"), "instances");
}

bool write_instance_record(const std::string &exe, const std::vector<std::string> &argv,
                           const std::string &cwd, const std::string &data_dir,
                           const std::string &bind_host, int port, const std::string &tunnel_url,
                           std::string &err) {
  const std::string dir = instances_dir();
  if (!util::make_dirs(dir, err)) return false;
  jsonx::Json j;
  j["version"] = 1;
  j["pid"] = static_cast<long long>(self_pid());
  j["exe"] = exe;
  jsonx::Json arr = jsonx::Json::array();
  for (const auto &a : argv) arr.push_back(jsonx::Json(a));
  j["argv"] = arr;
  j["cwd"] = cwd;
  j["data_dir"] = data_dir;
  j["bind_host"] = bind_host;
  j["port"] = port;
  j["tunnel_url"] = tunnel_url;
  // 最后加载的都是隧道插件本身，来源一眼看得出（外部 cloudflared 时为空）
  j["tunnel_source"] = tunnel_url.empty() ? "" : "plugin";
  j["started_at"] = static_cast<long long>(util::now_sec());
  j["started_human"] = util::now_string();
  const std::string path = util::join_path(dir, std::to_string(self_pid()) + ".json");
  if (!util::write_file_atomic(path, j.dump(), err)) return false;
  g_record_path = path;
  return true;
}

void remove_instance_record() {
  if (g_record_path.empty()) return;
  std::string err;
  util::remove_file(g_record_path, err);
  g_record_path.clear();
}

void prune_instance_records() {
  const std::string dir = instances_dir();
  for (const auto &path : util::list_files(dir, ".json")) {
    const std::string name = base_name(path);
    long pid = 0;
    if (!util::parse_long(name.c_str(), pid)) continue;
    // 文件名不是 pid.json 的（比如手工放进去的）不动，删掉别人的自述才是事故。
    if (pid <= 0 || !util::starts_with(name, std::to_string(pid) + ".")) continue;
    if (pid == self_pid()) continue;
    if (process_alive(pid)) continue;
    std::string err;
    util::remove_file(path, err);
  }
}

std::vector<Instance> discover_instances() {
  std::vector<Instance> found;
  for (const auto &path : util::list_files(instances_dir(), ".json")) {
    Instance inst;
    if (!load_record(path, inst)) continue;
    if (!inst.alive) continue;  // 死掉的自述留给 prune_instance_records 清理
    found.push_back(std::move(inst));
  }
#if !defined(_WIN32)
  scan_proc(found);
#else
  scan_toolhelp(found);
#endif
  std::sort(found.begin(), found.end(),
            [](const Instance &a, const Instance &b) { return a.pid < b.pid; });
  return found;
}

int print_current_tunnels(const std::string &data_override, int port_override) {
  // 先清掉死进程留下的自述：被强杀（或 --res 的旧进程）时会残留，
  // 留着只会让下一次 --cur 把没人接管的文件当成实例。
  prune_instance_records();
  std::vector<Instance> instances;
  if (!data_override.empty()) {
    const std::string want = normalize_path(data_override);
    for (auto &inst : discover_instances()) {
      if (normalize_path(inst.data_dir) == want) instances.push_back(inst);
    }
    if (instances.empty()) {
      // 没有自述文件时仍然尝试直连：老版本二进制不会有自述。
      Instance inst;
      inst.data_dir = data_override;
      inst.port = port_override > 0 ? port_override : 8080;
      inst.port_known = true;
      const InstanceProbe probe = probe_instance(inst.port);
      if (!probe.ok) {
        std::fprintf(stderr,
                     "在 %s 没有找到运行中的实例，127.0.0.1:%d 也连不上（连不上时请用 --port 指定端口）\n",
                     data_override.c_str(), inst.port);
        return 1;
      }
      instances.push_back(std::move(inst));
    }
  } else {
    instances = discover_instances();
    if (instances.empty()) {
      std::printf("没有找到运行中的 cochat 实例\n");
      return 1;
    }
  }

  std::printf("%-8s %-6s %-46s %-24s\n", "pid", "端口", "公网地址", "状态");
  for (auto &inst : instances) {
    describe_instance(inst);
    print_row(inst);
  }
  return 0;
}

}  // namespace app
