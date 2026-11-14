#include "restart.h"

#include "instances.h"
#include "util.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cerrno>
#endif

namespace app {

namespace {

#if !defined(_WIN32)
std::string base_name(const std::string &p) {
  const auto slash = p.find_last_of("\\/");
  return slash == std::string::npos ? p : p.substr(slash + 1);
}

long self_pid() { return static_cast<long>(::getpid()); }
#endif

// 重启完成后等一小会儿，把新进程真正对外服务的地址打出来。
// 旧地址在这一刻已经随旧进程失效，直接打印它会把操作者引到死链上。
void wait_for_tunnel(const Instance &info, const std::string &previous_url) {
  constexpr int kTries = 40;  // 40 x 500ms = 20s
  std::string last;
  int stable = 0;
  for (int i = 0; i < kTries; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    const InstanceProbe probe = probe_instance(info.port);
    if (!probe.ok) continue;
    if (probe.tunnel_url.empty()) continue;
    if (probe.tunnel_url != last) {
      last = probe.tunnel_url;
      stable = 0;
      continue;
    }
    if (++stable < 2) continue;  // 连续两次一致才算稳定
    if (probe.tunnel_url != previous_url) {
      std::printf("  新公网地址: %s\n", probe.tunnel_url.c_str());
    } else {
      std::printf("  公网地址: %s（未变化）\n", probe.tunnel_url.c_str());
    }
    std::fflush(stdout);
    return;
  }
  if (!last.empty()) {
    std::printf("  公网地址: %s（仍在建立中）\n", last.c_str());
  } else {
    std::printf("  （20 秒内没有等到新公网地址；稍后用 cochat --cur 再看）\n");
  }
  std::fflush(stdout);
}

#if !defined(_WIN32)

struct ProcInfo {
  long pid = 0;
  std::vector<std::string> argv;
  std::string cwd;
  std::string cgroup;
};

std::string read_all(const std::string &path) {
  std::string out;
  int fd = ::open(path.c_str(), O_RDONLY);
  if (fd < 0) return out;
  char buf[4096];
  for (;;) {
    const ssize_t n = ::read(fd, buf, sizeof(buf));
    if (n <= 0) break;
    out.append(buf, static_cast<std::size_t>(n));
  }
  ::close(fd);
  return out;
}

// 只认 cochat 本体：cochat、cochat.exe、cochat-linux-amd64 都算，cochatx 不算。
bool looks_like_cochat(const std::vector<std::string> &argv) {
  if (argv.empty()) return false;
  std::string name = util::to_lower(base_name(argv[0]));
  if (name.size() > 4 && name.compare(name.size() - 4, 4, ".exe") == 0) name.resize(name.size() - 4);
  if (name == "cochat") return true;
  return name.size() > 6 && name.compare(0, 6, "cochat") == 0 &&
         (name[6] == '-' || name[6] == '_' || name[6] == '.');
}

ProcInfo read_proc(long pid) {
  ProcInfo info;
  info.pid = pid;
  const std::string base = "/proc/" + std::to_string(pid) + "/";
  const std::string raw = read_all(base + "cmdline");
  std::string cur;
  for (char c : raw) {
    if (c == '\0') {
      info.argv.push_back(cur);
      cur.clear();
    } else {
      cur.push_back(c);
    }
  }
  if (!cur.empty()) info.argv.push_back(cur);
  char link[4096];
  const ssize_t n = ::readlink((base + "cwd").c_str(), link, sizeof(link) - 1);
  if (n > 0) {
    link[n] = '\0';
    info.cwd = link;
  }
  info.cgroup = read_all(base + "cgroup");
  return info;
}

std::vector<ProcInfo> discover_proc() {
  std::vector<ProcInfo> found;
  DIR *dir = ::opendir("/proc");
  if (!dir) return found;
  const long self = self_pid();
  while (dirent *ent = ::readdir(dir)) {
    const char *name = ent->d_name;
    if (name[0] < '0' || name[0] > '9') continue;
    long pid = 0;
    // 不用 std::strtol：glibc 2.38+ 会把它重定向到 __isoc23_strtol，
    // 目标机 glibc 较老时整个程序起不来（详见 util.h 的说明）。
    if (!util::parse_long(name, pid)) continue;
    if (pid == self) continue;  // 绝不重启自己
    ProcInfo info = read_proc(pid);
    if (info.argv.empty()) continue;  // 读目录与读 cmdline 之间进程没了
    if (!looks_like_cochat(info.argv)) continue;
    found.push_back(std::move(info));
  }
  ::closedir(dir);
  std::sort(found.begin(), found.end(),
            [](const ProcInfo &a, const ProcInfo &b) { return a.pid < b.pid; });
  return found;
}

// 托管这个进程的 systemd unit；手工启动时为空。从 cgroup 读，而不是
// systemctl status <pid>：后者在容器里不一定有，输出也不稳定。
std::string unit_from_cgroup(const std::string &raw) {
  std::string cgroup = raw;
  while (!cgroup.empty() && (cgroup.back() == '\n' || cgroup.back() == '\r' ||
                             cgroup.back() == ' ' || cgroup.back() == '\t')) {
    cgroup.pop_back();
  }
  std::string unit;
  std::size_t start = 0;
  while (start <= cgroup.size()) {
    const std::size_t end = cgroup.find('/', start);
    std::string part =
        cgroup.substr(start, end == std::string::npos ? std::string::npos : end - start);
    if (part.size() > 8 && part.compare(part.size() - 8, 8, ".service") == 0) unit = part;
    if (end == std::string::npos) break;
    start = end + 1;
  }
  return unit;
}

bool unit_exists(const std::string &unit) {
  static const char *kDirs[] = {"/etc/systemd/system", "/run/systemd/system",
                                "/usr/lib/systemd/system", "/lib/systemd/system"};
  for (const char *dir : kDirs) {
    struct stat st {};
    if (::stat((std::string(dir) + "/" + unit).c_str(), &st) == 0) return true;
  }
  return false;
}

int run_and_wait(const std::vector<std::string> &argv, const std::string &cwd) {
  if (argv.empty()) return -1;
  std::vector<char *> cargv;
  cargv.reserve(argv.size() + 1);
  for (const auto &a : argv) cargv.push_back(const_cast<char *>(a.c_str()));
  cargv.push_back(nullptr);
  const pid_t pid = ::fork();
  if (pid < 0) return -1;
  if (pid == 0) {
    if (!cwd.empty() && ::chdir(cwd.c_str()) != 0) ::_exit(127);
    ::execvp(cargv[0], cargv.data());
    ::_exit(127);
  }
  int status = 0;
  while (::waitpid(pid, &status, 0) < 0) {
    if (errno != EINTR) return -1;
  }
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

bool terminate_process(long pid) {
  if (::kill(static_cast<pid_t>(pid), SIGTERM) != 0 && errno != ESRCH) return false;
  for (int waited = 0; waited < 100; ++waited) {  // 最多 10 秒
    if (!process_alive(pid)) return true;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  if (::kill(static_cast<pid_t>(pid), SIGKILL) != 0 && errno != ESRCH) return false;
  for (int waited = 0; waited < 30; ++waited) {
    if (!process_alive(pid)) return true;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  return !process_alive(pid);
}

void print_command(const ProcInfo &info) {
  std::printf("  pid %ld: %s", info.pid, info.argv.empty() ? "" : info.argv[0].c_str());
  for (std::size_t i = 1; i < info.argv.size(); ++i) std::printf(" %s", info.argv[i].c_str());
  std::printf("\n");
  if (!info.cwd.empty()) std::printf("  cwd    : %s\n", info.cwd.c_str());
}

int restart_one(const ProcInfo &info) {
  print_command(info);
  // pid 会被回收：从读到 /proc 到动手之间，目标可能已经退出、pid 被别的进程
  // 复用。杀掉一个无关进程是这里能犯的最严重的错误，所以动手前再确认一次。
  const std::string image = process_image_name(info.pid);
  if (image.empty()) {
    std::fprintf(stderr, "error: pid %ld 已经不在了\n", info.pid);
    return 1;
  }
  if (!looks_like_cochat({image})) {
    std::fprintf(stderr, "error: pid %ld 现在是 %s，不是 cochat（pid 可能被复用）\n", info.pid,
                 image.c_str());
    return 1;
  }
  Instance inst;
  inst.pid = info.pid;
  inst.argv = info.argv;
  for (std::size_t i = 1; i + 1 < info.argv.size(); ++i) {
    if (info.argv[i] == "--port") inst.port = std::atoi(info.argv[i + 1].c_str());
  }
  const InstanceProbe before = probe_instance(inst.port);
  const std::string previous_url = before.ok ? before.tunnel_url : std::string();

  const std::string unit = unit_from_cgroup(info.cgroup);
  if (!unit.empty() && unit_exists(unit)) {
    // systemd 托管：重启 unit。直接杀 pid 会丢掉 unit 的 Restart= 策略、环境变量
    // 和 cgroup 限制——unit 才是"这个进程应该怎么跑"的权威描述。
    std::printf("  由 systemd unit %s 托管 -> systemctl restart %s\n", unit.c_str(), unit.c_str());
    const int rc = run_and_wait({"systemctl", "restart", unit}, "");
    if (rc != 0) {
      std::fprintf(stderr, "error: systemctl restart %s 失败（退出码 %d）\n", unit.c_str(), rc);
      return 1;
    }
    wait_for_tunnel(inst, previous_url);
    return 0;
  }
  if (!unit.empty()) {
    std::printf("  cgroup 指向 %s，但该 unit 不存在，按手工启动处理\n", unit.c_str());
  }

  // 手工启动：原样重放 argv。操作者的命令行参数是这个实例唯一的"怎么跑"描述，
  // 不做任何重建或规范化。
  //
  // 【顺序】必须先 fork 再 terminate。目标 pid 可能就是本进程（面板点"重启"
  // 就是这种情况），先 terminate 的话本进程当场消失，后面的 fork 根本执行不到，
  // 现场表现就是"点了重启，服务没了"。Windows 那边同理（见 spawn_replacement_win）。
  const pid_t pid = ::fork();
  if (pid < 0) {
    std::fprintf(stderr, "error: fork 失败: %s\n", std::strerror(errno));
    return 1;
  }
  if (pid == 0) {
    // 脱离：调用者马上就退出，新实例必须比它活得久。
    ::setsid();
    if (!info.cwd.empty() && ::chdir(info.cwd.c_str()) != 0) ::_exit(127);
    int devnull = ::open("/dev/null", O_RDWR);
    if (devnull >= 0) {
      ::dup2(devnull, STDIN_FILENO);
      ::dup2(devnull, STDOUT_FILENO);
      ::dup2(devnull, STDERR_FILENO);
      if (devnull > STDERR_FILENO) ::close(devnull);
    }
    std::vector<char *> cargv;
    cargv.reserve(info.argv.size() + 1);
    for (const auto &a : info.argv) cargv.push_back(const_cast<char *>(a.c_str()));
    cargv.push_back(nullptr);
    ::execvp(cargv[0], cargv.data());
    ::_exit(127);
  }
  // 孩子要么成为新实例，要么在 execvp 里死掉。先确认再报成功。
  for (int waited = 0; waited < 30; ++waited) {
    if (!process_alive(pid)) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  if (!process_alive(pid)) {
    std::fprintf(stderr, "error: 替换进程立刻退出了；%s 可能已被移动或删除\n",
                 info.argv.empty() ? "?" : info.argv[0].c_str());
    return 1;
  }
  std::printf("  已用同样的参数启动 pid %d\n", static_cast<int>(pid));

  // 新实例已经在跑，这时才收掉旧进程。
  //
  // 目标是本进程时不再 terminate：从"自己"里面杀"自己"，之后一行代码都不会
  // 执行，wait_for_tunnel 也没机会确认新实例真的对外服务。直接退出更诚实 ——
  // 新进程会重新写自述文件，调用方刷新就能看到。
  if (info.pid == self_pid()) {
    std::printf("  本实例即将退出，新实例已接管\n");
    std::fflush(stdout);
    // 给 HTTP 响应一点时间发出去（面板上的"重启"要能先拿到结果，
    // 否则浏览器看到的是连接被重置，用户会以为点坏了）。
    std::this_thread::sleep_for(std::chrono::milliseconds(400));
    ::_exit(0);
  }

  if (!terminate_process(info.pid)) {
    std::fprintf(stderr, "error: pid %ld 没有退出\n", info.pid);
    return 1;
  }
  wait_for_tunnel(inst, previous_url);
  return 0;
}

int restart_posix(const std::string &pid_arg) {
  std::vector<ProcInfo> targets;
  if (!pid_arg.empty()) {
    const char *end = nullptr;
    long pid = 0;
    // 整串必须都是数字：parse_long 允许尾随垃圾（与 strtol 一致），
    // 所以这里额外要求 end 指到结尾 —— "123abc" 不该被当成 pid 123。
    if (!util::parse_long(pid_arg.c_str(), pid, &end) || end == nullptr || *end != '\0' ||
        pid <= 0) {
      std::fprintf(stderr, "error: --res 需要数字 pid，收到 '%s'\n", pid_arg.c_str());
      return 1;
    }
    ProcInfo info = read_proc(pid);
    if (info.argv.empty()) {
      std::fprintf(stderr, "error: 没有 pid %ld 的进程\n", pid);
      return 1;
    }
    if (!looks_like_cochat(info.argv)) {
      std::fprintf(stderr, "error: pid %ld 不是 cochat（%s）\n", pid, info.argv[0].c_str());
      return 1;
    }
    targets.push_back(std::move(info));
  } else {
    targets = discover_proc();
    if (targets.empty()) {
      std::fprintf(stderr, "error: 没有找到运行中的 cochat 进程\n");
      return 1;
    }
    if (targets.size() > 1) {
      std::printf("cochat --res: 发现 %zu 个 cochat 进程，重启 pid 最小的那个（%ld）\n",
                  targets.size(), targets.front().pid);
    }
    targets.resize(1);
  }
  return restart_one(targets.front());
}

#else  // _WIN32

// Windows 命令行参数的通用转义：空串、含空格/引号/制表符的参数都要包起来。
std::wstring quote_arg(const std::wstring &arg) {
  if (!arg.empty() && arg.find_first_of(L" \t\n\v\"") == std::wstring::npos) return arg;
  std::wstring out = L"\"";
  for (wchar_t c : arg) {
    if (c == L'"') out += L"\\\"";
    else out.push_back(c);
  }
  out += L"\"";
  return out;
}

std::wstring widen(const std::string &s) {
  if (s.empty()) return std::wstring();
  const int len = ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
  std::wstring out(static_cast<size_t>(len), L'\0');
  if (len > 0) ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), &out[0], len);
  return out;
}

// argv[0] 可能只是 "cochat.exe"：先按 PATH 找，找不到再退回原名。
std::wstring resolve_exe(const std::wstring &argv0) {
  if (argv0.find_first_of(L"\\/") != std::wstring::npos) return argv0;
  wchar_t buf[MAX_PATH * 2];
  const DWORD n =
      ::SearchPathW(nullptr, argv0.c_str(), L".exe", static_cast<DWORD>(sizeof(buf) / sizeof(buf[0])),
                    buf, nullptr);
  if (n > 0 && n < sizeof(buf) / sizeof(buf[0])) return std::wstring(buf, n);
  return argv0;
}

bool terminate_process(long pid) {
  HANDLE h = ::OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, static_cast<DWORD>(pid));
  if (!h) return false;
  ::TerminateProcess(h, 0);
  const DWORD rc = ::WaitForSingleObject(h, 10000);
  ::CloseHandle(h);
  return rc == WAIT_OBJECT_0;
}

// 按自述文件里的 argv/cwd 原样拉起一个新实例。成功返回 0。
//
// 【顺序是这里唯一重要的东西】目标 pid 可能就是**我们自己的进程**（管理面板
// 里的"重启"就是这种情况：面板跑在这个进程里，重启号令由它自己执行）。
// 先 TerminateProcess 再 CreateProcess 的话，执行到第二句时进程已经在被终结，
// 新实例根本起不来 —— 现场表现是"点重启，服务就没了"。
// 所以拆成两步：先 spawn，再由调用方 terminate。
int spawn_replacement_win(const Instance &info) {
  // 同上：动手前确认这个 pid 现在还是 cochat，避免 pid 复用后误杀无关进程。
  const std::string image = process_image_name(info.pid);
  if (image.empty()) {
    std::fprintf(stderr, "error: pid %ld 已经不在了\n", info.pid);
    return 1;
  }
  if (!looks_like_cochat_name(image)) {
    std::fprintf(stderr, "error: pid %ld 现在是 %s，不是 cochat（pid 可能被复用）\n", info.pid,
                 image.c_str());
    return 1;
  }
  std::printf("  pid %ld: %s\n", info.pid,
              info.argv.empty() ? "(命令行未知)" : info.argv[0].c_str());
  if (info.argv.size() > 1) {
    std::printf("  参数    :");
    for (size_t i = 1; i < info.argv.size(); ++i) std::printf(" %s", info.argv[i].c_str());
    std::printf("\n");
  }
  if (info.cwd.empty()) {
    std::fprintf(stderr, "error: 自述文件里没有 cwd，无法原样重启（请手工重启一次以写入自述）\n");
    return 1;
  }
  const InstanceProbe before = probe_instance(info.port);
  const std::string previous_url = before.ok ? before.tunnel_url : std::string();

  std::wstring cmdline;
  for (size_t i = 0; i < info.argv.size(); ++i) {
    if (i) cmdline += L' ';
    cmdline += quote_arg(widen(info.argv[i]));
  }
  std::wstring exe = resolve_exe(widen(info.argv[0]));
  std::wstring cwd = widen(info.cwd);

  STARTUPINFOW si{};
  si.cb = sizeof(si);
  // 新实例不能继承我们的标准流：继承了，调用方（管道、终端）会一直等不到 EOF，
  // 看起来像 --res 卡住。stdio 全交给系统默认（控制台/服务各自有自己的）。
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdInput = nullptr;
  si.hStdOutput = nullptr;
  si.hStdError = nullptr;
  PROCESS_INFORMATION pi{};
  // DETACHED_PROCESS：新实例不挂到当前控制台上，父进程退出后它继续跑。
  // CREATE_NEW_PROCESS_GROUP：Ctrl+C 不会连带打到它。
  // CREATE_BREAKAWAY_FROM_JOB：祖先把我们放进 job 时也能脱身。
  DWORD flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
  if (!::CreateProcessW(exe.c_str(), &cmdline[0], nullptr, nullptr, FALSE,
                        flags | CREATE_BREAKAWAY_FROM_JOB, nullptr, cwd.c_str(), &si, &pi)) {
    // 不允许脱离 job 时退回普通启动，总比什么也没做要好。
    if (!::CreateProcessW(exe.c_str(), &cmdline[0], nullptr, nullptr, FALSE, flags, nullptr,
                          cwd.c_str(), &si, &pi)) {
      std::fprintf(stderr, "error: CreateProcess 失败（%lu）\n", static_cast<unsigned long>(::GetLastError()));
      return 1;
    }
  }
  std::printf("  已用同样的参数启动 pid %lu\n", static_cast<unsigned long>(pi.dwProcessId));
  ::CloseHandle(pi.hThread);
  ::CloseHandle(pi.hProcess);

  // 新实例已经在跑了，这时才允许收掉旧进程。顺序反过来就是"点了重启，
  // 服务直接没了"——因为执行到 TerminateProcess 时本进程已经被终结，
  // 后面的 CreateProcess 根本没机会运行。
  //
  // 目标就是本进程时（管理面板点"重启"），不能再走 terminate_process：
  // 那是从"自己"里面杀"自己"，之后一行代码都不会执行，新实例虽然起来了，
  // 但 wait_for_tunnel 没机会验证它是否真的对外服务。直接退出更诚实：
  // 新进程会重新写自述文件，调用方（浏览器）刷新后就能看到。
  if (info.pid == static_cast<long>(::GetCurrentProcessId())) {
    std::printf("  本实例即将退出，新实例已接管（面板会在几秒后恢复）\n");
    std::fflush(stdout);
    // 给 HTTP 响应一点时间发出去：面板上的"重启"要能先拿到结果，否则
    // 浏览器看到的是连接被重置，用户会以为点坏了。
    ::Sleep(400);
    ::ExitProcess(0);
  }

  if (!terminate_process(info.pid)) {
    std::fprintf(stderr, "error: pid %ld 无法终止（权限不足？）\n", info.pid);
    return 1;
  }
  wait_for_tunnel(info, previous_url);
  return 0;
}

// restart_one_win 的语义别名：名字说明"这里会先起后杀"。
int restart_one_win(const Instance &info) { return spawn_replacement_win(info); }

int restart_windows(const std::string &pid_arg) {
  const std::vector<Instance> all = discover_instances();
  if (all.empty()) {
    // 点名了 pid 就说清楚"那个 pid 不是 cochat"，别让人以为机器上一个都没有。
    std::fprintf(stderr, "error: %s\n",
                 pid_arg.empty() ? "没有找到运行中的 cochat 实例"
                                 : ("没有找到 pid " + pid_arg + " 的 cochat 实例").c_str());
    return 1;
  }
  if (!pid_arg.empty()) {
    const char *end = nullptr;
    long pid = 0;
    // 整串必须都是数字：parse_long 允许尾随垃圾（与 strtol 一致），
    // 所以这里额外要求 end 指到结尾 —— "123abc" 不该被当成 pid 123。
    if (!util::parse_long(pid_arg.c_str(), pid, &end) || end == nullptr || *end != '\0' ||
        pid <= 0) {
      std::fprintf(stderr, "error: --res 需要数字 pid，收到 '%s'\n", pid_arg.c_str());
      return 1;
    }
    for (const auto &inst : all) {
      if (inst.pid != pid) continue;
      if (inst.argv.size() <= 1 || inst.argv[0] == inst.exe) {
        // 只有 pid 没有命令行：Windows 读不到别的进程的 argv，只能靠自述文件。
        if (inst.cwd.empty()) {
          std::fprintf(stderr,
                       "error: pid %ld 没有自述文件（%s），拿不到它的命令行；请手工重启一次\n",
                       pid, instances_dir().c_str());
          return 1;
        }
      }
      return restart_one_win(inst);
    }
    std::fprintf(stderr, "error: 没有 pid %ld 的 cochat 实例\n", pid);
    return 1;
  }
  if (all.size() > 1) {
    std::printf("cochat --res: 发现 %zu 个 cochat 实例，重启 pid 最小的那个（%ld）\n", all.size(),
                all.front().pid);
  }
  return restart_one_win(all.front());
}

#endif

}  // namespace

int restart_instance(const std::string &pid_arg) {
#if defined(_WIN32)
  return restart_windows(pid_arg);
#else
  return restart_posix(pid_arg);
#endif
}

}  // namespace app
