#include "passwd.h"

#include "auth.h"
#include "instances.h"
#include "json.h"
#include "util.h"

#include "../third_party/httplib.h"

#include <cstdio>
#include <cstdlib>

#if !defined(_WIN32)
#include <unistd.h>
#endif
#include <string>
#include <vector>

namespace app {

namespace {

constexpr size_t kMinPassword = 6;  // 与 auth::Store::valid_password 的下限一致

// 服务端信令的 WebSocket 路径。
constexpr const char *kWsPath = "/ws";

// 报错口径与服务端保持一致：长度不对时服务端只回 BadPasswordFormat，
// 命令行直接说清楚，省得操作者去翻代码。
bool check_password_shape(const std::string &password) {
  if (password.size() < kMinPassword) return false;
  if (password.size() > 512) return false;
  return true;
}

// 读一行密码（不回显）。没有终端时（管道输入）退回读整行。
std::string read_password_line() {
  std::fputs("请输入新密码（回车结束，不回显）: ", stderr);
  std::fflush(stderr);
  std::string line;
#if !defined(_WIN32)
  // POSIX：关掉回显，避免密码留在终端滚动区
  const bool tty = ::isatty(STDIN_FILENO);
  if (tty) std::system("stty -echo");
  int c;
  while ((c = std::fgetc(stdin)) != EOF && c != '\n') {
    if (c != '\r') line.push_back(static_cast<char>(c));
  }
  if (tty) std::system("stty echo");
  std::fputc('\n', stderr);
#else
  int c;
  while ((c = std::fgetc(stdin)) != EOF && c != '\n') {
    if (c != '\r') line.push_back(static_cast<char>(c));
  }
#endif
  return line;
}

// 让运行中的服务自己确认一次：/ws + {"t":"auth",...}。
// 返回 1 密码对、0 密码错、-1 连不上/说不清。连不上绝不能算"对"。
int probe_live_login(int port, const std::string &user, const std::string &password) {
  httplib::ws::WebSocketClient cli("ws://127.0.0.1:" + std::to_string(port) + kWsPath);
  cli.set_connection_timeout(2, 0);
  if (!cli.connect()) return -1;
  cli.set_read_timeout(4, 0);

  jsonx::Json req;
  req["t"] = "auth";
  req["user"] = user;
  req["pass"] = password;
  if (!cli.send(jsonx::dump(req))) {
    cli.close();
    return -1;
  }
  // 服务端连上就先推一条 {"t":"hello"}，真正回答 auth 的是后面那条，
  // 所以这里要读到 auth-ok / auth-fail 为止，不能只看第一条。
  int verdict = -1;
  std::string reason;
  for (int i = 0; i < 8; ++i) {
    std::string msg;
    const auto rc = cli.read(msg);
    if (rc != httplib::ws::ReadResult::Text) break;
    jsonx::Json res;
    if (!jsonx::parse(msg, res) || !res.is_object()) continue;
    const std::string t = jsonx::str(res, "t");
    if (t == "auth-ok") { verdict = 1; break; }
    if (t == "auth-fail") { verdict = 0; reason = jsonx::str(res, "reason"); break; }
    // hello / users 之类的握手消息，继续读
  }
  cli.close();
  if (verdict == 1) return 1;
  if (verdict < 0) return -1;
  // 锁定与"密码错"要分开说：连续失败 8 次会锁 2 分钟，这时密码可能是对的。
  // 服务端把 auth::Status::Locked 的文案原样放在 reason 里（"尝试次数过多…"）。
  if (reason.find("尝试次数过多") != std::string::npos) return -2;
  return 0;
}

}  // namespace

int run_passwd_cli(const std::string &accounts_dir, const std::vector<std::string> &args,
                   bool check_only, bool force) {
  if (args.empty()) {
    auth::Store store(accounts_dir);
    std::string err;
    if (!store.load(err)) {
      std::fprintf(stderr, "读取账号库失败: %s\n", err.c_str());
      return 1;
    }
    std::printf("账号库: %s\n", store.dir().c_str());
    std::printf("提示: cochat --passwd <用户名> [新密码]  改密码；加 --check 只核对不改\n");
    return 0;
  }

  const std::string user = args[0];
  std::string password;
  if (args.size() > 1) {
    password = args[1];
  } else if (!check_only) {
    password = read_password_line();
    if (password.empty()) {
      std::fprintf(stderr, "error: 新密码不能为空\n");
      return 1;
    }
  }

  auth::Store store(accounts_dir);
  std::string err;
  if (!store.load(err)) {
    std::fprintf(stderr, "读取账号库失败: %s\n", err.c_str());
    return 1;
  }
  if (!store.has(user)) {
    std::fprintf(stderr, "error: 用户 %s 不存在（cochat --list 可以看到全部用户）\n", user.c_str());
    return 1;
  }

  if (check_only) {
    if (password.empty()) {
      std::fprintf(stderr, "error: --check 需要给出要核对的密码\n");
      return 1;
    }
    const auth::Status st = store.verify(user, password);
    const bool ok_file = (st == auth::Status::Ok);
    std::printf("%-22s %s\n", "账号文件:",
                ok_file ? "匹配"
                        : (st == auth::Status::Locked ? "锁定中（密码无法核对）" : "不匹配"));
    int rc = ok_file ? 0 : 1;

    // 再问一次活着的服务：账号文件匹配只说明"文件里是这套密码"，只有服务真的
    // 收下才算数。端口取自本机自述里的实例（--res/--cur 用的是同一份记录），
    // 一个都没有时才退回服务默认的 8080；连不上就如实说没验证过。
    int port = 8080;
    for (const auto &inst : discover_instances()) {
      if (inst.port > 0) {
        port = inst.port;
        break;
      }
    }
    const int live = probe_live_login(port, user, password);
    if (live == 1) {
      std::printf("%-22s 接受（已验证登录）\n", "运行中的服务:");
    } else if (live == 0) {
      std::printf("%-22s 拒绝（用户名或密码不对）\n", "运行中的服务:");
      rc = 1;
    } else if (live == -2) {
      std::printf("%-22s 账号被锁定，暂时无法验证\n", "运行中的服务:");
    } else {
      std::printf("%-22s 未能验证（127.0.0.1:%d 上没有可用的服务）\n", "运行中的服务:", port);
      rc = 1;
    }
    return rc;
  }

  if (!check_password_shape(password) && !force) {
    std::fprintf(stderr,
                 "error: 密码长度必须是 %zu 到 512 个字符（现在 %zu 个）。\n"
                 "       确认要用这个密码就加 --force。\n",
                 kMinPassword, password.size());
    return 1;
  }

  const auth::Status st = store.set_password(user, password, err);
  if (st != auth::Status::Ok) {
    std::fprintf(stderr, "修改失败: %s\n", auth::status_text(st));
    if (!err.empty()) std::fprintf(stderr, "        %s\n", err.c_str());
    return 1;
  }
  std::printf("已修改 %s 的密码（服务端已重新加盐，明文不落盘）\n", user.c_str());
  // 服务按文件修改时间热加载，改完立刻生效，不必重启。
  std::printf("提示: 运行中的服务会自动读到新密码；在线会话需要用新密码重新登录。\n");
  return 0;
}

}  // namespace app
