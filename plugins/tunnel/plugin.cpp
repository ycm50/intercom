// 隧道插件的 ABI 实现 + 监督线程：把 api.h 的三个入口接到 client / quick 上。
//
// 这个文件是整个插件里唯一"跨 DLL 边界"的地方，因此它也承担了 runtime.h 的
// 实现（log_line / publish / publish_now / runtime()）：插件内部其它模块只通过
// 这几条通道上报，插件从不假设主程序认识自己的任何类型。
//
// 两条贯穿全文的约定：
//   * start() 只做校验和起线程就返回 —— 主程序是在 HTTP 线程里调它的，在这里
//     等注册超时等于主界面卡死；失败一律走回调报告。
//   * 状态只在"当前代"的线程手里才算数 —— stop() 之后立刻 start() 时，旧线程
//     可能还在收尾，它写下的 running=false 会盖掉新连接（见 generation 注释）。
#include <algorithm>
#include <atomic>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <system_error>
#include <thread>

#include "client.h"
#include "ingress.h"
#include "quick.h"
#include "runtime.h"

// Windows 的 DLL 导出必须显式声明；POSIX 上靠 visibility("default")。
// CMake 给这个目标设了 CXX_VISIBILITY_PRESET hidden，不写这一句就等于不导出。
#if defined(_WIN32)
#define COCHAT_TUNNEL_EXPORT __declspec(dllexport)
#else
#define COCHAT_TUNNEL_EXPORT __attribute__((visibility("default")))
#endif

namespace ct {

// ---- runtime.h 的实现 ------------------------------------------------------

Runtime& runtime() {
  // 进程级单例：一次只能有一条隧道，stop() 之后可以再来一次。
  static Runtime rt;
  return rt;
}

}  // namespace ct

namespace ct {
namespace abi {

// ---- 共享状态 -------------------------------------------------------------
// g_* 的这些由 runtime().mu 保护；g_stopping 单独用原子量，因为它要被
// 睡眠中的监督线程和主线程同时看到。

std::atomic<bool> g_stopping{false};

// 当前这一轮的客户端。用 shared_ptr：stop() 拿到一份后可以安全地调它的 stop()，
// 而监督线程仍持有自己那份，直到 run() 返回 —— 否则 stop() 会用到已析构的对象。
std::shared_ptr<client::Client> g_client;

// start() 校验过的配置副本：监督线程每一轮重连都从这里取，这样主程序传进来的
// cfg 指针不必活到线程结束。
struct Startup {
  std::string token;
  std::string edgeHost = "region1.v2.argotunnel.com";
  std::uint16_t edgePort = 7844;
  std::string edgeSni = "h2.cftunnel.com";
  std::string originHost = "127.0.0.1";
  std::uint16_t originPort = 8080;
  int connectTimeoutMs = 15000;
  int registerTimeoutMs = 20000;
  std::string dataDir;
};

Startup g_startup;

// ---- 小工具 ---------------------------------------------------------------

// err/errlen 来自另一个编译单元的调用方，长度可能是任何值；一律截断并补 NUL。
void set_err(char* err, std::size_t errlen, const std::string& text) {
  if (err == nullptr || errlen == 0) return;
  const std::size_t n = text.size() < errlen - 1 ? text.size() : errlen - 1;
  if (n > 0) std::memcpy(err, text.data(), n);
  err[n] = '\0';
}

// 状态里的 char[N] 由我们自己写，同样要保证"截断后仍然以 NUL 结尾"。
void copy_str(char* dst, std::size_t cap, const std::string& src) {
  if (dst == nullptr || cap == 0) return;
  const std::size_t n = src.size() < cap - 1 ? src.size() : cap - 1;
  if (n > 0) std::memcpy(dst, src.data(), n);
  dst[n] = '\0';
}

// 配置里的 char[N] 不保证以 NUL 结尾（有人按固定宽度填），只按字段宽度扫描，
// 绝不越过字段读内存。
std::string field_str(const char* p, std::size_t cap) {
  if (p == nullptr) return std::string();
  std::size_t n = 0;
  while (n < cap && p[n] != '\0') ++n;
  return std::string(p, n);
}

void stamp(cochat_tunnel_status& st) {
  st.abi = COCHAT_TUNNEL_ABI;
  st.struct_size = static_cast<std::uint32_t>(sizeof(cochat_tunnel_status));
}

// 写状态 + 通知主程序。gen 非 0 时只有"当前代"的线程才写得进去：
// 旧线程退出时覆盖新线程的状态，正是 stop 后立刻 start 那个窗口里的经典故障。
bool store_and_notify(const cochat_tunnel_status& st, std::uint64_t gen) {
  Runtime& rt = runtime();
  cochat_tunnel_status snap;
  cochat_tunnel_status_fn fn = nullptr;
  void* user = nullptr;
  {
    std::lock_guard<std::mutex> lk(rt.mu);
    if (gen != 0 && rt.generation != gen) return false;
    rt.status = st;
    stamp(rt.status);
    snap = rt.status;
    fn = rt.on_status;
    user = rt.user;
  }
  // 回调必须在锁外：主程序完全可能在回调里回头调 status() 甚至 stop()。
  // （唯一不能做的是在回调里调 stop()：那会在自己的线程上 join 自己。）
  if (fn != nullptr) fn(user, &snap);
  return true;
}

cochat_tunnel_status make_status(const client::Status& cs, bool quick, const std::string& host,
                                 std::uint64_t servedTotal) {
  cochat_tunnel_status out{};
  stamp(out);
  out.running = 1;
  out.connected = cs.connected ? 1 : 0;
  out.registered = cs.registered ? 1 : 0;
  out.quick = quick ? 1 : 0;
  // 计数器只许涨：run() 每轮都从 0 开始，直接用 cs.requestsServed 会让主程序
  // 看到已服务数量倒退。
  out.requests_served = std::max(servedTotal, cs.requestsServed);
  copy_str(out.hostname, sizeof out.hostname, host);
  copy_str(out.location, sizeof out.location, cs.location);
  copy_str(out.uuid, sizeof out.uuid, cs.uuid);
  copy_str(out.error, sizeof out.error, cs.error);
  return out;
}

// 分片睡眠：stop() 最多等一个 200ms 的片就能生效，而不是等满 30s 的退避。
bool sleep_backoff(int ms) {
  for (int waited = 0; waited < ms; waited += 200) {
    if (g_stopping.load(std::memory_order_relaxed)) return false;
    const int slice = std::min(200, ms - waited);
    std::this_thread::sleep_for(std::chrono::milliseconds(slice));
  }
  return !g_stopping.load(std::memory_order_relaxed);
}

// ---- 监督线程 -------------------------------------------------------------

void worker_main(std::uint64_t gen) {
  cochat_tunnel_status last{};
  stamp(last);
  last.running = 1;

  std::string knownHost;  // quick: 注册接口给的域名；命名隧道: 边缘 ingress 推来的
  std::string quickToken;
  bool haveQuick = false;
  std::uint64_t servedTotal = 0;
  int delayMs = 1000;
  int quickFailures = 0;

  auto emit = [gen](const cochat_tunnel_status& st) { store_and_notify(st, gen); };

  while (!g_stopping.load(std::memory_order_relaxed)) {
    Startup run;
    {
      std::lock_guard<std::mutex> lk(runtime().mu);
      if (g_stopping.load(std::memory_order_relaxed)) break;
      run = g_startup;
    }
    const bool quick = run.token.empty();
    std::string token = run.token;

    // 1) 令牌：空 token 的 ad-hoc quick 隧道要先去 API 换一个。
    //    注册放在这里而不是 start() 里，因为这是网络操作，可能卡上十几秒。
    if (quick && !haveQuick) {
      ct::quick::Credentials creds;
      std::string qerr;
      if (ct::quick::register_new(run.dataDir, creds, qerr) && !creds.token.empty()) {
        haveQuick = true;
        quickToken = creds.token;
        if (!creds.hostname.empty()) knownHost = creds.hostname;
        quickFailures = 0;
        log_line(2, "quick 隧道已注册：%s（新域名通常要一两分钟才能解析）", knownHost.c_str());
      } else {
        if (qerr.empty()) qerr = "注册接口没有返回可用的令牌";
        // API 不可达时退回上次落盘的凭据：离线机器至少还有域名可用，
        // 但这个域名可能已经在边缘失效，所以要明确说出来而不是悄悄用。
        ct::quick::Credentials cached;
        if (ct::quick::load_cached(run.dataDir, cached) && !cached.token.empty()) {
          haveQuick = true;
          quickToken = cached.token;
          if (!cached.hostname.empty()) knownHost = cached.hostname;
          log_line(1, "quick 隧道注册失败（%s），沿用上次落盘的凭据 %s；该域名可能已失效",
                   qerr.c_str(), knownHost.c_str());
        } else {
          log_line(0, "quick 隧道注册失败：%s", qerr.c_str());
        }
      }
      if (!haveQuick) {
        ++quickFailures;
        last.running = 1;
        last.connected = 0;
        last.registered = 0;
        copy_str(last.error, sizeof last.error, qerr);
        emit(last);
        const int waitMs = delayMs;
        delayMs = std::min(delayMs * 2, 30000);
        if (!sleep_backoff(waitMs)) break;
        continue;
      }
    }
    if (quick) token = quickToken;

    // 2) 解析令牌。失败只可能是配置问题，重试再多次也不会好；但 start() 已经
    //    承诺非阻塞返回，所以这里只报告 + 退避，把"要不要停"留给主程序。
    client::Config cc;
    std::string perr;
    if (!client::Client::parse_token(token, cc, perr)) {
      log_line(0, "隧道令牌无效：%s", perr.c_str());
      last.running = 1;
      last.connected = 0;
      last.registered = 0;
      copy_str(last.error, sizeof last.error, perr);
      emit(last);
      const int waitMs = delayMs;
      delayMs = std::min(delayMs * 2, 30000);
      if (!sleep_backoff(waitMs)) break;
      continue;
    }

    // 3) 覆盖层的配置优先于令牌里的默认值（令牌只有 a/t/s，没有边缘地址）。
    cc.edgeHost = run.edgeHost;
    cc.edgePort = run.edgePort;
    cc.edgeSni = run.edgeSni;
    cc.originHost = run.originHost;
    cc.originPort = run.originPort;
    cc.connectTimeoutMs = run.connectTimeoutMs;
    cc.registerTimeoutMs = run.registerTimeoutMs;

    auto cl = std::make_shared<client::Client>();
    {
      std::lock_guard<std::mutex> lk(runtime().mu);
      if (g_stopping.load(std::memory_order_relaxed)) break;
      g_client = cl;
    }

    client::Status st;
    auto on_line = [](const std::string& line) { log_line(2, "%s", line.c_str()); };
    // 回调在 client 线程里跑 = 就在本线程里跑，所以引用局部变量是安全的。
    auto on_state = [&](const client::Status& cs) {
      if (!quick) {
        const std::string picked = ct::ingress::first_usable(cs.hostnames);
        if (!picked.empty()) knownHost = picked;
      }
      if (cs.requestsServed > servedTotal) servedTotal = cs.requestsServed;
      last = make_status(cs, quick, knownHost, servedTotal);
      emit(last);
    };
    cl->run(cc, st, on_line, on_state);

    {
      std::lock_guard<std::mutex> lk(runtime().mu);
      if (runtime().generation == gen && g_client == cl) g_client.reset();
    }
    if (st.requestsServed > servedTotal) servedTotal = st.requestsServed;
    const std::uint64_t liveServed = cl->requests_served();
    if (liveServed > servedTotal) servedTotal = liveServed;

    // 本轮结束：线程还活着（准备重连），但连接已经没了。
    last.running = 1;
    last.connected = 0;
    last.registered = 0;
    last.requests_served = servedTotal;
    copy_str(last.error, sizeof last.error, st.error);
    emit(last);

    if (g_stopping.load(std::memory_order_relaxed)) break;

    // quick 隧道是边缘上的 ad-hoc 对象：域名被回收后，旧令牌再也连不回去，
    // 无限重连只会一直报"注册失败"。连续几轮都没注册上就换一个新的。
    if (quick && !st.registered) {
      if (++quickFailures >= 3) {
        haveQuick = false;
        quickToken.clear();
        knownHost.clear();
        quickFailures = 0;
        log_line(1, "quick 隧道连续多轮未注册成功，重新申请一个");
      }
    } else {
      quickFailures = 0;
    }

    // 指数退避：边缘侧故障时不要变成重连风暴；这一轮真的注册上了就回到 1s。
    const int waitMs = delayMs;
    delayMs = st.registered ? 1000 : std::min(delayMs * 2, 30000);
    log_line(1, "隧道连接中断（%s），%d 秒后重连",
             st.error.empty() ? "对端关闭或网络不可达" : st.error.c_str(), waitMs / 1000);
    if (!sleep_backoff(waitMs)) break;
  }

  // 收尾。"当前代"校验放在写状态之前：旧线程不许把新一轮的 running 清掉。
  last.running = 0;
  last.connected = 0;
  last.registered = 0;
  last.requests_served = servedTotal;
  {
    std::lock_guard<std::mutex> lk(runtime().mu);
    if (runtime().generation == gen) runtime().startGuard = false;
  }
  emit(last);
}

// ---- C ABI 实现 -----------------------------------------------------------

const char* version_impl() {
  // 固定版本串：主程序只用它显示/记录，不解析。
  return "cochat-tunnel/1";
}

int start_impl(const cochat_tunnel_config* cfg, cochat_tunnel_log_fn log,
               cochat_tunnel_status_fn on_status, void* user, char* err, std::size_t errlen) {
  if (cfg == nullptr) {
    set_err(err, errlen, "配置为空");
    return -1;
  }
  if (cfg->abi != COCHAT_TUNNEL_ABI) {
    set_err(err, errlen, "配置的 abi（" + std::to_string(cfg->abi) + "）与插件（" +
                             std::to_string(COCHAT_TUNNEL_ABI) + "）不符");
    return -1;
  }
  // struct_size 校验：abi 相同但结构体被裁短，说明调用方是拿另一份头文件编出来的，
  // 再往后读字段就是越界读。更大的 struct_size 是允许的（未来版本加了字段）。
  if (cfg->struct_size < sizeof(cochat_tunnel_config)) {
    set_err(err, errlen,
            "配置结构体长度 " + std::to_string(cfg->struct_size) + " 小于插件需要的 " +
                std::to_string(sizeof(cochat_tunnel_config)));
    return -1;
  }

  // 已经在跑：只换回调（主程序可能重新挂了一遍界面），不另起一条隧道。
  // 同一个隧道挂两个连接器，边缘那边会互相抢流。
  {
    std::lock_guard<std::mutex> lk(runtime().mu);
    if (runtime().startGuard) {
      runtime().log = log;
      runtime().on_status = on_status;
      runtime().user = user;
      return 0;
    }
  }

  // 上一轮的线程可能已经跑完却没人 join。std::thread 在 joinable 时被赋新值会
  // 直接 std::terminate，所以先回收。
  std::thread stale;
  {
    std::lock_guard<std::mutex> lk(runtime().mu);
    if (runtime().worker.joinable()) stale = std::move(runtime().worker);
  }
  if (stale.joinable()) {
    if (stale.get_id() == std::this_thread::get_id()) {
      stale.detach();  // 在回调线程里 start（异步）：没法 join 自己
    } else {
      stale.join();
    }
  }

  Startup s;
  s.token = field_str(cfg->token, sizeof cfg->token);
  s.edgeHost = field_str(cfg->edge_host, sizeof cfg->edge_host);
  if (s.edgeHost.empty()) s.edgeHost = "region1.v2.argotunnel.com";
  s.edgePort = cfg->edge_port != 0 ? cfg->edge_port : 7844;
  s.edgeSni = field_str(cfg->edge_sni, sizeof cfg->edge_sni);
  if (s.edgeSni.empty()) s.edgeSni = "h2.cftunnel.com";
  s.originHost = field_str(cfg->origin_host, sizeof cfg->origin_host);
  if (s.originHost.empty()) s.originHost = "127.0.0.1";
  s.originPort = cfg->origin_port;
  s.connectTimeoutMs = cfg->connect_timeout_ms > 0 ? cfg->connect_timeout_ms : 15000;
  s.registerTimeoutMs = cfg->register_timeout_ms > 0 ? cfg->register_timeout_ms : 20000;
  s.dataDir = field_str(cfg->data_dir, sizeof cfg->data_dir);
  const bool originPortGiven = cfg->origin_port != 0;
  if (!originPortGiven) s.originPort = 8080;  // api.h 没给默认值，这里只给一个惯例值

  std::uint64_t gen = 0;
  {
    std::lock_guard<std::mutex> lk(runtime().mu);
    g_startup = s;
    g_stopping.store(false);
    runtime().log = log;
    runtime().on_status = on_status;
    runtime().user = user;
    gen = ++runtime().generation;  // 递增即"旧代作废"，不需要等旧线程真的退出
    runtime().startGuard = true;
    cochat_tunnel_status fresh{};
    stamp(fresh);
    fresh.running = 1;
    fresh.quick = s.token.empty() ? 1 : 0;
    runtime().status = fresh;
  }

  bool spawned = false;
  std::string spawnError;
  {
    // 持锁创建线程：不持锁的话 stop() 可能刚好在"已置标志、还没拿到句柄"之间跑过去，
    // 那之后就没人 join 这条线程了。worker 第一件事也是要锁，正好等我们释放。
    std::lock_guard<std::mutex> lk(runtime().mu);
    try {
      runtime().worker = std::thread(worker_main, gen);
      spawned = true;
    } catch (const std::system_error& e) {
      spawnError = e.what();
      runtime().startGuard = false;
      runtime().status.running = 0;
    }
  }
  if (!spawned) {
    set_err(err, errlen, "无法创建监督线程：" + spawnError);
    return -2;
  }

  log_line(2, "隧道已启动：边缘 %s:%u，origin %s:%u，%s", s.edgeHost.c_str(),
           static_cast<unsigned>(s.edgePort), s.originHost.c_str(),
           static_cast<unsigned>(s.originPort), s.token.empty() ? "quick 隧道（先申请域名）" : "命名隧道");
  if (!originPortGiven) {
    log_line(1, "没有给出 origin 端口，按 8080 转发；服务不在这个端口时请显式指定");
  }
  return 0;
}

void stop_impl() {
  std::thread th;
  std::shared_ptr<client::Client> cl;
  {
    std::lock_guard<std::mutex> lk(runtime().mu);
    g_stopping.store(true);
    cl = g_client;
    if (runtime().worker.joinable()) th = std::move(runtime().worker);
  }
  // 先唤醒连接再 join：run() 在一个 poll 片内返回，不必等注册超时。
  if (cl) cl->stop();
  if (th.joinable()) {
    if (th.get_id() == std::this_thread::get_id()) {
      // 回调线程里调 stop() 会 join 自己（std::system_error / 终止）。退化成分离，
      // 线程自己会看到停止标志并在下一个片退出 —— 但主程序不应该走到这条路上。
      th.detach();
    } else {
      th.join();
    }
  }

  const bool wasLive = (cl != nullptr) || th.get_id() != std::thread::id();
  cochat_tunnel_status down;
  {
    std::lock_guard<std::mutex> lk(runtime().mu);
    g_client.reset();
    runtime().startGuard = false;
    down = runtime().status;
    down.running = 0;
    down.connected = 0;
    down.registered = 0;
    stamp(down);
    runtime().status = down;
  }
  // 幂等：本来就没在跑就不必再推一次"已停止"，免得主程序收到重复事件。
  if (wasLive) store_and_notify(down, 0);
}

int status_impl(cochat_tunnel_status* out) {
  if (out == nullptr) return -1;
  // struct_size 是调用方填的：它描述"你分配了多大"。0 当作"就是 v1 大小"，
  // 便于懒得初始化的调用方；其余按前缀拷贝，超出部分不动。
  const std::uint32_t callerSize = out->struct_size;
  if (callerSize != 0 && callerSize < sizeof(std::uint32_t) * 2) return -2;

  cochat_tunnel_status snap;
  std::shared_ptr<client::Client> cl;
  {
    std::lock_guard<std::mutex> lk(runtime().mu);
    snap = runtime().status;
    cl = g_client;
  }
  stamp(snap);
  // 已服务计数在客户端的原子量里实时更新，而状态只在变化时发布；主程序可能
  // 靠这个数字给界面刷新，所以这里补上实时值。
  if (cl) {
    const std::uint64_t served = cl->requests_served();
    if (served > snap.requests_served) snap.requests_served = served;
  }

  const std::size_t want = callerSize != 0 ? callerSize : sizeof(cochat_tunnel_status);
  const std::size_t n = std::min(want, sizeof(cochat_tunnel_status));
  std::memcpy(out, &snap, n);
  // struct_size 归调用方所有：写回自己的长度会让它下次以为结构变大了。
  if (callerSize != 0) out->struct_size = callerSize;
  return 0;
}

void set_log_level_impl(int lvl) {
  if (lvl < 0) lvl = 0;
  if (lvl > 3) lvl = 3;
  std::lock_guard<std::mutex> lk(runtime().mu);
  runtime().logLevel = lvl;
}

const cochat_tunnel_api kApi{
    .abi = COCHAT_TUNNEL_ABI,
    .struct_size = static_cast<std::uint32_t>(sizeof(cochat_tunnel_api)),
    .version = &version_impl,
    .start = &start_impl,
    .stop = &stop_impl,
    .status = &status_impl,
    .set_log_level = &set_log_level_impl,
};

}  // namespace abi
}  // namespace ct

namespace ct {

// ---- runtime.h 的实现（续） -------------------------------------------------

void log_line(int level, const char* fmt, ...) {
  if (fmt == nullptr) return;
  // 先按级别过滤再格式化：默认 info 级以下不打印，没必要为一个丢掉的行做 snprintf。
  int maxLevel = 1;
  {
    std::lock_guard<std::mutex> lk(runtime().mu);
    maxLevel = runtime().logLevel;
  }
  if (level > maxLevel) return;

  char buf[1024];
  va_list ap;
  va_start(ap, fmt);
  const int n = std::vsnprintf(buf, sizeof buf, fmt, ap);
  va_end(ap);
  if (n < 0) return;  // 格式化失败：宁可丢一行，也不送半截缓冲区给主程序
  // vsnprintf 保证在 buf 内以 NUL 结尾（截断也截在末尾），这里不必再补一次。

  cochat_tunnel_log_fn fn = nullptr;
  void* user = nullptr;
  {
    std::lock_guard<std::mutex> lk(runtime().mu);
    fn = runtime().log;
    user = runtime().user;
  }
  if (fn == nullptr) return;  // 主程序没挂日志回调：静默丢弃，不往 stdout 写
  fn(user, level, buf);       // buf 以 NUL 结尾、不含换行，与 api.h 的约定一致
}

void publish(const cochat_tunnel_status& st) {
  abi::store_and_notify(st, 0);  // gen 0 = 无条件写（调用方自己保证它是当前代）
}

void publish_now() {
  cochat_tunnel_status snap;
  {
    std::lock_guard<std::mutex> lk(runtime().mu);
    snap = runtime().status;
  }
  abi::store_and_notify(snap, 0);
}

}  // namespace ct

// ---- 唯一导出 -------------------------------------------------------------

extern "C" {

COCHAT_TUNNEL_EXPORT const cochat_tunnel_api* cochat_tunnel_entry(std::uint32_t abi) {
  // abi 是语义版本：不匹配就返回 NULL，让主程序判定为"插件版本不符"退到纯局域网
  // 模式，而不是拿着一个布局可能不同的结构体继续跑。
  if (abi != COCHAT_TUNNEL_ABI) return nullptr;
  return &ct::abi::kApi;
}

}  // extern "C"
