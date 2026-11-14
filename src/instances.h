#pragma once
// 运行实例发现：给 `cochat --cur` 与 `cochat --res` 提供"这台机器上有哪些
// cochat 在跑、它们的公网地址是多少、它们的原始命令行是什么"。
//
// 两条数据来源：
//   1) 每个实例启动时在 ~/.intercom/instances/<pid>.json 写一份自述（pid、端口、
//      数据目录、原始 argv、cwd）。这是跨平台都能拿到的"我是怎么被启动的"，
//      Windows 上没有 /proc，靠它才能原样重启。
//   2) POSIX 上再扫描一遍 /proc，把老版本二进制（还没有自述文件）也找出来。
//
// 隧道地址则问活着的进程自己（GET /api/info），因为只有它知道此刻隧道通不通。
#include <cstdint>
#include <string>
#include <vector>

namespace app {

struct Instance {
  long pid = 0;
  std::string exe;                  // argv[0]
  std::vector<std::string> argv;    // 原始命令行，--res 原样重放
  std::string cwd;
  std::string data_dir;
  std::string bind_host;
  int port = 8080;
  bool port_known = false;
  std::string public_url;           // https://xxx.trycloudflare.com
  std::string tunnel_source;        // cli / observed / 空
  std::string state;                // 已连接 / 已配置隧道 / 无隧道 / 无响应
  int64_t started_at = 0;
  bool alive = false;
  bool from_record = false;         // 来自 <instances>/<pid>.json
};

// 实例自述目录：<主目录>/.intercom/instances
std::string instances_dir();

// 服务启动时写一份自述；退出时删除。失败只影响 --cur/--res，不影响服务本身。
bool write_instance_record(const std::string &exe, const std::vector<std::string> &argv,
                           const std::string &cwd, const std::string &data_dir,
                           const std::string &bind_host, int port,
                           const std::string &tunnel_url, std::string &err);
void remove_instance_record();

// 清理自述文件里已经死掉的 pid（进程被强杀时会留下残留）。
void prune_instance_records();

// 当前这台机器上活着（或至少自述过）的全部实例。
//
// 返回时 state / public_url 可能还空着 —— 它们要靠 describe_instance 向实例
// 发一次 /api/info 才知道。探测是网络调用，跟"有哪些实例"是两件事，分开能
// 让不需要状态的调用方（--res）不必为每个实例都打一次 HTTP。
std::vector<Instance> discover_instances();

// 补齐某个实例的运行状态（隧道通不通、公网地址）。会发一次短超时 HTTP 探测。
void describe_instance(Instance &inst);


// 进程是否还活着。POSIX 用 kill(pid,0)，Windows 用 OpenProcess+零超时等待。
bool process_alive(long pid);

// 进程的可执行文件名（不含路径），拿不到时为空。
// 用途：pid 会被系统回收，--res 动手前要确认"这个 pid 现在还是不是 cochat"，
// 否则会把一个刚复用了同一个 pid 的无关进程杀掉。
std::string process_image_name(long pid);

// 这个名字看起来是不是 cochat（cochat / cochat.exe / cochat-linux-amd64）。
bool looks_like_cochat_name(const std::string &exe);

// 问某个端口上活着的实例：隧道此刻通不通、地址是多少。只有它自己知道，
// 文件里记的只是"上次对外公布的地址"。ok=false 表示连不上或不是 cochat。
struct InstanceProbe {
  bool ok = false;
  int status = 0;
  std::string tunnel_url;
  std::string tunnel_state;
  std::string tunnel_source;
  bool tunnel_configured = false;
};
InstanceProbe probe_instance(int port);

// `cochat --cur`：打印每个实例的公网地址与状态，找到至少一个返回 0。
// data_override 非空时只看这一个数据目录；port_override > 0 时用它覆盖端口。
int print_current_tunnels(const std::string &data_override, int port_override);

}  // namespace app
