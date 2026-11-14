#pragma once
// 把正在运行的 cochat 重启：
//   cochat --res <pid>   重启指定实例
//   cochat --res         重启本机 pid 最小的那个实例
//
// "重启"的含义取决于谁拥有这个进程，二者不能混为一谈：
//   * systemd 托管的 -> systemctl restart <unit>，保留 unit 的 Restart= 策略、
//     环境变量与 cgroup 限制；直接杀 pid 会把这些全部丢掉。
//   * 手工启动的   -> 终止后按原 argv、原工作目录重新拉起一份。
//     Windows 上再附加 CREATE_BREAKAWAY_FROM_JOB，避免被当前控制台/任务一起带走。
//
// 成功返回 0，失败返回 1（没有可重启的实例、权限不足、目标进程不退出……），
// 诊断信息写 stderr。
#include <string>

namespace app {

int restart_instance(const std::string &pid_arg);

}  // namespace app
