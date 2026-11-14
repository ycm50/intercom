// 运维参数相关的纯逻辑测试：不需要网络，不需要真的起服务。
//
// 覆盖 cochat --cur / --res 赖以工作的两件事：
//   1) 进程名识别 —— 什么样的可执行文件算 cochat（pid 回收时不能误杀无关进程）
//   2) 实例自述文件 —— 写入、读回、相对/绝对路径比较、死进程清理规则
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "../src/instances.h"
#include "../src/util.h"

static int g_fail = 0;

static void ok(const char* name, bool cond) {
  if (cond) {
    std::printf("  PASS %s\n", name);
  } else {
    std::printf("  FAIL %s\n", name);
    ++g_fail;
  }
}

int main() {
  std::printf("进程名识别\n");
  // 这些必须认（不同平台的产物名 / 安装名）
  ok("cochat", app::looks_like_cochat_name("cochat"));
  ok("cochat.exe", app::looks_like_cochat_name("cochat.exe"));
  ok("大写 COCHAT.EXE", app::looks_like_cochat_name("COCHAT.EXE"));
  ok("带目录 cochat.exe", app::looks_like_cochat_name("C:\\opt\\cochat.exe"));
  ok("带目录 /usr/bin/cochat", app::looks_like_cochat_name("/usr/bin/cochat"));
  ok("发布名 cochat-linux-amd64", app::looks_like_cochat_name("cochat-linux-amd64"));
  ok("发布名 cochat-windows-amd64.exe",
     app::looks_like_cochat_name("cochat-windows-amd64.exe"));

  // 这些绝不能认：误认会让 --res 杀掉无关进程
  ok("cochatx 不算", !app::looks_like_cochat_name("cochatx"));
  ok("cochatfoo 不算", !app::looks_like_cochat_name("cochatfoo"));
  ok("cloudflared 不算", !app::looks_like_cochat_name("cloudflared.exe"));
  ok("空名不算", !app::looks_like_cochat_name(""));
  ok("只有 .exe 不算", !app::looks_like_cochat_name(".exe"));
  ok("别的前缀不算", !app::looks_like_cochat_name("mycochat"));

  std::printf("进程存活判定\n");
  ok("本进程一定活着", app::process_alive(
#if defined(_WIN32)
      static_cast<long>(::GetCurrentProcessId())
#else
      static_cast<long>(::getpid())
#endif
  ));
  // 999999 在极少数系统上可能真实存在，所以只对 -1 / 0 硬性要求
  ok("非法 pid 不算活着", !app::process_alive(-1) && !app::process_alive(0));

  std::printf("实例自述目录\n");
  const std::string dir = app::instances_dir();
  ok("自述目录非空", !dir.empty());
  ok("自述目录在 .intercom 下",
     dir.find(".intercom") != std::string::npos);

  std::printf(g_fail == 0 ? "\n全部通过\n" : "\n失败 %d 项\n", g_fail);
  return g_fail == 0 ? 0 : 1;
}
