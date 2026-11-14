#pragma once
// 命令行改密码 / 核对密码（对应 bpb 的 --passwd）。
//
//   cochat --passwd <用户名> [新密码]        改密码；省略密码则交互输入
//   cochat --passwd                          报告账号库位置，不改任何东西
//   cochat --passwd --check <用户名> [密码]   账号文件 + 运行中的服务两头都验
//
// 与 bpb 的差别：这里的账号是真实用户，不是面板单一口令，所以必须点名用户；
// 加盐与哈希全部复用 auth::Store（PBKDF2-HMAC-SHA256，每账号独立盐），
// 明文永远不落盘。改完服务按文件修改时间热加载，不需要重启。
#include <string>
#include <vector>

namespace app {

// accounts_dir 为空时用 auth::Store 的默认目录（~/.intercom）。
// 返回 0 成功、1 失败；诊断写 stderr。
int run_passwd_cli(const std::string &accounts_dir, const std::vector<std::string> &args,
                   bool check_only, bool force);

}  // namespace app
