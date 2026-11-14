#pragma once
// 管理面板（/admin）的契约 —— 主程序与面板模块之间唯一的接口。
//
// 设计要点（改之前先读）：
//   1. 面板只管"运行中这个进程"：实例列表、隧道状态、账号、日志、动作。
//      不引入数据库、不落盘新状态，全部从内存和既有的自述文件读。
//   2. 鉴权只有一个账号 admin，密码与聊天账号共用同一套 auth::Store、
//      同一个 ~/.intercom 目录、同一条 --passwd 通道。它不是"另一个系统"。
//   3. admin 不可增删：它由面板自己保证存在（首次启动自动建一个随机密码），
//      --add / --del / --un 明确拒绝 admin，避免运维把自己锁在门外。
//   4. 面板与聊天服务跑在同一个 httplib::Server 上，只是挂在 /admin 前缀下：
//      这样访问控制（仅回环 / 仅隧道来源）、CSP 头、超时全部自动继承，
//      不需要为面板再造一套监听。
#include <cstdint>
#include <functional>
#include <string>

#include "../auth.h"
#include "../json.h"

namespace panel {

// 面板用到的宿主能力。做成回调而不是让面板模块直接抓全局变量：
// 面板是独立编译单元，抓全局就得把 main.cpp 里的静态对象全暴露出去。
struct Host {
    // 账号库（已加载好，面板不负责 load/reload 生命周期）。
    // 这里直接用 auth::Store* 而不是 void*：面板确实要读账号列表、验密码，
    // 类型擦除只会把编译期能查出来的错误推迟到运行期。
    auth::Store* store = nullptr;

    // 指纹信息：进程启动时间、监听地址、数据目录、版本
    std::function<std::string()> info_json;      // /api/info 的同一份内容
    std::function<std::string()> stats_json;     // 消息/媒体/信令计数等增量
    std::function<std::string()> instances_json; // 本机实例列表（含自述文件）
    std::function<std::string()> logs_json;      // 最近 N 行日志（环形缓冲）

    // 动作。返回 (成功?, 给人看的结果)。
    std::function<std::pair<bool, std::string>(const std::string& user,
                                               const std::string& display,
                                               const std::string& password)> add_user;
    std::function<std::pair<bool, std::string>(const std::string& user)> del_user;
    std::function<std::pair<bool, std::string>(const std::string& old_user,
                                               const std::string& new_user)> rename_user;
    std::function<std::pair<bool, std::string>(const std::string& user,
                                               const std::string& password)> set_password;
    std::function<std::pair<bool, std::string>(const std::string& pid)> restart_instance;
    // 隧道状态（只读）与"重新申请 quick 隧道"这类运维动作
    std::function<std::string()> tunnel_json;
    // 审计日志落点。面板的登录成败与账号增删改都要进服务端日志，
    // 否则"谁在什么时候删了谁"在事后完全无从追溯 —— 这是管理面板最该有、
    // 也最容易漏掉的一件事。宿主不接线时面板照常工作，只是不留痕。
    std::function<void(const std::string&)> log;
};

// 面板的固定账号名。不是命令行可配的：面板一旦能被改名，运维就会把自己
// 锁在门外，而这个"我进不去了"现场没有任何自救手段（服务还在跑）。
inline constexpr const char* kAdminUser = "admin";

// 判断某个用户名是否是保留名。用户名比较一律大小写不敏感（auth 层就是这么
// 存的），所以 "ADMIN" / "Admin " 也算。
bool is_reserved_user(const std::string& user);

// 挂载面板到 srv 的 /admin 前缀下。
//
// 参数：
//   public_dir  面板静态资源目录（可选，为空则用内嵌的那份）
//   data_dir    会话令牌的落盘目录（放 <data_dir>/admin-sessions.json）
//
// 返回 false 表示面板没装起来，error 是原因。面板装不起来**不是错误**：
// 主程序照常提供聊天服务，只是没有管理界面。
bool register_routes(void* srv_as_httplib_server, const Host& host, const std::string& public_dir,
                     const std::string& data_dir, std::string& error);

// 首次启动时确保 admin 账号存在（不存在就随机生成一个强密码并返回给调用方，
// 由调用方打印一次，之后再也拿不到明文）。
//
// 为什么随机而不是要求运维先手工 --add：新装好的机器直接启动就该能进面板，
// 而"先去命令行建一个 admin、再回来登录"是多一步且容易忘的仪式。
// 已经存在的 admin 密码绝不覆盖 —— 否则每次重启都会把运维的密码换掉。
bool ensure_admin(auth::Store& store, std::string& generated_password, std::string& error);

// ---- admin.cpp 提供的辅助 ---------------------------------------------------
//
// 账号列表（JSON 数组），每项 {user, display, created_at, last_login, admin}。
// 刻意不含 salt / hash / iterations：面板是让运维看"有哪些人、什么时候建的"，
// 不是展示密钥材料的地方；盐和哈希一旦进了页面或浏览器缓存就收不回来了。
jsonx::Json accounts_json(auth::Store& store);

// 把账号动作（新建 / 删除 / 改名 / 改密码）填进 host 的回调。
//
// 保留名 admin 的拒绝规则只在这里写一次：main.cpp 与 routes.cpp 各写一份，
// 迟早出现"面板拦住了、命令行没拦住"这种自锁。
void install_account_actions(auth::Store& store, Host& host);

}  // namespace panel
