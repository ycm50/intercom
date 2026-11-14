#include "panel.h"

#include <cstddef>
#include <utility>

#include "../crypto.h"
#include "../util.h"

namespace panel {

namespace {

// admin 的展示名。面板自动建号与列表展示共用这一份，免得同一个账号在
// 不同地方出现两种叫法。
constexpr const char *kAdminDisplay = "管理员";

// 面板侧的口令下限与命令行 --passwd 的 6 位口径保持一致（那边 6 位以下必须
// 加 --force 才肯写）。面板没有"我就是要用 6 位以下"的强制通道，所以直接拒绝，
// 省得运维连点两次就把 admin 变成一个摆设。
constexpr size_t kMinPassword = 6;
constexpr size_t kMaxPassword = 512;  // 与 auth::Store::valid_password 的上限一致

// 12 字节随机数按十六进制展开成 24 个字符：熵 96 位，猜是不可能的；
// 而十六进制不含 + / = 这类在命令行、URL、聊天窗口里容易被转义或截断的字符，
// 运维复制粘贴一次就完事，不用猜"这个符号要不要加引号"。
constexpr size_t kPasswordBytes = 12;

// 把 auth 的状态码翻成"给人看的一句话"。err 里偶尔带更具体的细节
// （比如某个文件的路径），能补就补上，重复了就只留状态文案。
std::string status_reason(auth::Status st, const std::string &detail) {
  std::string out = auth::status_text(st);
  if (!detail.empty() && detail != out) out += "（" + detail + "）";
  return out;
}

// Host 的回调统一返回 (成功?, 给人看的结果)，这里用两个小助手收敛写法。
std::pair<bool, std::string> fail(std::string msg) { return {false, std::move(msg)}; }
std::pair<bool, std::string> ok(std::string msg) { return {true, std::move(msg)}; }

}  // namespace

bool is_reserved_user(const std::string &user) {
  // 必须和 auth::Store::normalize 用同一套规则（trim + lowercase）：存储层
  // 会把 "ADMIN"、" admin "、"Admin" 都落到同一个 admin 账号文件上。只按原样
  // 字符串比较的话，这些写法就能绕过保留名检查 —— 面板里"删除 ADMIN"会真的
  // 删掉 admin 的账号文件，运维当场把自己锁在门外，而服务还在跑、没有自救手段。
  return util::to_lower(util::trim(user)) == kAdminUser;
}

bool ensure_admin(auth::Store &store, std::string &generated_password, std::string &error) {
  generated_password.clear();
  error.clear();

  // 已有 admin：什么都不做。这里的"绝不覆盖"是硬要求 —— 每次重启都换一次密码，
  // 运维永远记不住口令，界面上的"改密码"也会被下一次重启悄悄抹掉。
  if (store.has(kAdminUser)) return true;

  // has() 只看内存里的表。磁盘上已有 admin 文件而内存里没有，通常意味着这个
  // Store 还没 load 过；先重新载入一次再看。这一步不能省：Store::create 只查
  // 内存表，文件是直接原子写入的，跳过检查就会把现成的 admin 覆盖掉。
  const std::string admin_file = store.path_of(kAdminUser);
  if (util::file_exists(admin_file)) {
    std::string load_err;
    if (!store.load(load_err)) {
      error = "admin 账号文件已存在，但重新载入账号库失败：" + load_err;
      return false;
    }
    if (store.has(kAdminUser)) return true;
    // 文件在、却解析不出账号（内容被截断、salt/hash 缺失……）。宁可让运维
    // 手工处理，也不要用一套新密码把一份可能还能救回来的账号文件盖掉。
    error = "admin 账号文件无法解析（" + admin_file +
            "），为避免覆盖请先手工修复或删除它";
    return false;
  }

  unsigned char raw[kPasswordBytes];
  if (!crypto::random_bytes(raw, sizeof(raw))) {
    // 不能用 util::random_token 代替：它把 crypto::random_bytes 的失败吞掉，
    // 随机源不可用时会安安静静给出一个全零的"随机"密码。
    error = "生成随机密码失败：系统安全随机源不可用，admin 账号未创建";
    return false;
  }
  const std::string password = util::hex_encode(raw, sizeof(raw));

  // 防御性自检：create() 的校验才是唯一口径，这里先过一遍，免得生成的密码
  // 悄悄不满足要求、只换来一句含糊的失败。
  if (!auth::Store::valid_password(password)) {
    error = "生成的随机密码不满足账号库的格式要求，admin 账号未创建";
    return false;
  }

  std::string create_err;
  const auth::Status st = store.create(kAdminUser, kAdminDisplay, password, create_err);
  if (st == auth::Status::Exists) {
    // 从 has() 到 create() 之间，另一个进程（命令行 --add admin）抢先建好了。
    // 密码已经在它手里，本次不打印任何明文；但 admin 确实存在，面板能起来，
    // 所以按"已存在"当成功，让调用方照常挂面板。
    return true;
  }
  if (st != auth::Status::Ok) {
    error = "创建 admin 账号失败：" + status_reason(st, create_err);
    return false;
  }

  // 明文只在这里交出去一次；调用方打印之后，它只存在于运维的屏幕/剪贴板里。
  generated_password = password;
  return true;
}

jsonx::Json accounts_json(auth::Store &store) {
  jsonx::Json list = jsonx::Json::array();
  // Store::list 已经按 created_at 升序排好，正好是"先建的人在前"，
  // 面板不需要再排一次（也不想因为排序规则不同而两次启动顺序不一样）。
  for (const auto &a : store.list()) {
    jsonx::Json item = jsonx::Json::object();
    item["user"] = a.user;
    item["display"] = a.display.empty() ? a.user : a.display;
    item["created_at"] = a.created_at;
    item["last_login"] = a.last_login;
    // 只给"是不是那个不可删除的 admin"这一个布尔，界面据此禁用删除/改名按钮；
    // 具体的保留名规则留在 is_reserved_user 一处，前端不重复判断。
    item["admin"] = is_reserved_user(a.user);
    list.push_back(item);
  }
  return list;
}

void install_account_actions(auth::Store &store, Host &host) {
  // 按值捕获指针而不是捕获引用变量：闭包会被存进 Host、活到进程结束，
  // 捕获引用的话只要哪次把 Store 放在栈上就立刻悬垂。
  auth::Store *st = &store;

  host.add_user = [st](const std::string &user, const std::string &display,
                       const std::string &password) -> std::pair<bool, std::string> {
    if (is_reserved_user(user)) return fail("\"admin\" 是面板保留账号，不能新建同名账号");
    // 先热加载：命令行刚 --add 出来的账号不必重启服务也能看见；更要紧的是
    // create() 只查内存表，不重载就可能把别人刚建的账号文件直接覆盖掉。
    st->reload_if_changed();
    std::string err;
    const auth::Status s = st->create(util::to_lower(util::trim(user)), util::trim(display),
                                      password, err);
    if (s != auth::Status::Ok) return fail("新建账号失败：" + status_reason(s, err));
    return ok("已创建账号 " + util::to_lower(util::trim(user)));
  };

  host.del_user = [st](const std::string &user) -> std::pair<bool, std::string> {
    // 删 admin 等于把唯一的入口删掉：服务不会因此退出，但面板从此没人能登。
    if (is_reserved_user(user)) {
      return fail("\"admin\" 是面板保留账号，不能删除 —— 删掉就再也没有入口了");
    }
    st->reload_if_changed();
    std::string err;
    const auth::Status s = st->remove(util::trim(user), err);
    if (s != auth::Status::Ok) return fail("删除账号失败：" + status_reason(s, err));
    return ok("已删除账号 " + util::to_lower(util::trim(user)));
  };

  host.rename_user = [st](const std::string &old_user,
                          const std::string &new_user) -> std::pair<bool, std::string> {
    // 两个方向都要拦：改名源是 admin 会把入口改名，改名目标叫 admin 会抢名字。
    if (is_reserved_user(old_user)) {
      return fail("\"admin\" 是面板保留账号，不能改名 —— 面板的登录名固定在它上面");
    }
    if (is_reserved_user(new_user)) return fail("\"admin\" 是保留名，不能把别的账号改成它");
    st->reload_if_changed();
    std::string err;
    const auth::Status s = st->rename(util::trim(old_user), util::trim(new_user), err);
    if (s != auth::Status::Ok) return fail("改名失败：" + status_reason(s, err));
    return ok("已把 " + util::to_lower(util::trim(old_user)) + " 改名为 " +
              util::to_lower(util::trim(new_user)));
  };

  host.set_password = [st](const std::string &user,
                           const std::string &password) -> std::pair<bool, std::string> {
    // 改密码这里不拦 admin：面板没有"重置 admin 密码"的别的通道，拦了就等于
    // 运维永远没法轮换自己的口令（只能回命令行，而那正是面板想省掉的仪式）。
    if (password.size() < kMinPassword || password.size() > kMaxPassword) {
      return fail("密码长度必须是 6 到 512 个字符");
    }
    st->reload_if_changed();
    std::string err;
    const auth::Status s = st->set_password(util::trim(user), password, err);
    if (s != auth::Status::Ok) return fail("修改密码失败：" + status_reason(s, err));
    // 明文不落盘：Store 会重新生成盐并只写哈希，这里只是把这件事告诉运维。
    return ok("已修改 " + util::to_lower(util::trim(user)) +
              " 的密码（服务端已重新加盐，明文不落盘）");
  };
}

}  // namespace panel
