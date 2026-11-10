#pragma once
// 账号库：每个账号一个独立文件 ~/.intercom/<userid>.json
//
// 存储策略：
//   - 密码只以 PBKDF2-HMAC-SHA256(密码, 每账号随机盐, 210000 轮) 的哈希形式保存；
//   - 盐由服务端生成并与哈希一起写入该账号的文件；
//   - 验证时读文件、用文件里的盐重新计算哈希做恒定时间比较；
//   - --passwd 改密码、--un 改用户名都在服务端完成加盐与哈希，明文密码从不落盘。
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace auth {

struct Account {
  std::string user;        // 小写用户 ID（也是文件名）
  std::string display;     // 展示名
  std::string salt;        // 十六进制盐（服务端生成）
  std::string hash;        // 十六进制哈希
  int iterations = 0;
  int64_t created_at = 0;
  int64_t last_login = 0;
  std::string file;        // 账号文件完整路径
};

enum class Status {
  Ok,
  NoUser,
  BadPassword,
  Exists,
  BadName,
  BadPasswordFormat,
  Locked,
  IoError,
};

const char *status_text(Status s);

class Store {
 public:
  // dir 为空时使用 ~/.intercom
  explicit Store(std::string dir);

  bool load(std::string &err);
  bool reload_if_changed();  // 目录或文件变动时重新载入

  Status create(const std::string &user, const std::string &display,
                const std::string &password, std::string &err);
  Status set_password(const std::string &user, const std::string &password, std::string &err);
  Status rename(const std::string &old_user, const std::string &new_user, std::string &err);
  Status remove(const std::string &user, std::string &err);
  std::vector<Account> list();

  Status verify(const std::string &user, const std::string &password);
  bool has(const std::string &user);

  const std::string &dir() const { return dir_; }
  std::string path_of(const std::string &user) const;

  static bool valid_username(const std::string &user);
  static bool valid_password(const std::string &password);

 private:
  struct Failure {
    int count = 0;
    int64_t lock_until = 0;
  };

  bool save_account(const Account &a, std::string &err);
  bool parse_account_file(const std::string &path, Account &out);
  std::string normalize(const std::string &user) const;

  std::string dir_;
  std::mutex mu_;
  std::unordered_map<std::string, Account> accounts_;
  std::unordered_map<std::string, Failure> failures_;
  int iterations_ = 210000;
  int64_t dir_stamp_ = -1;
};

}  // namespace auth
