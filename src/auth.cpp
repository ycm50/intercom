#include "auth.h"

#include <algorithm>
#include <cctype>
#include <ctime>

#include "crypto.h"
#include "json.h"
#include "util.h"

namespace auth {

namespace {

const int kSaltBytes = 16;
const int kHashBytes = 32;
const int kMaxFailures = 8;
const int64_t kLockSeconds = 120;

std::string lowercase(const std::string &s) {
  std::string out = s;
  std::transform(out.begin(), out.end(), out.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return out;
}

bool pbkdf2(const std::string &password, const std::string &salt_hex, int iterations,
            std::string &hash_hex) {
  unsigned char salt[64];
  size_t salt_len = salt_hex.size() / 2;
  if (salt_len == 0 || salt_len > sizeof(salt)) return false;
  auto hexval = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (size_t i = 0; i < salt_len; ++i) {
    int hi = hexval(salt_hex[i * 2]);
    int lo = hexval(salt_hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) return false;
    salt[i] = static_cast<unsigned char>((hi << 4) | lo);
  }
  unsigned char out[kHashBytes];
  if (!crypto::pbkdf2_sha256(password, salt, salt_len, iterations, out, kHashBytes)) {
    return false;
  }
  hash_hex = util::hex_encode(out, kHashBytes);
  return true;
}

bool constant_time_equal(const std::string &a, const std::string &b) {
  if (a.size() != b.size()) return false;
  unsigned char diff = 0;
  for (size_t i = 0; i < a.size(); ++i) {
    diff |= static_cast<unsigned char>(a[i] ^ b[i]);
  }
  return diff == 0;
}

}  // namespace

const char *status_text(Status s) {
  switch (s) {
    case Status::Ok: return "成功";
    case Status::NoUser: return "用户不存在";
    case Status::BadPassword: return "密码错误";
    case Status::Exists: return "用户已存在";
    case Status::BadName: return "用户名不合法：只能用英文/数字/常见符号（1-64 个字符），不能用汉字或空格";
    case Status::BadPasswordFormat: return "密码不能为空（长度上限 512 字节）";
    case Status::Locked: return "尝试次数过多，请稍后再试";
    case Status::IoError: return "账号文件读写失败";
  }
  return "未知错误";
}

Store::Store(std::string dir) {
  if (dir.empty()) dir = util::join_path(util::join_path(util::home_dir(), ".intercom"), "");
  dir_ = dir;
}

// 用户名（ID）只允许 ASCII 可见字符（0x21-0x7E）：字母、数字、下划线、短横线、点、
// 以及 ~ ! @ # $ % ^ & * ( ) + = { } [ ] | \ / : ; " ' , < > ? 等常见符号。
// 不允许汉字、空格、控制字符——避免终端编码不一致导致「看不到却输不对」。
// 密码不限制（可用中文/空格/符号），展示名也不限制。
bool Store::valid_username(const std::string &user) {
  std::string u = util::trim(user);
  if (u.empty() || u.size() > 64) return false;
  for (unsigned char c : u) {
    if (c < 0x21 || c > 0x7E) return false;  // 排除空格、控制字符、非 ASCII
  }
  return true;
}

bool Store::valid_password(const std::string &password) {
  return !password.empty() && password.size() <= 512;
}

// 用户名直接当文件名会有非法字符，这里做百分号转义：
// 字母/数字/._- 原样保留，其余字节按 %XX 编码，保证任何用户名都能安全落盘。
static std::string encode_filename(const std::string &name) {
  static const char *hex = "0123456789ABCDEF";
  std::string out;
  out.reserve(name.size() * 3);
  for (unsigned char c : name) {
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
        c == '.' || c == '_' || c == '-') {
      out.push_back(static_cast<char>(c));
    } else {
      out.push_back('%');
      out.push_back(hex[c >> 4]);
      out.push_back(hex[c & 0x0F]);
    }
  }
  if (out.empty()) out = "%00";
  return out;
}

std::string Store::normalize(const std::string &user) const {
  return lowercase(util::trim(user));
}

std::string Store::path_of(const std::string &user) const {
  return util::join_path(dir_, encode_filename(normalize(user)) + ".json");
}

bool Store::parse_account_file(const std::string &path, Account &out) {
  std::string text;
  if (!util::read_file(path, text)) return false;
  jsonx::Json doc;
  if (!jsonx::parse(text, doc) || !doc.is_object()) return false;
  out.user = lowercase(jsonx::str(doc, "user"));
  out.display = jsonx::str(doc, "display", out.user);
  out.salt = jsonx::str(doc, "salt");
  out.hash = jsonx::str(doc, "hash");
  out.iterations = static_cast<int>(jsonx::num(doc, "iterations", 210000));
  out.created_at = jsonx::num(doc, "created_at", 0);
  out.last_login = jsonx::num(doc, "last_login", 0);
  out.file = path;
  if (out.user.empty() || out.salt.empty() || out.hash.empty()) return false;
  return true;
}

bool Store::save_account(const Account &a, std::string &err) {
  // 调用方已持有锁
  jsonx::Json doc;
  doc["version"] = 1;
  doc["user"] = a.user;
  doc["display"] = a.display;
  doc["salt"] = a.salt;
  doc["hash"] = a.hash;
  doc["iterations"] = a.iterations;
  doc["created_at"] = a.created_at;
  doc["last_login"] = a.last_login;
  doc["algo"] = "pbkdf2-hmac-sha256";
  return util::write_file_atomic(path_of(a.user), jsonx::dump(doc), err);
}

bool Store::load(std::string &err) {
  std::lock_guard<std::mutex> lk(mu_);
  if (!util::make_dirs(dir_, err)) return false;
  accounts_.clear();
  dir_stamp_ = util::file_mtime_ns(dir_);
  for (const auto &path : util::list_files(dir_, ".json")) {
    Account a;
    if (!parse_account_file(path, a)) continue;
    accounts_[a.user] = a;
  }
  return true;
}

bool Store::reload_if_changed() {
  {
    std::lock_guard<std::mutex> lk(mu_);
    if (util::file_mtime_ns(dir_) == dir_stamp_) return false;
  }
  std::string err;
  load(err);
  return true;
}

Status Store::create(const std::string &user, const std::string &display,
                            const std::string &password, std::string &err) {
  std::string key = normalize(user);
  if (!valid_username(key)) return Status::BadName;
  if (!valid_password(password)) return Status::BadPasswordFormat;

  std::lock_guard<std::mutex> lk(mu_);
  if (accounts_.count(key)) return Status::Exists;
  if (!util::make_dirs(dir_, err)) return Status::IoError;

  Account a;
  a.user = key;
  a.display = util::trim(display).empty() ? key : util::trim(display).substr(0, 64);
  // 服务端生成盐并计算哈希
  std::string raw_salt = util::random_bytes(kSaltBytes);
  a.salt = util::hex_encode(reinterpret_cast<const unsigned char *>(raw_salt.data()),
                            raw_salt.size());
  a.iterations = iterations_;
  if (!pbkdf2(password, a.salt, a.iterations, a.hash)) {
    err = "哈希计算失败";
    return Status::IoError;
  }
  a.created_at = util::now_sec();
  a.file = path_of(key);
  if (!save_account(a, err)) return Status::IoError;
  accounts_[key] = a;
  dir_stamp_ = util::file_mtime_ns(dir_);
  return Status::Ok;
}

Status Store::set_password(const std::string &user, const std::string &password,
                                  std::string &err) {
  std::string key = normalize(user);
  if (!valid_password(password)) return Status::BadPasswordFormat;
  std::lock_guard<std::mutex> lk(mu_);
  auto it = accounts_.find(key);
  if (it == accounts_.end()) return Status::NoUser;
  // 换密码时重新生成盐，避免旧盐复用
  std::string raw_salt = util::random_bytes(kSaltBytes);
  it->second.salt = util::hex_encode(reinterpret_cast<const unsigned char *>(raw_salt.data()),
                                     raw_salt.size());
  it->second.iterations = iterations_;
  if (!pbkdf2(password, it->second.salt, it->second.iterations, it->second.hash)) {
    err = "哈希计算失败";
    return Status::IoError;
  }
  if (!save_account(it->second, err)) return Status::IoError;
  failures_.erase(key);
  dir_stamp_ = util::file_mtime_ns(dir_);
  return Status::Ok;
}

Status Store::rename(const std::string &old_user, const std::string &new_user,
                            std::string &err) {
  std::string from = normalize(old_user);
  std::string to = normalize(new_user);
  if (!valid_username(to)) return Status::BadName;
  std::lock_guard<std::mutex> lk(mu_);
  auto it = accounts_.find(from);
  if (it == accounts_.end()) return Status::NoUser;
  if (accounts_.count(to)) return Status::Exists;

  Account acc = it->second;
  std::string old_path = path_of(from);
  acc.user = to;
  acc.file = path_of(to);
  if (!save_account(acc, err)) return Status::IoError;
  std::string rm_err;
  util::remove_file(old_path, rm_err);

  accounts_.erase(from);
  accounts_[to] = acc;
  dir_stamp_ = util::file_mtime_ns(dir_);
  return Status::Ok;
}

Status Store::remove(const std::string &user, std::string &err) {
  std::string key = normalize(user);
  std::lock_guard<std::mutex> lk(mu_);
  auto it = accounts_.find(key);
  if (it == accounts_.end()) return Status::NoUser;
  if (!util::remove_file(path_of(key), err)) return Status::IoError;
  accounts_.erase(it);
  failures_.erase(key);
  dir_stamp_ = util::file_mtime_ns(dir_);
  return Status::Ok;
}

std::vector<Account> Store::list() {
  std::lock_guard<std::mutex> lk(mu_);
  std::vector<Account> out;
  out.reserve(accounts_.size());
  for (const auto &kv : accounts_) out.push_back(kv.second);
  std::sort(out.begin(), out.end(), [](const Account &a, const Account &b) {
    return a.created_at < b.created_at;
  });
  return out;
}

bool Store::has(const std::string &user) {
  std::string key = normalize(user);
  std::lock_guard<std::mutex> lk(mu_);
  return accounts_.count(key) > 0;
}

Status Store::verify(const std::string &user, const std::string &password) {
  std::string key = normalize(user);

  // 每次验证都从磁盘读取该账号文件，保证文件被外部改动后立刻生效
  Account acc;
  if (!parse_account_file(path_of(key), acc)) {
    std::lock_guard<std::mutex> lk(mu_);
    return Status::NoUser;
  }
  acc.user = key;

  std::lock_guard<std::mutex> lk(mu_);
  Failure &f = failures_[key];
  int64_t now = util::now_sec();
  if (f.lock_until > now) return Status::Locked;

  std::string hash_hex;
  if (!pbkdf2(password, acc.salt, acc.iterations, hash_hex)) return Status::IoError;

  if (!constant_time_equal(hash_hex, acc.hash)) {
    if (++f.count >= kMaxFailures) {
      f.count = 0;
      f.lock_until = now + kLockSeconds;
      return Status::Locked;
    }
    return Status::BadPassword;
  }
  f.count = 0;
  f.lock_until = 0;
  acc.last_login = util::now_sec();
  accounts_[key] = acc;
  std::string err;
  save_account(acc, err);  // 记录最近登录时间，失败不影响登录
  return Status::Ok;
}

}  // namespace auth