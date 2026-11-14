#include "util.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <climits>
#include <cstring>
#include <ctime>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <random>
#include <system_error>

#if !defined(_WIN32)
#include <unistd.h>
#endif

#include "crypto.h"

#if defined(_WIN32)
#include <windows.h>
#endif

namespace util {

std::string trim(const std::string &s) {
  size_t b = 0, e = s.size();
  while (b < e && static_cast<unsigned char>(s[b]) <= ' ') ++b;
  while (e > b && static_cast<unsigned char>(s[e - 1]) <= ' ') --e;
  return s.substr(b, e - b);
}

bool parse_long(const char *s, long &out, const char **end) {
  out = 0;
  if (s == nullptr) {
    if (end != nullptr) *end = nullptr;
    return false;
  }
  const char *p = s;
  // 前导空白：与 strtol 一致。
  while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == '\f' || *p == '\v') ++p;
  bool neg = false;
  if (*p == '+' || *p == '-') {
    neg = (*p == '-');
    ++p;
  }
  if (*p < '0' || *p > '9') {
    // 没有数字：明确告诉调用方失败。本项目所有调用点都要求真的解析出数字，
    // 0 是合法的 pid/端口，不能拿它当错误值。
    if (end != nullptr) *end = s;
    return false;
  }
  // 用无符号累加再判断溢出：直接对 long 乘加，溢出是 UB。
  unsigned long acc = 0;
  const unsigned long limit =
      neg ? static_cast<unsigned long>(-(LONG_MIN + 1)) + 1UL : static_cast<unsigned long>(LONG_MAX);
  while (*p >= '0' && *p <= '9') {
    const unsigned long d = static_cast<unsigned long>(*p - '0');
    if (acc > (limit - d) / 10) {
      if (end != nullptr) *end = p;
      return false;
    }
    acc = acc * 10 + d;
    ++p;
  }
  out = neg ? static_cast<long>(0UL - acc) : static_cast<long>(acc);
  if (end != nullptr) *end = p;
  return true;
}

std::string to_lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return s;
}

bool starts_with(const std::string &s, const std::string &p) {
  return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}

bool ends_with(const std::string &s, const std::string &p) {
  return s.size() >= p.size() && s.compare(s.size() - p.size(), p.size(), p) == 0;
}

std::vector<std::string> split(const std::string &s, char sep) {
  std::vector<std::string> out;
  std::string cur;
  for (char c : s) {
    if (c == sep) {
      out.push_back(cur);
      cur.clear();
    } else {
      cur.push_back(c);
    }
  }
  out.push_back(cur);
  return out;
}

static const char *kB64 =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string b64_encode(const unsigned char *data, size_t len) {
  std::string out;
  out.reserve(((len + 2) / 3) * 4);
  size_t i = 0;
  for (; i + 2 < len; i += 3) {
    uint32_t v = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8) | data[i + 2];
    out.push_back(kB64[(v >> 18) & 0x3f]);
    out.push_back(kB64[(v >> 12) & 0x3f]);
    out.push_back(kB64[(v >> 6) & 0x3f]);
    out.push_back(kB64[v & 0x3f]);
  }
  if (i + 1 == len) {
    uint32_t v = uint32_t(data[i]) << 16;
    out.push_back(kB64[(v >> 18) & 0x3f]);
    out.push_back(kB64[(v >> 12) & 0x3f]);
    out.push_back('=');
    out.push_back('=');
  } else if (i + 2 == len) {
    uint32_t v = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8);
    out.push_back(kB64[(v >> 18) & 0x3f]);
    out.push_back(kB64[(v >> 12) & 0x3f]);
    out.push_back(kB64[(v >> 6) & 0x3f]);
    out.push_back('=');
  }
  return out;
}

std::string b64_encode(const std::string &in) {
  return b64_encode(reinterpret_cast<const unsigned char *>(in.data()), in.size());
}

bool b64_decode(const std::string &in, std::string &out) {
  static int table[256];
  static bool init = false;
  if (!init) {
    for (int i = 0; i < 256; ++i) table[i] = -1;
    for (int i = 0; i < 64; ++i) table[static_cast<unsigned char>(kB64[i])] = i;
    table[static_cast<unsigned char>('-')] = 62;
    table[static_cast<unsigned char>('_')] = 63;
    init = true;
  }
  out.clear();
  out.reserve(in.size() * 3 / 4 + 3);
  uint32_t acc = 0;
  int bits = 0;
  for (char c : in) {
    int v = table[static_cast<unsigned char>(c)];
    if (v < 0) {
      if (c == '=' || c == '\n' || c == '\r') continue;
      return false;
    }
    acc = (acc << 6) | uint32_t(v);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<char>((acc >> bits) & 0xff));
    }
  }
  return true;
}

std::string hex_encode(const unsigned char *data, size_t len) {
  static const char *d = "0123456789abcdef";
  std::string out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; ++i) {
    out.push_back(d[data[i] >> 4]);
    out.push_back(d[data[i] & 0x0f]);
  }
  return out;
}

std::string random_bytes(size_t n) {
  std::string out(n, '\0');
  if (n == 0) return out;
  crypto::random_bytes(reinterpret_cast<unsigned char *>(&out[0]), n);
  return out;
}

std::string random_token(size_t n) {
  std::string raw = random_bytes(n);
  return hex_encode(reinterpret_cast<const unsigned char *>(raw.data()), raw.size());
}

uint64_t now_ms() {
  using namespace std::chrono;
  return static_cast<uint64_t>(
      duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

int64_t now_sec() { return static_cast<int64_t>(now_ms() / 1000); }

std::string now_string() {
  std::time_t t = std::time(nullptr);
  std::tm tmv{};
#if defined(_WIN32)
  localtime_s(&tmv, &t);
#else
  localtime_r(&t, &tmv);
#endif
  char buf[32];
  std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmv);
  return buf;
}

bool read_file(const std::string &path, std::string &out) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return false;
  std::string data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  out.swap(data);
  return true;
}

bool write_file_atomic(const std::string &path, const std::string &data, std::string &err) {
  std::filesystem::path p(path);
  std::filesystem::path dir = p.parent_path();
  if (!dir.empty()) {
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) {
      err = "无法创建目录 " + dir.string() + ": " + ec.message();
      return false;
    }
  }
  std::string tmp = path + ".tmp";
  {
    std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
    if (!f) {
      err = "无法写入临时文件 " + tmp;
      return false;
    }
    f.write(data.data(), static_cast<std::streamsize>(data.size()));
    if (!f) {
      err = "写入失败 " + tmp;
      return false;
    }
  }
  std::error_code ec;
#if defined(_WIN32)
  std::filesystem::rename(tmp, path, ec);
  if (ec) {
    std::filesystem::remove(path, ec);
    ec.clear();
    std::filesystem::rename(tmp, path, ec);
  }
#else
  std::filesystem::rename(tmp, path, ec);
#endif
  if (ec) {
    err = "无法保存 " + path + ": " + ec.message();
    return false;
  }
  return true;
}

bool file_exists(const std::string &path) {
  std::error_code ec;
  return std::filesystem::is_regular_file(path, ec);
}

std::string join_path(const std::string &a, const std::string &b) {
  if (a.empty()) return b;
  std::filesystem::path p(a);
  p /= b;
  return p.string();
}

std::string home_dir() {
#if defined(_WIN32)
  const char *up = std::getenv("USERPROFILE");
  if (up && *up) return up;
  const char *hd = std::getenv("HOMEDRIVE");
  const char *hp = std::getenv("HOMEPATH");
  if (hd && hp) return std::string(hd) + hp;
  return ".";
#else
  const char *h = std::getenv("HOME");
  if (h && *h) return h;
  return ".";
#endif
}

std::vector<std::string> list_files(const std::string &dir, const std::string &ext) {
  std::vector<std::string> out;
  std::error_code ec;
  if (!std::filesystem::is_directory(dir, ec)) return out;
  for (const auto &entry : std::filesystem::directory_iterator(dir, ec)) {
    if (ec) break;
    if (!entry.is_regular_file()) continue;
    std::string p = entry.path().string();
    if (!ext.empty() && !ends_with(p, ext)) continue;
    out.push_back(p);
  }
  return out;
}

bool make_dirs(const std::string &dir, std::string &err) {
  std::error_code ec;
  std::filesystem::create_directories(dir, ec);
  if (ec) {
    err = "无法创建目录 " + dir + ": " + ec.message();
    return false;
  }
  return true;
}

bool remove_file(const std::string &path, std::string &err) {
  std::error_code ec;
  std::filesystem::remove(path, ec);
  if (ec) {
    err = "无法删除 " + path + ": " + ec.message();
    return false;
  }
  return true;
}

int64_t file_mtime_ns(const std::string &path) {
  std::error_code ec;
  auto ts = std::filesystem::last_write_time(path, ec);
  if (ec) return -1;
  return static_cast<int64_t>(ts.time_since_epoch().count());
}

std::string exe_dir() {
#if defined(_WIN32)
  char buf[MAX_PATH * 4];
  DWORD n = ::GetModuleFileNameA(nullptr, buf, sizeof(buf));
  if (n == 0) return ".";
  std::string full(buf, n);
  size_t pos = full.find_last_of("\\/");
  return pos == std::string::npos ? std::string(".") : full.substr(0, pos);
#else
  // Linux：从 /proc/self/exe 取真实路径，保证 data / public 默认跟着可执行文件走
  char buf[4096];
  ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
  if (n <= 0) return ".";
  buf[n] = '\0';
  std::string full(buf);
  size_t pos = full.find_last_of('/');
  return pos == std::string::npos ? std::string(".") : full.substr(0, pos);
#endif
}

}  // namespace util