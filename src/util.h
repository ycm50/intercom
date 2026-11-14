#pragma once
// 小工具集合：字符串、编码、十六进制、随机数、文件读写
#include <cstdint>
#include <string>
#include <vector>

namespace util {

std::string trim(const std::string &s);

// 解析十进制整数（pid、端口、行数这类）。
//
// 为什么不用 std::strtol：glibc 2.38 起它被 __REDIRECT 到 __isoc23_strtol，
// 而新版 libstdc++ 会强制走那条路。结果是在 glibc 2.41 上编出来的二进制
// 拿到 Debian 12（2.36）上直接报 "GLIBC_2.38 not found"，整个程序起不来。
// 自己解析没有这个耦合，而且这几处调用点本来就只需要十进制。
//
// 失败返回 false 并把 out 置 0；成功时 out 是结果，end 指向第一个未消费字符
// （不需要时传 nullptr）。允许前导空白与正负号，与 strtol 一致。
bool parse_long(const char *s, long &out, const char **end = nullptr);
std::string to_lower(std::string s);
bool starts_with(const std::string &s, const std::string &p);
bool ends_with(const std::string &s, const std::string &p);
std::vector<std::string> split(const std::string &s, char sep);

std::string b64_encode(const std::string &in);
std::string b64_encode(const unsigned char *data, size_t len);
bool b64_decode(const std::string &in, std::string &out);

std::string hex_encode(const unsigned char *data, size_t len);
std::string random_bytes(size_t n);
std::string random_token(size_t n);

uint64_t now_ms();
int64_t now_sec();
std::string now_string();  // 本地时间 "YYYY-MM-DD HH:MM:SS"

bool read_file(const std::string &path, std::string &out);
bool write_file_atomic(const std::string &path, const std::string &data, std::string &err);
bool file_exists(const std::string &path);

std::string join_path(const std::string &a, const std::string &b);
std::string exe_dir();
std::string home_dir();          // 用户主目录（Windows: %USERPROFILE%，Linux: $HOME）
std::vector<std::string> list_files(const std::string &dir, const std::string &ext);
bool make_dirs(const std::string &dir, std::string &err);
bool remove_file(const std::string &path, std::string &err);
int64_t file_mtime_ns(const std::string &path);  // 不存在返回 -1

}  // namespace util