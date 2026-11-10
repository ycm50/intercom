#pragma once
// 小工具集合：字符串、编码、十六进制、随机数、文件读写
#include <cstdint>
#include <string>
#include <vector>

namespace util {

std::string trim(const std::string &s);
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