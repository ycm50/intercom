#pragma once
// 内置密码学原语：SHA-256 / HMAC-SHA256 / PBKDF2-HMAC-SHA256 / 安全随机数
//
// 为了让服务端在 amd64 / arm64 等各类 Linux 服务器上「不装任何开发包」就能编译，
// 这里用纯 C++ 实现，不依赖 OpenSSL（Windows 与 Linux 共用同一份代码）。
#include <cstddef>
#include <cstdint>
#include <string>

namespace crypto {

struct Sha256 {
  uint32_t state[8];
  uint64_t bitlen;
  unsigned char buffer[64];
  size_t buflen;
};

void sha256_init(Sha256 &ctx);
void sha256_update(Sha256 &ctx, const void *data, size_t len);
void sha256_final(Sha256 &ctx, unsigned char out[32]);

// 一次性计算
void sha256(const void *data, size_t len, unsigned char out[32]);
std::string sha256_hex(const std::string &data);

// HMAC-SHA256
void hmac_sha256(const unsigned char *key, size_t key_len, const unsigned char *data,
                 size_t data_len, unsigned char out[32]);

// PBKDF2-HMAC-SHA256，输出 dk_len 字节
bool pbkdf2_sha256(const std::string &password, const unsigned char *salt, size_t salt_len,
                   int iterations, unsigned char *out, size_t out_len);

// 安全随机数（失败返回 false）
bool random_bytes(unsigned char *out, size_t len);

}  // namespace crypto
