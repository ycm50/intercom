#include "crypto.h"

#include <cstring>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace crypto {

namespace {

const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2};

inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

void sha256_block(Sha256 &ctx, const unsigned char *p) {
  uint32_t w[64];
  for (int i = 0; i < 16; ++i) {
    w[i] = (uint32_t(p[i * 4]) << 24) | (uint32_t(p[i * 4 + 1]) << 16) |
           (uint32_t(p[i * 4 + 2]) << 8) | uint32_t(p[i * 4 + 3]);
  }
  for (int i = 16; i < 64; ++i) {
    uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
    uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  uint32_t a = ctx.state[0], b = ctx.state[1], c = ctx.state[2], d = ctx.state[3];
  uint32_t e = ctx.state[4], f = ctx.state[5], g = ctx.state[6], h = ctx.state[7];
  for (int i = 0; i < 64; ++i) {
    uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    uint32_t ch = (e & f) ^ ((~e) & g);
    uint32_t t1 = h + S1 + ch + K[i] + w[i];
    uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t t2 = S0 + maj;
    h = g; g = f; f = e; e = d + t1;
    d = c; c = b; b = a; a = t1 + t2;
  }
  ctx.state[0] += a; ctx.state[1] += b; ctx.state[2] += c; ctx.state[3] += d;
  ctx.state[4] += e; ctx.state[5] += f; ctx.state[6] += g; ctx.state[7] += h;
}

}  // namespace

void sha256_init(Sha256 &ctx) {
  ctx.state[0] = 0x6a09e667; ctx.state[1] = 0xbb67ae85;
  ctx.state[2] = 0x3c6ef372; ctx.state[3] = 0xa54ff53a;
  ctx.state[4] = 0x510e527f; ctx.state[5] = 0x9b05688c;
  ctx.state[6] = 0x1f83d9ab; ctx.state[7] = 0x5be0cd19;
  ctx.bitlen = 0;
  ctx.buflen = 0;
}

void sha256_update(Sha256 &ctx, const void *data, size_t len) {
  const unsigned char *p = static_cast<const unsigned char *>(data);
  ctx.bitlen += uint64_t(len) * 8;
  while (len > 0) {
    size_t take = 64 - ctx.buflen;
    if (take > len) take = len;
    std::memcpy(ctx.buffer + ctx.buflen, p, take);
    ctx.buflen += take;
    p += take;
    len -= take;
    if (ctx.buflen == 64) {
      sha256_block(ctx, ctx.buffer);
      ctx.buflen = 0;
    }
  }
}

void sha256_final(Sha256 &ctx, unsigned char out[32]) {
  uint64_t bits = ctx.bitlen;
  unsigned char pad = 0x80;
  sha256_update(ctx, &pad, 1);
  unsigned char zero = 0;
  while (ctx.buflen != 56) sha256_update(ctx, &zero, 1);
  unsigned char lenbuf[8];
  for (int i = 0; i < 8; ++i) lenbuf[i] = static_cast<unsigned char>(bits >> (56 - i * 8));
  // 直接写入缓冲区，避免再次累加 bitlen
  std::memcpy(ctx.buffer + 56, lenbuf, 8);
  sha256_block(ctx, ctx.buffer);
  for (int i = 0; i < 8; ++i) {
    out[i * 4] = static_cast<unsigned char>(ctx.state[i] >> 24);
    out[i * 4 + 1] = static_cast<unsigned char>(ctx.state[i] >> 16);
    out[i * 4 + 2] = static_cast<unsigned char>(ctx.state[i] >> 8);
    out[i * 4 + 3] = static_cast<unsigned char>(ctx.state[i]);
  }
}

void sha256(const void *data, size_t len, unsigned char out[32]) {
  Sha256 ctx;
  sha256_init(ctx);
  sha256_update(ctx, data, len);
  sha256_final(ctx, out);
}

std::string sha256_hex(const std::string &data) {
  unsigned char digest[32];
  sha256(data.data(), data.size(), digest);
  static const char *d = "0123456789abcdef";
  std::string out;
  out.reserve(64);
  for (int i = 0; i < 32; ++i) {
    out.push_back(d[digest[i] >> 4]);
    out.push_back(d[digest[i] & 0x0f]);
  }
  return out;
}

void hmac_sha256(const unsigned char *key, size_t key_len, const unsigned char *data,
                 size_t data_len, unsigned char out[32]) {
  unsigned char k[64];
  std::memset(k, 0, sizeof(k));
  if (key_len > 64) {
    sha256(key, key_len, k);
  } else {
    std::memcpy(k, key, key_len);
  }
  unsigned char ipad[64];
  unsigned char opad[64];
  for (int i = 0; i < 64; ++i) {
    ipad[i] = k[i] ^ 0x36;
    opad[i] = k[i] ^ 0x5c;
  }
  Sha256 ctx;
  sha256_init(ctx);
  sha256_update(ctx, ipad, 64);
  sha256_update(ctx, data, data_len);
  unsigned char inner[32];
  sha256_final(ctx, inner);

  sha256_init(ctx);
  sha256_update(ctx, opad, 64);
  sha256_update(ctx, inner, 32);
  sha256_final(ctx, out);
}

bool pbkdf2_sha256(const std::string &password, const unsigned char *salt, size_t salt_len,
                   int iterations, unsigned char *out, size_t out_len) {
  if (iterations < 1 || out_len == 0) return false;
  const size_t hlen = 32;
  size_t blocks = (out_len + hlen - 1) / hlen;
  for (size_t i = 1; i <= blocks; ++i) {
    unsigned char u[32];
    unsigned char t[32];
    unsigned char counter[4] = {static_cast<unsigned char>(i >> 24),
                                static_cast<unsigned char>(i >> 16),
                                static_cast<unsigned char>(i >> 8),
                                static_cast<unsigned char>(i)};
    // U1 = HMAC(password, salt || INT(i))
    unsigned char msg[256];
    size_t msg_len = salt_len + 4;
    if (msg_len > sizeof(msg)) return false;
    std::memcpy(msg, salt, salt_len);
    std::memcpy(msg + salt_len, counter, 4);
    const unsigned char *pwd = password.empty()
        ? reinterpret_cast<const unsigned char *>("")
        : reinterpret_cast<const unsigned char *>(password.data());
    hmac_sha256(pwd, password.size(), msg, msg_len, u);
    std::memcpy(t, u, hlen);
    for (int j = 1; j < iterations; ++j) {
      unsigned char u2[32];
      hmac_sha256(pwd, password.size(), u, hlen, u2);
      std::memcpy(u, u2, hlen);
      for (size_t k = 0; k < hlen; ++k) t[k] ^= u[k];
    }
    size_t offset = (i - 1) * hlen;
    size_t chunk = out_len - offset < hlen ? out_len - offset : hlen;
    std::memcpy(out + offset, t, chunk);
  }
  return true;
}

bool random_bytes(unsigned char *out, size_t len) {
  if (len == 0) return true;
#if defined(_WIN32)
  return ::BCryptGenRandom(nullptr, out, static_cast<ULONG>(len),
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
#else
  int fd = ::open("/dev/urandom", O_RDONLY);
  if (fd < 0) return false;
  size_t got = 0;
  while (got < len) {
    ssize_t n = ::read(fd, out + got, len - got);
    if (n <= 0) {
      ::close(fd);
      return false;
    }
    got += static_cast<size_t>(n);
  }
  ::close(fd);
  return true;
#endif
}

}  // namespace crypto
