// 验证内置 crypto 与 OpenSSL 结果一致（PBKDF2 / SHA256 / HMAC）
#include <cstdio>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include "../src/crypto.h"

static std::string hex(const unsigned char *d, size_t n) {
  static const char *t = "0123456789abcdef";
  std::string s;
  for (size_t i = 0; i < n; ++i) { s.push_back(t[d[i] >> 4]); s.push_back(t[d[i] & 15]); }
  return s;
}

int main() {
  int fail = 0;
  // 1. SHA-256
  const char *vectors[] = {"", "abc", "The quick brown fox jumps over the lazy dog"};
  for (const char *v : vectors) {
    unsigned char a[32], b[32];
    crypto::sha256(v, strlen(v), a);
    SHA256(reinterpret_cast<const unsigned char *>(v), strlen(v), b);
    if (hex(a, 32) != hex(b, 32)) { printf("SHA256 不一致: %s\n", v); fail++; }
  }
  // 2. HMAC-SHA256
  {
    const char *key = "key-测试";
    const char *msg = "message-内容";
    unsigned char a[32], b[32];
    crypto::hmac_sha256(reinterpret_cast<const unsigned char *>(key), strlen(key),
                        reinterpret_cast<const unsigned char *>(msg), strlen(msg), a);
    unsigned int blen = 32;
    HMAC(EVP_sha256(), key, (int)strlen(key),
         reinterpret_cast<const unsigned char *>(msg), strlen(msg), b, &blen);
    if (hex(a, 32) != hex(b, 32)) { printf("HMAC 不一致\n"); fail++; }
  }
  // 3. PBKDF2 多轮
  for (int iter : {1, 1000, 210000}) {
    const char *pwd = "alicepass1";
    unsigned char salt[16];
    for (int i = 0; i < 16; ++i) salt[i] = (unsigned char)(i * 7 + 3);
    unsigned char a[32], b[32];
    crypto::pbkdf2_sha256(pwd, salt, 16, iter, a, 32);
    PKCS5_PBKDF2_HMAC(pwd, (int)strlen(pwd), salt, 16, iter, EVP_sha256(), 32, b);
    if (hex(a, 32) != hex(b, 32)) { printf("PBKDF2 不一致 iter=%d\n", iter); fail++; }
  }
  // 4. 长密码（超过 64 字节，走 key 先 sha256 的分支）
  {
    std::string pwd(200, 'x');
    unsigned char salt[8] = {1,2,3,4,5,6,7,8};
    unsigned char a[32], b[32];
    crypto::pbkdf2_sha256(pwd, salt, 8, 10, a, 32);
    PKCS5_PBKDF2_HMAC(pwd.data(), (int)pwd.size(), salt, 8, 10, EVP_sha256(), 32, b);
    if (hex(a, 32) != hex(b, 32)) { printf("长密码 PBKDF2 不一致\n"); fail++; }
  }
  // 5. 随机数
  {
    unsigned char r1[32], r2[32];
    if (!crypto::random_bytes(r1, 32) || !crypto::random_bytes(r2, 32)) { printf("随机数失败\n"); fail++; }
    else if (memcmp(r1, r2, 32) == 0) { printf("随机数重复\n"); fail++; }
  }
  printf(fail == 0 ? "内置 crypto 与 OpenSSL 完全一致\n" : "%d 项不一致\n", fail);
  return fail == 0 ? 0 : 1;
}
