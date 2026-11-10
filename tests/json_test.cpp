#include <cstdio>
#include <string>
#include "../src/json.h"

int main() {
  jsonx::Json list = jsonx::Json::array();
  list.push_back({{"urls", "stun:stun.cloudflare.com:3478"}});
  std::printf("arr=%s\n", jsonx::dump(list).c_str());
  jsonx::Json ice;
  ice["iceServers"] = list;
  std::printf("ice=%s\n", jsonx::dump(ice).c_str());
  jsonx::Json back;
  if (!jsonx::parse(jsonx::dump(ice), back)) { std::printf("parse 失败\n"); return 1; }
  std::printf("roundtrip=%s\n", jsonx::dump(back).c_str());
  return 0;
}
