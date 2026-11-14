#pragma once
// 边缘通过控制流推送的 ingress 配置解析（纯函数，便于离线测试）。
//
// 命名隧道唯一的"我知道自己的公网域名"来源就是这里：连接令牌（base64 的
// {"a","t","s"}）只有账号、隧道 id 和密钥，没有域名；能回答域名的 REST API
// 需要额外的 account token，我们不该向用户索取。控制流免费把它送过来。
//
// 结构形如：
//   {"version":2,"config":{"ingress":[
//       {"hostname":"xxx.example.com","service":"http://localhost:8080"},
//       {"service":"http_status:404"}],
//     "warp-routing":{"enabled":false}}}
#include <string>
#include <vector>

namespace ct::ingress {

// ingress 规则里的公网 hostname，按边缘给出的顺序。保留通配（"*.x.com"）。
std::vector<std::string> hostnames(const std::string& body);

// 配置版本号（边缘用它排序）
int version(const std::string& body);

// 第一个可直接用作订阅域名的条目：通配条目描述的是规则，不是能拨的地址。
std::string first_usable(const std::vector<std::string>& hosts);

// 回给边缘的确认体
std::string update_ack(int version);

}  // namespace ct::ingress
