#include "ingress.h"

#include <string>
#include <vector>

#include "../../src/json.h"

namespace ct::ingress {

// 边缘推来的 body 是 cloudflared 的 ConfigurationUpdateBody。这里全部用纯函数
// 实现：解析出错只可能来自"对面发了什么"，与网络时序无关，因此可以离线喂样本
// 验证，不需要一条活着的隧道。

std::vector<std::string> hostnames(const std::string& body) {
    std::vector<std::string> out;
    jsonx::Json doc;
    // jsonx::parse 失败只说明"这不是 JSON"，不是致命错误：边缘可能推一个我们
    // 还没见过的形态，此时当成"没有 hostname"比让调用方处理异常更简单。
    if (!jsonx::parse(body, doc) || !doc.is_object()) return out;

    auto config = doc.find("config");
    if (config == doc.end() || !config->is_object()) return out;

    auto rules = config->find("ingress");
    if (rules == config->end() || !rules->is_array()) return out;

    for (const auto& rule : *rules) {
        // 数组里混进非对象元素时跳过，而不是整体失败：一条规则写坏不该让
        // 其余仍然有效的域名全部丢掉。
        if (!rule.is_object()) continue;
        auto host = rule.find("hostname");
        if (host == rule.end() || !host->is_string()) continue;
        const std::string h = host->as_string();
        // 空 hostname 在 cloudflared 的语义里是"匹配所有主机名"的兜底规则，
        // 它不是一个可以拿去发布的地址。
        if (h.empty()) continue;
        out.push_back(h);
    }
    return out;
}

int version(const std::string& body) {
    jsonx::Json doc;
    if (!jsonx::parse(body, doc) || !doc.is_object()) return 0;
    auto it = doc.find("version");
    // 只有整数才算版本号：浮点/字符串说明对面换了协议，按 0（"未知版本"）
    // 处理，调用方据此不会把一次未知推送当成有效的版本推进。
    if (it == doc.end() || !it->is_number() || !it->is_integer()) return 0;
    return it->get<int>();
}

std::string first_usable(const std::vector<std::string>& hosts) {
    for (const auto& h : hosts) {
        if (h.empty()) continue;
        // 通配条目描述的是"这条规则匹配哪些名字"，客户端没法拨 "*.x.com"
        // 这样的地址。常见形态是 "*.x.com"，但 "a.*.b" 之类同样不可拨，所以统一
        // 按"含 '*' 就跳过"处理，而不是只认前缀 "*."。
        if (h.find('*') != std::string::npos) continue;
        return h;
    }
    return std::string();
}

std::string update_ack(int version) {
    // 用 jsonx 拼而不是手写字符串：版本号来自网络，将来要加字段时也不用再
    // 手工照顾转义。
    jsonx::Json ack;
    ack["lastAppliedVersion"] = version;
    return ack.dump();
}

}  // namespace ct::ingress
