#include "turn.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#include "../third_party/httplib.h"
#include "json.h"
#include "util.h"

#if defined(INTERCOM_WITH_OPENSSL)
#include <openssl/err.h>
#include <openssl/ssl.h>
#if defined(_WIN32)
#include <windows.h>
#include <wincrypt.h>
#endif
#endif

namespace turn {

namespace {

// Cloudflare Realtime 的凭证端点。Key ID 与 API Token 来自控制台的 Realtime 应用。
constexpr const char* kEndpointHost = "rtc.live.cloudflare.com";
constexpr const char* kPathPrefix = "/v1/turn/keys/";

struct Cache {
    std::mutex mu;
    std::vector<IceServer> servers;
    std::int64_t expires_at = 0;   // Unix 秒；为 0 表示还没取过
    std::string last_error;
};
Cache& cache() {
    static Cache c;
    return c;
}

#if defined(INTERCOM_WITH_OPENSSL)
// 信任库：Linux 读系统 CA；Windows 的 OpenSSL 看不到系统存储，要手动导入。
// 这段和 plugins/tunnel/quick.cpp 里的做法一致 —— 两个模块各自独立编译，
// 不能互相引用（插件是独立动态库，主程序不该依赖它）。
bool install_trust(SSL_CTX* ctx) {
    bool ok = SSL_CTX_set_default_verify_paths(ctx) == 1;
#if defined(_WIN32)
    HCERTSTORE store = ::CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
                                       CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_READONLY_FLAG,
                                       "ROOT");
    if (store != nullptr) {
        X509_STORE* xs = SSL_CTX_get_cert_store(ctx);
        int added = 0;
        PCCERT_CONTEXT cur = nullptr;
        while ((cur = ::CertEnumCertificatesInStore(store, cur)) != nullptr) {
            const unsigned char* der = cur->pbCertEncoded;
            if (der == nullptr || cur->cbCertEncoded == 0) continue;
            X509* c = ::d2i_X509(nullptr, &der, static_cast<long>(cur->cbCertEncoded));
            if (c == nullptr) continue;
            if (X509_STORE_add_cert(xs, c) == 1) ++added;
            X509_free(c);
        }
        ::CertCloseStore(store, 0);
        ::ERR_clear_error();
        if (added > 0) ok = true;
    }
#endif
    return ok;
}
#endif

}  // namespace

bool load_config(const std::string& data_dir, Config& out, std::string& error) {
    out = Config{};
    error.clear();

    // 文件优先：运维改完不用重启（每次调用都会重新读，凭证本身有缓存）。
    std::string path = util::join_path(data_dir, "turn.json");
    std::string text;
    if (util::file_exists(path) && util::read_file(path, text)) {
        jsonx::Json doc;
        if (jsonx::parse(text, doc) && doc.is_object()) {
            out.key_id = jsonx::str(doc, "key_id");
            out.api_token = jsonx::str(doc, "api_token");
            const long long ttl = jsonx::num(doc, "ttl", 86400);
            // 太短会让浏览器频繁换凭证，太长没有意义（Cloudflare 也有上限）。
            if (ttl >= 600 && ttl <= 86400) out.ttl_seconds = static_cast<int>(ttl);
        } else {
            error = path + " 不是合法的 JSON";
        }
    }

    // 环境变量兜底：适合容器/临时试验，不必写文件。
    if (out.key_id.empty()) {
        const char* k = std::getenv("CLOUDFLARE_TURN_KEY_ID");
        if (k != nullptr) out.key_id = k;
    }
    if (out.api_token.empty()) {
        const char* t = std::getenv("CLOUDFLARE_TURN_API_TOKEN");
        if (t != nullptr) out.api_token = t;
    }
    return !out.key_id.empty() && !out.api_token.empty();
}
bool fetch_credentials(const Config& cfg, std::vector<IceServer>& out, std::string& error) {
    error.clear();
    if (cfg.key_id.empty() || cfg.api_token.empty()) {
        error = "没有配置 TURN（缺 key_id 或 api_token）";
        return false;
    }

    {
        std::lock_guard<std::mutex> lk(cache().mu);
        const std::int64_t now = util::now_sec();
        // 留 5 分钟余量：浏览器拿到凭证后到真正建连还有一段时间，
        // 卡着过期时间发出去等于让最后几分钟的通话必然失败。
        if (!cache().servers.empty() && cache().expires_at - 300 > now) {
            out = cache().servers;
            return true;
        }
    }

    std::string body = "{\"ttl\":" + std::to_string(cfg.ttl_seconds) + "}";
    std::string path = std::string(kPathPrefix) + cfg.key_id + "/credentials/generate";

#if !defined(INTERCOM_WITH_OPENSSL)
    error = "本程序编译时没有 OpenSSL，无法向 Cloudflare 换取 TURN 凭证";
    return false;
#else
    ERR_clear_error();
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == nullptr) {
        error = "SSL_CTX_new 失败";
        return false;
    }
    struct CtxGuard {
        SSL_CTX* c;
        ~CtxGuard() { if (c) SSL_CTX_free(c); }
    } guard{ctx};

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    if (!install_trust(ctx)) {
        error = "加载系统 CA 信任库失败，无法校验 Cloudflare 的证书";
        return false;
    }

    httplib::Client cli(std::string("https://") + kEndpointHost + ":443");
    cli.set_connection_timeout(8, 0);
    cli.set_read_timeout(12, 0);
    cli.set_write_timeout(12, 0);
    httplib::Headers headers;
    headers.emplace("Authorization", "Bearer " + cfg.api_token);
    headers.emplace("Content-Type", "application/json");
    auto res = cli.Post(path.c_str(), headers, body, "application/json");
    if (!res) {
        error = "连接 Cloudflare 换取 TURN 凭证失败（网络不可达）";
        return false;
    }
    if (res->status != 200 && res->status != 201) {
        // 把服务端的话带出来：401 是 token 错，404 是 key_id 错，
        // 这两者在日志里必须能分清，否则运维只能靠猜。
        error = "Cloudflare 返回 " + std::to_string(res->status) + "：" + res->body.substr(0, 200);
        return false;
    }

    jsonx::Json doc;
    if (!jsonx::parse(res->body, doc) || !doc.is_object()) {
        error = "Cloudflare 的响应不是 JSON";
        return false;
    }

    // 响应形如：
    //   {"iceServers":{"urls":[...],"username":"...","credential":"..."}}
    // 注意它是**单个对象**而不是数组，这点容易写错。
    std::vector<IceServer> servers;
    auto it = doc.find("iceServers");
    if (it != doc.end() && it->is_object()) {
        IceServer s;
        auto u = it->find("urls");
        if (u != it->end() && u->is_array()) {
            for (std::size_t i = 0; i < u->size(); ++i) {
                // 数组元素只能按下标取，没有按 key 的访问器。
                const std::string one = (*u)[i].as_string();
                if (!one.empty()) s.urls.push_back(one);
            }
        }
        s.username = jsonx::str(*it, "username");
        s.credential = jsonx::str(*it, "credential");
        if (!s.urls.empty() && !s.username.empty() && !s.credential.empty()) {
            servers.push_back(std::move(s));
        }
    }
    if (servers.empty()) {
        error = "Cloudflare 的响应里没有可用的 iceServers";
        return false;
    }

    {
        std::lock_guard<std::mutex> lk(cache().mu);
        cache().servers = servers;
        cache().expires_at = util::now_sec() + cfg.ttl_seconds;
        cache().last_error.clear();
    }
    out = servers;
    return true;
#endif
}

std::string ice_servers_json(const std::vector<IceServer>& servers) {
    if (servers.empty()) return std::string("[]");
    jsonx::Json arr = jsonx::Json::array();
    for (const auto& s : servers) {
        jsonx::Json o;
        jsonx::Json urls = jsonx::Json::array();
        for (const auto& u : s.urls) urls.push_back(jsonx::Json(u));
        o["urls"] = urls;
        o["username"] = s.username;
        o["credential"] = s.credential;
        arr.push_back(o);
    }
    return jsonx::dump(arr);
}

/* -------------------------- 给管理面板用 -------------------------- */

namespace {

// 只留前几位：够运维确认填的是不是同一把，又不至于把密钥摊在页面上。
std::string mask(const std::string& s) {
    if (s.empty()) return std::string();
    if (s.size() <= 4) return std::string("****");
    return s.substr(0, 4) + "****";
}

std::string config_path(const std::string& data_dir) {
    return util::join_path(data_dir, "turn.json");
}

}  // namespace

void invalidate_cache() {
    std::lock_guard<std::mutex> lk(cache().mu);
    cache().servers.clear();
    cache().expires_at = 0;
    cache().last_error.clear();
}

std::string status_json(const std::string& data_dir) {
    Config cfg;
    std::string err;
    const bool configured = load_config(data_dir, cfg, err);
    const bool present = util::file_exists(config_path(data_dir));

    jsonx::Json j;
    j["configured"] = configured;
    j["file"] = present;
    j["key_id_masked"] = mask(cfg.key_id);
    j["api_token_set"] = !cfg.api_token.empty();
    j["ttl"] = cfg.ttl_seconds;
    if (!err.empty()) j["error"] = err;

    if (configured) {
        std::vector<IceServer> servers;
        std::string ferr;
        if (fetch_credentials(cfg, servers, ferr)) {
            j["working"] = true;
            j["server_count"] = static_cast<long long>(servers.size());
        } else {
            j["working"] = false;
            j["fetch_error"] = ferr;
        }
    } else {
        j["working"] = false;
    }
    return jsonx::dump(j);
}

bool save_config(const std::string& data_dir, const std::string& key_id,
                 const std::string& api_token, int ttl, std::string& error) {
    error.clear();

    // 空串表示这一项不改。先把现有值读出来，避免只改一项时把另一项清掉。
    Config cur;
    std::string ignored;
    load_config(data_dir, cur, ignored);

    std::string k = util::trim(key_id);
    std::string a = util::trim(api_token);
    if (k.empty()) k = cur.key_id;
    if (a.empty()) a = cur.api_token;
    if (k.empty() || a.empty()) {
        error = "Key ID 与 API Token 都必须提供（留空表示沿用原值）";
        return false;
    }
    if (ttl < 600 || ttl > 86400) ttl = 86400;

    jsonx::Json doc;
    doc["key_id"] = k;
    doc["api_token"] = a;
    doc["ttl"] = static_cast<long long>(ttl);

    std::string err;
    (void)util::make_dirs(data_dir, err);
    const std::string path = config_path(data_dir);
    if (!util::write_file_atomic(path, jsonx::dump(doc), error)) {
        if (error.empty()) error = "写入 " + path + " 失败";
        return false;
    }
    invalidate_cache();
    return true;
}

bool clear_config(const std::string& data_dir, std::string& error) {
    error.clear();
    const std::string path = config_path(data_dir);
    if (util::file_exists(path)) {
        if (!util::remove_file(path, error)) {
            if (error.empty()) error = "删除 " + path + " 失败";
            return false;
        }
    }
    invalidate_cache();
    return true;
}

}  // namespace turn