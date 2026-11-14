#pragma once
// 面板 HTTP 路由表：路径常量与统一响应助手。
//
// 为什么把地址写成常量：面板页面（ui.cpp 里的 HTML/JS）、后端路由、以及将来
// 可能加的外部脚本，三方都必须引用同一批地址。地址散落成字符串字面量，
// 改一个漏一个是迟早的事，而且这种错在编译期完全看不出来。
#include <string>

#include "../json.h"

namespace panel {
namespace routes {

// ---- 页面 ------------------------------------------------------------------
inline constexpr const char *kPage = "/admin";
inline constexpr const char *kPageSlash = "/admin/";
inline constexpr const char *kCss = "/admin/assets/panel.css";
inline constexpr const char *kJs = "/admin/assets/panel.js";

// ---- 接口 ------------------------------------------------------------------
inline constexpr const char *kLogin = "/admin/api/login";
inline constexpr const char *kLogout = "/admin/api/logout";
inline constexpr const char *kStatus = "/admin/api/status";
inline constexpr const char *kInstances = "/admin/api/instances";
inline constexpr const char *kUsers = "/admin/api/users";
inline constexpr const char *kUserAdd = "/admin/api/users/add";
inline constexpr const char *kUserDel = "/admin/api/users/del";
inline constexpr const char *kUserRename = "/admin/api/users/rename";
inline constexpr const char *kUserPasswd = "/admin/api/users/passwd";
inline constexpr const char *kLogs = "/admin/api/logs";
inline constexpr const char *kRestart = "/admin/api/restart";

// 统一响应形状：成功 {"ok":true,...}，失败 {"ok":false,"error":"人话原因"}。
// 两个助手集中在一处，是为了避免每个路由自己拼字段 —— 把 "ok" 写成 "success"
// 或者把 "error" 写成 "msg"，前端只会静默当成成功，没有任何报错线索。
//
// ok_reply 会把 payload（若为对象）的字段原样并进结果里，"ok":true 最后写入，
// 这样调用方传进来的同名字段不可能把它改成 false。
//
// 参数按值传、不用 const 引用加默认形参：jsonx::Json 支持移动，传右值就少一次
// 对象内部的 vector 拷贝，而这两个函数每个请求路径上都要走一次。
jsonx::Json ok_reply(jsonx::Json payload = jsonx::Json());
jsonx::Json error_reply(const std::string &error);

}  // namespace routes
}  // namespace panel
