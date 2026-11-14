#pragma once
// 面板前端资源：整段 HTML / CSS / JS 以 C++ 原始字符串内嵌进可执行文件。
//
// 为什么内嵌而不是只读 public/ 目录：
//   现场机器经常只拷一个可执行文件过去（没有源码树、也没有 public/），
//   "管理面板打不开"这类故障的排查成本，远高于多出来的几十 KB 代码段。
//   register_routes 的 public_dir 参数仍然保留，给想改外观又懒得重新编译的人。
//
// 返回值是函数内 static 的 const 引用：首次调用时构造一次，之后零成本，
// 引用在进程生命周期内一直有效，调用方可以直接 set_content，不需要拷贝。
//
// 三份资源彼此独立（HTML 用外部 <link>/<script> 引用，不含任何内联脚本），
// 这样宿主设的 CSP 只要允许 'self' 就够用，不必为面板开 inline 白名单。
#include <string>

namespace panel {

// 登录页 + 主界面的完整 HTML 外壳（内容由 panel.js 填充）。
const std::string& panel_html();
// 深色为主、浅色可切换的样式；移动端 <480px 退化为单列。
const std::string& panel_css();
// 原生 fetch + DOM 的前端逻辑：登录、概况、实例、账号、日志。
const std::string& panel_js();

}  // namespace panel
