#include "ui.h"

// 为什么整段资源内嵌、而不是从 public/ 目录读文件：
//   现场经常只拷一个可执行文件过去（没有源码树、也没有 public/），
//   "管理面板打不开"这种故障的排查成本，远高于多出来的几十 KB 代码段。
//   要改外观又不想重编译，仍可走 register_routes 的 public_dir 分支。
//
// 三份资源分三个函数、三个原始字符串，而不是塞进一个巨大的常量：
//   routes 需要给它们不同的 Content-Type，改 CSS 时也不必在 JS 的大段文本里翻。
// 返回值是函数内 static（C++11 起首次调用的初始化是线程安全的），
// 拿到的是引用，之后每次请求零拷贝；引用在进程生命周期内一直有效。

namespace panel {

const std::string& panel_html() {
  static const std::string html = R"PANEL(<!doctype html>
<html lang="zh-CN" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#0b1220">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex,nofollow">
<title>管理面板 · 局域网对讲机</title>
<link rel="icon" href="data:,">
<link rel="stylesheet" href="/admin/assets/panel.css">
</head>
<body>

<section id="view-login" class="view">
  <div class="login-wrap">
    <div class="card login-card">
      <h1 class="brand">管理面板</h1>
      <p class="muted small">局域网对讲机 · 仅限管理员</p>
      <form id="login-form" autocomplete="off">
        <label class="field">
          <span class="field-label">账号</span>
          <input id="in-user" class="input mono" type="text" value="admin" readonly>
        </label>
        <label class="field">
          <span class="field-label">密码</span>
          <input id="in-pass" class="input" type="password" placeholder="输入 admin 的密码，回车即登录" autocomplete="current-password" spellcheck="false">
        </label>
        <p id="login-err" class="err" hidden></p>
        <button id="btn-login" class="btn primary block" type="submit">登录</button>
      </form>
      <p class="muted small note">账号固定为 admin：它是面板的保底入口，不能改名也不能删除。首次启动生成的随机密码只打印在服务端控制台一次。</p>
    </div>
  </div>
</section>

<section id="view-main" class="view hidden">
  <header class="topbar">
    <div class="topbar-title">管理面板 <span id="top-host" class="muted small mono"></span></div>
    <div class="topbar-actions">
      <button id="btn-theme" class="btn ghost small" type="button">浅色</button>
      <button id="btn-logout" class="btn ghost small" type="button">退出</button>
    </div>
  </header>

  <nav id="tabs" class="tabs">
    <button class="tab active" data-tab="overview" type="button">运行概况</button>
    <button class="tab" data-tab="instances" type="button">实例</button>
    <button class="tab" data-tab="users" type="button">账号</button>
    <button class="tab" data-tab="turn" type="button">中继</button>
    <button class="tab" data-tab="logs" type="button">日志</button>
  </nav>

  <main class="content">
    <section id="tab-overview" class="tab-panel">
      <div class="tiles" id="tiles"></div>
      <div class="card">
        <div class="card-head">
          <h2>运行信息</h2>
          <button class="btn ghost small" data-refresh="overview" type="button">刷新</button>
        </div>
        <dl class="kv" id="kv-info"></dl>
      </div>
      <div class="card">
        <div class="card-head">
          <h2>隧道</h2>
          <button class="btn ghost small" data-refresh="overview" type="button">刷新</button>
        </div>
        <dl class="kv" id="kv-tunnel"></dl>
      </div>
    </section>

    <section id="tab-instances" class="tab-panel hidden">
      <div class="card">
        <div class="card-head">
          <h2>本机实例</h2>
          <button class="btn ghost small" data-refresh="instances" type="button">刷新</button>
        </div>
        <p class="muted small note">重启会让该实例上正在进行的通话中断；重启当前实例时本页面会短暂失联，稍后刷新即可。</p>
        <div id="inst-list" class="inst-list"></div>
      </div>
    </section>

    <section id="tab-users" class="tab-panel hidden">
      <div class="card">
        <div class="card-head">
          <h2>账号</h2>
          <div class="head-actions">
            <button id="btn-user-add" class="btn small" type="button">新增账号</button>
            <button class="btn ghost small" data-refresh="users" type="button">刷新</button>
          </div>
        </div>
        <p class="muted small note">admin 是面板的保底账号：改名或删除会让运维再也进不来（服务仍在运行，没有别的入口）。因此 admin 那一行的改名、删除按钮是禁用的，只保留改密码。</p>
        <div class="table-wrap">
          <table class="table">
            <thead>
              <tr><th>用户名</th><th>展示名</th><th>创建时间</th><th>最后登录</th><th>角色</th><th>操作</th></tr>
            </thead>
            <tbody id="users-body"></tbody>
          </table>
        </div>
      </div>
    </section>

    <section id="tab-turn" class="tab-panel hidden">
      <div class="card">
        <div class="card-head">
          <h2>中继（TURN）</h2>
          <button class="btn ghost small" data-refresh="turn" type="button">刷新</button>
        </div>
        <p class="muted small note">
          两台手机各自在不同网络时，NAT 会让点对点直连失败，只有中继能通。
          这里填 Cloudflare Realtime 应用的 Key ID 与 API Token。
          <strong>Token 是长期密钥，保存后不再回显</strong>；留空表示沿用原值。
        </p>
        <dl class="kv" id="kv-turn"></dl>
        <div class="row-actions">
          <button class="btn" id="turn-save" type="button">设置 / 修改</button>
          <button class="btn ghost" id="turn-clear" type="button">清除（回到仅 STUN）</button>
        </div>
      </div>
    </section>

    <section id="tab-logs" class="tab-panel hidden">
      <div class="card">
        <div class="card-head">
          <h2>最近日志</h2>
          <div class="head-actions">
            <select id="log-lines" class="input small">
              <option value="100">100 行</option>
              <option value="200" selected>200 行</option>
              <option value="500">500 行</option>
            </select>
            <button class="btn ghost small" data-refresh="logs" type="button">刷新</button>
          </div>
        </div>
        <pre id="log-box" class="log">（尚未加载）</pre>
      </div>
    </section>
  </main>
</section>

<div id="toast" class="toast hidden"></div>

<div id="dlg-mask" class="dlg-mask hidden">
  <div class="dlg" role="dialog" aria-modal="true" aria-labelledby="dlg-title">
    <h3 id="dlg-title" class="dlg-title"></h3>
    <div id="dlg-body"></div>
    <p id="dlg-err" class="err" hidden></p>
    <div class="dlg-actions">
      <button id="dlg-cancel" class="btn ghost" type="button">取消</button>
      <button id="dlg-ok" class="btn primary" type="button">确定</button>
    </div>
  </div>
</div>

<script src="/admin/assets/panel.js"></script>
</body>
</html>
)PANEL";
  return html;
}

const std::string& panel_css() {
  static const std::string css = R"PANEL(/* 深色是默认主题；浅色只覆盖变量，避免两套规则各写一遍（改一处样式两边同时生效）。 */
:root{
  --sans:-apple-system,"Noto Sans SC","PingFang SC","Microsoft YaHei",system-ui,sans-serif;
  --mono:ui-monospace,"SFMono-Regular",Menlo,Consolas,"Liberation Mono",monospace;
  --radius:12px;
  --accent:#3b82f6; --accent-fg:#ffffff;
  --danger:#ef4444; --warn:#f59e0b; --okc:#22c55e;
  --bg:#0b1220; --bg2:#111a2c; --card:#141d30; --line:#1f2b42;
  --fg:#e8eefc; --dim:#8ea0c0; --input:#0d1626;
  --mask:rgba(4,8,16,.62); --shadow:0 10px 30px rgba(0,0,0,.35);
  --ok-bg:#123322; --ok-fg:#86efac; --bad-bg:#3b1515; --bad-fg:#fca5a5; --warn-bg:#3a2a0d; --warn-fg:#fcd34d;
}
:root[data-theme="light"]{
  --accent:#2563eb;
  --danger:#dc2626; --warn:#d97706; --okc:#16a34a;
  --bg:#f5f7fb; --bg2:#ffffff; --card:#ffffff; --line:#dbe3f0;
  --fg:#0f172a; --dim:#5a6a84; --input:#f1f5fb;
  --mask:rgba(15,23,42,.35); --shadow:0 10px 26px rgba(15,23,42,.10);
  --ok-bg:#dcfce7; --ok-fg:#166534; --bad-bg:#fee2e2; --bad-fg:#991b1b; --warn-bg:#fef3c7; --warn-fg:#92400e;
}
html{color-scheme:dark}
html[data-theme="light"]{color-scheme:light}
*{box-sizing:border-box}
body{margin:0;min-height:100dvh;background:var(--bg);color:var(--fg);
  font:15px/1.55 var(--sans);-webkit-text-size-adjust:100%}
.hidden{display:none !important}
.mono{font-family:var(--mono);font-variant-numeric:tabular-nums}
.small{font-size:12px}
.muted{color:var(--dim)}
.err{margin:0 0 10px;color:var(--danger);font-size:13px}
.note{margin:0 0 12px;line-height:1.6}
.empty{margin:4px 0;color:var(--dim);font-size:13px}

/* 登录 */
.view{min-height:100dvh}
.login-wrap{min-height:100dvh;display:flex;align-items:center;justify-content:center;padding:24px}
.login-card{width:100%;max-width:380px}
.brand{margin:0 0 4px;font-size:22px;font-weight:600;letter-spacing:1px}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);padding:16px;box-shadow:var(--shadow)}
.card-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:10px;flex-wrap:wrap}
.card-head h2{margin:0;font-size:14px;font-weight:600}
.head-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap}

/* 表单：登录框与弹窗共用一套样式 */
.field{display:block;margin-bottom:12px}
.field-label{display:block;margin-bottom:6px;font-size:12px;color:var(--dim)}
.input{width:100%;padding:11px 12px;border:1px solid var(--line);border-radius:10px;
  background:var(--input);color:var(--fg);font:inherit;outline:none}
.input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(59,130,246,.18)}
.input[readonly]{color:var(--dim);cursor:default}
/* 卡片头部的小控件不该像表单一样撑满整行 */
.input.small{width:auto;max-width:150px;padding:6px 10px;font-size:12px}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;
  padding:8px 14px;min-height:34px;border:1px solid var(--line);border-radius:10px;
  background:var(--bg2);color:var(--fg);font:inherit;font-size:13px;cursor:pointer}
.btn:hover{border-color:var(--accent)}
.btn:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
.btn:disabled{opacity:.4;cursor:not-allowed;border-color:var(--line)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-fg)}
.btn.ghost{background:transparent}
.btn.danger{color:var(--danger);border-color:rgba(239,68,68,.45)}
.btn.small{padding:5px 10px;min-height:28px;font-size:12px}
.btn.block{width:100%;padding:11px;margin-top:4px;font-size:15px}

/* 主界面 */
.topbar{display:flex;align-items:center;justify-content:space-between;gap:12px;
  padding:14px 16px;border-bottom:1px solid var(--line);background:var(--bg2);
  position:sticky;top:0;z-index:5}
.topbar-title{display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-size:16px;font-weight:600}
.topbar-actions{display:flex;gap:8px}
.tabs{display:flex;gap:8px;padding:12px 16px 0;overflow-x:auto}
.tab{flex:0 0 auto;padding:7px 14px;border:1px solid var(--line);border-radius:999px;
  background:var(--bg2);color:var(--dim);font:inherit;font-size:13px;cursor:pointer;white-space:nowrap}
.tab.active{background:var(--accent);border-color:var(--accent);color:var(--accent-fg)}
.content{display:flex;flex-direction:column;gap:14px;max-width:1100px;margin:0 auto;
  padding:14px 16px 40px}
.tab-panel{display:flex;flex-direction:column;gap:14px}

/* 数字卡片：数字用等宽字体，位数对齐后一眼能比大小 */
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);padding:12px 14px}
.tile-label{color:var(--dim);font-size:12px;margin-bottom:6px}
.tile-value{font-family:var(--mono);font-variant-numeric:tabular-nums;font-size:20px;font-weight:600;
  word-break:break-all;line-height:1.3}
.tile-value .unit{font-family:var(--sans);font-size:12px;font-weight:400;color:var(--dim);margin-left:3px}

/* 键值表 */
.kv{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:7px 16px;margin:0;font-size:13px}
.kv dt{color:var(--dim);white-space:nowrap}
.kv dd{margin:0;word-break:break-all}
.kv dd.mono{font-family:var(--mono)}

/* 账号表 */
.table-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch}
.table{width:100%;border-collapse:collapse;font-size:13px}
.table th{text-align:left;padding:8px 10px;font-weight:500;color:var(--dim);
  border-bottom:1px solid var(--line);white-space:nowrap}
.table td{padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:middle}
.table tbody tr:last-child td{border-bottom:none}
.table tr.row-admin td{background:rgba(59,130,246,.07)}
.ops{display:flex;flex-wrap:wrap;gap:6px}
.ops .btn{flex:0 0 auto;white-space:nowrap}
/* 时间列保持单行：宁可让表格横向滚动，也别把一行账号撑成三行高 */
.table .mono{white-space:nowrap}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;
  border:1px solid transparent;white-space:nowrap}
.badge.ok{background:var(--ok-bg);color:var(--ok-fg)}
.badge.bad{background:var(--bad-bg);color:var(--bad-fg)}
.badge.warn{background:var(--warn-bg);color:var(--warn-fg)}
.badge.plain{border-color:var(--line);color:var(--dim)}

/* 实例 */
.inst-list{display:flex;flex-direction:column;gap:10px}
.inst{border:1px solid var(--line);border-radius:10px;padding:10px 12px;background:var(--bg2)}
.inst-head{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:8px}
.inst-head .pid{font-family:var(--mono);font-size:13px}
.inst-head .spacer{flex:1 1 auto}
.inst .kv{font-size:12px}

/* 日志 */
.log{margin:0;max-height:60vh;overflow:auto;padding:12px;border:1px solid var(--line);
  border-radius:10px;background:var(--input);color:var(--fg);
  font-family:var(--mono);font-size:12.5px;line-height:1.5;
  white-space:pre-wrap;word-break:break-all}

/* 轻提示 */
.toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%);z-index:30;
  max-width:min(92vw,560px);padding:10px 16px;border-radius:10px;
  background:var(--bg2);border:1px solid var(--line);box-shadow:var(--shadow);font-size:13px}
.toast.good{border-color:rgba(34,197,94,.55);background:var(--ok-bg);color:var(--ok-fg)}
.toast.bad{border-color:rgba(239,68,68,.6);background:var(--bad-bg);color:var(--bad-fg)}

/* 弹窗 */
.dlg-mask{position:fixed;inset:0;z-index:40;display:flex;align-items:center;justify-content:center;
  padding:18px;background:var(--mask)}
.dlg{width:100%;max-width:400px;padding:16px;background:var(--card);
  border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow)}
.dlg-title{margin:0 0 12px;font-size:15px;font-weight:600}
.dlg-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:14px}

/* 手机上单列：卡片与键值都竖排，表格横向滚动，弹窗贴底 */
@media (max-width:480px){
  .content{padding:12px 12px 32px}
  .tiles{grid-template-columns:1fr}
  .kv{grid-template-columns:1fr;gap:2px}
  .kv dt{padding-top:6px}
  .topbar{padding:12px}
  .tabs{padding:10px 12px 0}
  /* 窄屏上把账号表拆成一列一列的卡片：六列横向滚动在手机上是没法用的 */
  .table{font-size:12px}
  .table thead{display:none}
  .table,.table tbody{display:block}
  .table tr{display:block;margin-bottom:10px;padding:6px 10px;
    border:1px solid var(--line);border-radius:10px;background:var(--bg2)}
  .table td{display:flex;align-items:baseline;justify-content:space-between;gap:12px;
    padding:4px 0;border-bottom:none}
  .table td::before{content:attr(data-label);flex:0 0 auto;color:var(--dim);font-size:12px}
  .table td .ops{justify-content:flex-end}
  .table tr.row-admin{border-color:rgba(59,130,246,.55)}
  .btn.small{min-height:32px}
  .dlg-mask{align-items:flex-end;padding:0}
  .dlg{max-width:none;border-radius:14px 14px 0 0}
  .log{max-height:55vh}
}
)PANEL";
  return css;
}

const std::string& panel_js() {
  static const std::string js = R"PANEL(/* 管理面板前端：原生 fetch + DOM，无框架、无外部请求（断网也能用）。
   所有写操作都带 X-CSRF-Token；401 统一回登录页，避免半登录状态下的静默失败。 */
(function () {
'use strict';

var CSRF = '';
var STATE = { tab: 'overview', timer: null };

function $(id) { return document.getElementById(id); }
function has(v) { return v !== undefined && v !== null && v !== ''; }
function txt(v, fb) { return has(v) ? String(v) : (fb === undefined ? '—' : fb); }
function num(v) { var n = Number(v); return isFinite(n) ? n : null; }
function el(tag, cls, text) {
  var e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = String(text);
  return e;
}
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); return node; }
function pad2(n) { return (n < 10 ? '0' : '') + n; }
function fmtInt(v) {
  var n = num(v);
  if (n === null) return txt(v);
  return String(Math.round(n)).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}
/* 接口里的时间可能是秒也可能是毫秒：按量级判断，调用方不必各自转换 */
function fmtTime(v) {
  var n = num(v);
  if (n === null || n <= 0) return '—';
  if (n < 1e11) n = n * 1000;
  var d = new Date(n);
  if (isNaN(d.getTime())) return txt(v);
  return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()) + ' ' +
         pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
}
function fmtDuration(v) {
  var sec = num(v);
  if (sec === null) return txt(v);
  sec = Math.max(0, Math.floor(sec));
  var d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600),
      m = Math.floor((sec % 3600) / 60), s = sec % 60;
  if (d > 0) return d + ' 天 ' + pad2(h) + ':' + pad2(m) + ':' + pad2(s);
  if (h > 0) return pad2(h) + ':' + pad2(m) + ':' + pad2(s);
  return m + ' 分 ' + pad2(s) + ' 秒';
}
/* 兼容扁平的 info 与 {info:{...}} 两种形态：接口还在成形期，前端不跟着来回改 */
function fieldOf(d, keys) {
  var src = [d, d.info, d.stats, d.host, d.server, d.storage];
  for (var i = 0; i < src.length; i++) {
    var o = src[i];
    if (!o || typeof o !== 'object') continue;
    for (var k = 0; k < keys.length; k++) {
      if (has(o[keys[k]])) return o[keys[k]];
    }
  }
  return undefined;
}
function failMsg(e) { return (e && e.message) ? e.message : '请求失败'; }

var toastTimer = null;
function toast(msg, kind) {
  var t = $('toast');
  if (!t) return;
  t.className = 'toast' + (kind ? ' ' + kind : '');
  t.textContent = msg;
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(function () { t.className = 'toast hidden'; }, 2800);
}
function setErr(node, msg) { if (!node) return; node.textContent = msg || ''; node.hidden = !msg; }

/* 统一入口：JSON 解析失败时退回文本，401 有专门分支，错误信息一律取服务端的 error 字段 */
function api(path, opts) {
  opts = opts || {};
  var init = { method: opts.method || 'GET', credentials: 'same-origin', cache: 'no-store', headers: {} };
  if (CSRF) init.headers['X-CSRF-Token'] = CSRF;
  if (init.method !== 'GET') {
    init.headers['Content-Type'] = 'application/json; charset=utf-8';
    if (opts.body !== undefined) init.body = JSON.stringify(opts.body);
  }
  return fetch(path, init).then(function (res) {
    return res.text().then(function (raw) {
      var data = {};
      if (raw) {
        try { data = JSON.parse(raw); } catch (e) { data = { ok: res.ok, raw: raw }; }
      }
      if (!data || typeof data !== 'object' || Array.isArray(data)) data = { ok: res.ok, value: data };
      if (res.status === 401) {
        if (!opts.public401) { toLogin(); throw new Error('登录状态已失效，请重新登录'); }
        data.ok = false;
      } else if (!res.ok) {
        data.ok = false;
      }
      data.__status = res.status;
      if (!data.ok && !has(data.error)) {
        data.error = (res.status === 401 || res.status === 403)
          ? '密码错误或无权访问'
          : (res.status === 429 ? '尝试次数过多，请稍后再试' : '请求失败（HTTP ' + res.status + '）');
      }
      return data;
    });
  });
}

/* ---------------- 主题 ---------------- */
function loadTheme() {
  try { return localStorage.getItem('panel-theme') || 'dark'; } catch (e) { return 'dark'; }
}
function applyTheme(t) {
  var light = (t === 'light');
  document.documentElement.setAttribute('data-theme', light ? 'light' : 'dark');
  var b = $('btn-theme');
  if (b) b.textContent = light ? '深色' : '浅色';
}

/* ---------------- 登录 / 退出 ---------------- */
function toLogin() {
  stopTimer();
  /* 令牌可能已经随着会话一起失效了：回登录页时重新取一份，
     否则重新登录这一下会因为缺 CSRF 头被直接拒掉 */
  CSRF = '';
  refreshToken();
  var main = $('view-main'), login = $('view-login');
  if (main) main.classList.add('hidden');
  if (login) login.classList.remove('hidden');
  setErr($('login-err'), '');
  var p = $('in-pass');
  if (p) { p.value = ''; setTimeout(function () { try { p.focus(); } catch (e) {} }, 30); }
}
function enterMain(info) {
  $('view-login').classList.add('hidden');
  $('view-main').classList.remove('hidden');
  applyTopHost(info);
  startTimer();
  switchTab('overview');
}
function refreshToken() {
  return api('/admin/api/status', { public401: true }).then(function (d) {
    if (has(d.csrf)) CSRF = String(d.csrf);
    return CSRF;
  }).catch(function () { return CSRF; });
}
function onLogin(ev) {
  if (ev) ev.preventDefault();
  var pw = ($('in-pass') || {}).value || '';
  if (!pw) { setErr($('login-err'), '请输入密码'); if ($('in-pass')) $('in-pass').focus(); return; }
  var btn = $('btn-login');
  setErr($('login-err'), '');
  if (btn) btn.disabled = true;
  /* 首次进页面若还没来得及拿到令牌，先补一次，登录请求才不会缺头 */
  var ready = CSRF ? Promise.resolve(CSRF) : refreshToken();
  ready.then(function () {
    return api('/admin/api/login', { method: 'POST', public401: true,
      body: { user: 'admin', pass: pw, password: pw } });
  })
    .then(function (d) {
      if (!d.ok) throw new Error(d.error || '登录失败');
      if (has(d.csrf)) CSRF = String(d.csrf);
      var p = $('in-pass'); if (p) p.value = '';
      return api('/admin/api/status').then(function (s) { enterMain(s); return null; });
    })
    .catch(function (e) { setErr($('login-err'), failMsg(e)); })
    .then(function () { if (btn) btn.disabled = false; });
}
function onLogout() {
  api('/admin/api/logout', { method: 'POST', body: {} }).then(toLogin, toLogin);
}

/* ---------------- 标签页 ---------------- */
function switchTab(name) {
  STATE.tab = name;
  var tabs = document.querySelectorAll('.tab');
  for (var i = 0; i < tabs.length; i++) {
    if (tabs[i].getAttribute('data-tab') === name) tabs[i].classList.add('active');
    else tabs[i].classList.remove('active');
  }
  var panels = document.querySelectorAll('.tab-panel');
  for (var j = 0; j < panels.length; j++) {
    if (panels[j].id === 'tab-' + name) panels[j].classList.remove('hidden');
    else panels[j].classList.add('hidden');
  }
  if (name === 'overview') loadStatus(false);
  else if (name === 'instances') loadInstances(false);
  else if (name === 'users') loadUsers(false);
  else if (name === 'turn') loadTurn();
  else if (name === 'logs') loadLogs(false);
}
function startTimer() {
  stopTimer();
  /* 概况页要跟着时间走；其余页面只在切换时拉，避免无谓的整表重绘 */
  STATE.timer = setInterval(function () {
    if ($('view-main').classList.contains('hidden')) return;
    if (STATE.tab === 'overview') loadStatus(true);
    else if (STATE.tab === 'instances') loadInstances(true);
    else if (STATE.tab === 'logs') loadLogs(true);
  }, 15000);
}
function stopTimer() { if (STATE.timer) { clearInterval(STATE.timer); STATE.timer = null; } }

/* ---------------- 概况 ---------------- */
function applyTopHost(d) {
  var host = fieldOf(d, ['bind', 'listen', 'addr', 'address', 'listen_addr']);
  var box = $('top-host');
  if (box) box.textContent = has(host) ? '· ' + host : '';
}
function addTile(box, label, value, unit) {
  var t = el('div', 'tile');
  t.appendChild(el('div', 'tile-label', label));
  var v = el('div', 'tile-value');
  v.appendChild(document.createTextNode(value));
  if (unit) v.appendChild(el('span', 'unit', unit));
  t.appendChild(v);
  box.appendChild(t);
}
function addKV(dl, k, v, mono) {
  dl.appendChild(el('dt', '', k));
  var dd = el('dd', mono ? 'mono' : '', v);
  dl.appendChild(dd);
  return dd;
}
function stateClass(s) {
  var v = String(s || '').toLowerCase();
  if (!v) return 'plain';
  if (/run|ok|在线|已连接|connected|alive|up|正常/.test(v)) return 'ok';
  if (/fail|error|失败|离线|退出|stop|down|dead|异常/.test(v)) return 'bad';
  if (/wait|pending|未|等待|connecting|启动/.test(v)) return 'warn';
  return 'plain';
}
function renderOverview(d) {
  var tiles = clear($('tiles'));
  addTile(tiles, '运行时长', fmtDuration(fieldOf(d, ['uptime', 'uptime_sec', 'uptime_seconds'])));
  addTile(tiles, '在线人数', fmtInt(fieldOf(d, ['online', 'online_users', 'users_online'])), '人');
  addTile(tiles, '房间数', fmtInt(fieldOf(d, ['rooms', 'room_count'])), '个');
  addTile(tiles, '消息', fmtInt(fieldOf(d, ['messages', 'message_count', 'msgs'])), '条');
  addTile(tiles, '媒体', fmtInt(fieldOf(d, ['media', 'media_count'])), '次');
  addTile(tiles, '信令', fmtInt(fieldOf(d, ['signals', 'signal_count'])), '条');

  var kv = clear($('kv-info'));
  addKV(kv, '服务名称', txt(fieldOf(d, ['name', 'title', 'product'])));
  addKV(kv, '监听地址', txt(fieldOf(d, ['bind', 'listen', 'addr', 'address', 'listen_addr'])), true);
  addKV(kv, '数据目录', txt(fieldOf(d, ['data_dir', 'datadir', 'dataDir', 'dir'])), true);
  addKV(kv, '进程 PID', txt(fieldOf(d, ['pid', 'process_id'])), true);
  var started = fieldOf(d, ['started_at', 'start_time', 'started']);
  addKV(kv, '启动时间', has(started) ? fmtTime(started) : '—', true);
  // 这里刻意不显示"版本"：本项目没有版本号概念（改版本号是刻意的禁区），
  // 摆一行"版本 —"只会让人以为版本信息读失败了。
}

function loadStatus(quiet) {
  return api('/admin/api/status').then(function (d) {
    if (has(d.csrf)) CSRF = String(d.csrf);
    applyTopHost(d);
    renderOverview(d);
    renderTunnel(d.tunnel || d);
    return d;
  }).catch(function (e) { if (!quiet) toast(failMsg(e), 'bad'); });
}
function renderTunnel(t) {
  t = (t && typeof t === 'object') ? t : {};
  var tv = clear($('kv-tunnel'));
  var dd = addKV(tv, '状态', '');
  var st = txt(t.state, '未知');
  dd.appendChild(el('span', 'badge ' + stateClass(st), st));
  addKV(tv, '公网地址', txt(t.url, '未分配'), true);
  addKV(tv, '来源', txt(t.source, '未配置'));
  if (has(t.configured)) addKV(tv, '已配置', t.configured ? '是' : '否');
}

/* ---------------- 实例 ---------------- */
function renderInstances(list) {
  var box = clear($('inst-list'));
  if (!list.length) {
    box.appendChild(el('p', 'empty', '没有读到实例列表（可能本机只有当前进程，且它还没写自述文件）。'));
    return;
  }
  list.forEach(function (it) {
    var item = el('div', 'inst');
    var head = el('div', 'inst-head');
    head.appendChild(el('span', 'pid', 'PID ' + txt(it.pid)));
    var st = txt(it.state !== undefined ? it.state : it.status, '未知');
    head.appendChild(el('span', 'badge ' + stateClass(st), st));
    head.appendChild(el('span', 'spacer'));
    var btn = el('button', 'btn small danger', '重启');
    btn.type = 'button';
    if (!has(it.pid)) btn.disabled = true;
    btn.addEventListener('click', function () { restartInstance(it); });
    head.appendChild(btn);
    item.appendChild(head);

    var kv = el('dl', 'kv');
    addKV(kv, '端口', txt(it.port !== undefined ? it.port : it.listen, '—'), true);
    addKV(kv, '公网地址', txt(it.url !== undefined ? it.url : (it.public_url !== undefined ? it.public_url : it.public), '无'), true);
    addKV(kv, '数据目录', txt(it.data_dir, '—'), true);
    var argv = it.argv !== undefined ? it.argv : (it.cmdline !== undefined ? it.cmdline : (it.command_line !== undefined ? it.command_line : it.cmd));
    var argvText = Array.isArray(argv) ? argv.join(' ') : txt(argv, '—');
    addKV(kv, '命令行', argvText, true);
    item.appendChild(kv);
    box.appendChild(item);
  });
}
function loadInstances(quiet) {
  return api('/admin/api/instances').then(function (d) {
    var list = Array.isArray(d.list) ? d.list : (Array.isArray(d.instances) ? d.instances : []);
    renderInstances(list);
    return list;
  }).catch(function (e) {
    if (!quiet) {
      var box = $('inst-list');
      if (box) { clear(box); box.appendChild(el('p', 'empty', '读取实例失败：' + failMsg(e))); }
      toast(failMsg(e), 'bad');
    }
  });
}
function restartInstance(it) {
  var pid = it.pid;
  openDialog({
    title: '重启实例',
    danger: true,
    okText: '重启',
    note: '将结束 PID ' + txt(pid) + ' 并重新拉起它。该实例上的通话会立即中断。',
    fields: [],
    onSubmit: function () {
      return api('/admin/api/restart', { method: 'POST', body: { pid: pid } })
        .then(function (d) { if (!d.ok) throw new Error(d.error || '重启失败'); return null; })
        .catch(function (e) { return '重启失败：' + failMsg(e); });
    },
    after: function () {
      toast('已请求重启 PID ' + txt(pid), 'good');
      setTimeout(function () { loadInstances(true); }, 1200);
    }
  });
}

/* ---------------- 账号 ---------------- */
function isAdmin(it) {
  return it.admin === true || it.admin === 1 || it.role === 'admin' ||
         String(it.user || '').toLowerCase() === 'admin';
}
function renderUsers(list) {
  var body = clear($('users-body'));
  if (!list.length) {
    var tr0 = el('tr');
    var td0 = el('td', 'empty', '账号库为空');
    td0.colSpan = 6;
    tr0.appendChild(td0);
    body.appendChild(tr0);
    return;
  }
  list.forEach(function (it) {
    var admin = isAdmin(it);
    var tr = el('tr', admin ? 'row-admin' : '');
    /* data-label 是给窄屏用的：手机上表格改成卡片布局，标签靠 CSS 的 ::before 取这个值 */
    var tdUser = el('td', 'mono', txt(it.user));
    tdUser.setAttribute('data-label', '用户名');
    tr.appendChild(tdUser);

    var tdD = el('td', '');
    tdD.setAttribute('data-label', '展示名');
    tdD.appendChild(document.createTextNode(has(it.display) ? String(it.display) : (admin ? 'admin' : '—')));
    if (admin) tdD.appendChild(el('span', 'muted small', ' （面板账号）'));
    tr.appendChild(tdD);

    var tdC = el('td', 'mono small', fmtTime(it.created_at));
    tdC.setAttribute('data-label', '创建时间');
    tr.appendChild(tdC);
    var tdL = el('td', 'mono small', fmtTime(it.last_login));
    tdL.setAttribute('data-label', '最后登录');
    tr.appendChild(tdL);
    var tdRole = el('td', '');
    tdRole.setAttribute('data-label', '角色');
    tdRole.appendChild(el('span', 'badge ' + (admin ? 'ok' : 'plain'), admin ? 'admin' : '普通'));
    tr.appendChild(tdRole);

    var ops = el('div', 'ops');
    var bPw = el('button', 'btn small', '改密');
    bPw.type = 'button';
    bPw.addEventListener('click', function () { changePasswd(it); });
    ops.appendChild(bPw);

    var bRename = el('button', 'btn small ghost', '改名');
    bRename.type = 'button';
    bRename.addEventListener('click', function () { renameUser(it); });
    var bDel = el('button', 'btn small danger', '删除');
    bDel.type = 'button';
    bDel.addEventListener('click', function () { delUser(it); });
    if (admin) {
      /* admin 是唯一的保底入口：界面上直接锁死改名/删除，而不是等后端拒绝再报错 */
      bRename.disabled = true;
      bDel.disabled = true;
      bRename.title = 'admin 是保底账号，不允许改名';
      bDel.title = 'admin 是保底账号，不允许删除';
    }
    ops.appendChild(bRename);
    ops.appendChild(bDel);
    var tdOps = el('td', '');
    tdOps.setAttribute('data-label', '操作');
    tdOps.appendChild(ops);
    tr.appendChild(tdOps);
    body.appendChild(tr);
  });
}
function loadUsers(quiet) {
  return api('/admin/api/users').then(function (d) {
    var list = Array.isArray(d.list) ? d.list : (Array.isArray(d.users) ? d.users : []);
    renderUsers(list);
    return list;
  }).catch(function (e) {
    if (!quiet) {
      var body = $('users-body');
      if (body) {
        clear(body);
        var tr = el('tr'), td = el('td', 'empty', '读取账号失败：' + failMsg(e));
        td.colSpan = 6;
        tr.appendChild(td);
        body.appendChild(tr);
      }
      toast(failMsg(e), 'bad');
    }
  });
}
function addUser() {
  openDialog({
    title: '新增账号',
    okText: '创建',
    fields: [
      { name: 'user', label: '用户名（英文 / 数字 / 符号，不含空格）', placeholder: '例如 zhangsan' },
      { name: 'display', label: '展示名（可留空，默认与用户名相同）' },
      { name: 'password', label: '初始密码', type: 'password', autocomplete: 'new-password' },
      { name: 'password2', label: '再输一次密码', type: 'password', autocomplete: 'new-password' }
    ],
    onSubmit: function (v) {
      var user = (v.user || '').trim();
      if (!user) return '请填写用户名';
      if (!/^[\x21-\x7E]+$/.test(user)) return '用户名只能使用英文、数字和常见符号，不能含空格或汉字';
      if (!v.password) return '请填写初始密码';
      if (v.password !== v.password2) return '两次输入的密码不一致';
      return api('/admin/api/users/add', { method: 'POST',
          body: { user: user, display: (v.display || '').trim() || user, password: v.password } })
        .then(function (d) { if (!d.ok) throw new Error(d.error || '创建失败'); return null; })
        .catch(function (e) { return failMsg(e); });
    },
    after: function () { toast('账号已创建', 'good'); loadUsers(true); }
  });
}
function changePasswd(it) {
  openDialog({
    title: '改密码 · ' + txt(it.user),
    okText: '保存',
    note: '改完立即生效，旧密码作罢；不会影响正在进行的通话。',
    fields: [
      { name: 'password', label: '新密码', type: 'password', autocomplete: 'new-password' },
      { name: 'password2', label: '再输一次', type: 'password', autocomplete: 'new-password' }
    ],
    onSubmit: function (v) {
      if (!v.password) return '新密码不能为空';
      if (v.password !== v.password2) return '两次输入的密码不一致';
      return api('/admin/api/users/passwd', { method: 'POST', body: { user: it.user, password: v.password } })
        .then(function (d) { if (!d.ok) throw new Error(d.error || '修改失败'); return null; })
        .catch(function (e) { return failMsg(e); });
    },
    after: function () { toast('密码已更新', 'good'); loadUsers(true); }
  });
}
function renameUser(it) {
  openDialog({
    title: '改名 · ' + txt(it.user),
    okText: '改名',
    fields: [
      { name: 'from', label: '当前用户名', value: it.user, readonly: true, mono: true },
      { name: 'to', label: '新用户名（英文 / 数字 / 符号）', placeholder: '例如 lisi' }
    ],
    onSubmit: function (v) {
      var to = (v.to || '').trim();
      if (!to) return '请填写新用户名';
      if (to.toLowerCase() === String(it.user).toLowerCase()) return '新旧用户名相同';
      if (!/^[\x21-\x7E]+$/.test(to)) return '用户名只能使用英文、数字和常见符号，不能含空格或汉字';
      return api('/admin/api/users/rename', { method: 'POST', body: { from: it.user, to: to } })
        .then(function (d) { if (!d.ok) throw new Error(d.error || '改名失败'); return null; })
        .catch(function (e) { return failMsg(e); });
    },
    after: function () { toast('已改名', 'good'); loadUsers(true); }
  });
}
function delUser(it) {
  openDialog({
    title: '删除账号',
    danger: true,
    okText: '删除',
    note: '删除后该账号立即无法登录，账号文件一并移除；历史通话记录不受影响。',
    fields: [
      { name: 'confirm', label: '输入用户名确认删除', placeholder: it.user, mono: true }
    ],
    onSubmit: function (v) {
      if ((v.confirm || '').trim() !== it.user) return '请输入完整用户名 ' + it.user + ' 以确认';
      return api('/admin/api/users/del', { method: 'POST', body: { user: it.user } })
        .then(function (d) { if (!d.ok) throw new Error(d.error || '删除失败'); return null; })
        .catch(function (e) { return failMsg(e); });
    },
    after: function () { toast('账号已删除', 'good'); loadUsers(true); }
  });
}

/* ---------------- 日志 ---------------- */
function lineText(x) {
  if (x === undefined || x === null) return '';
  if (typeof x === 'string') return x;
  if (typeof x === 'object') {
    var ts = x.ts !== undefined ? fmtTime(x.ts) : txt(x.time || x.t, '');
    var m = x.line || x.msg || x.text || x.message || '';
    return ts ? ts + '  ' + m : String(m);
  }
  return String(x);
}
/* ---------------- 中继（TURN） ---------------- */

function loadTurn() {
  return api('/admin/api/turn').then(function (d) {
    var kv = clear($('kv-turn'));
    var configured = d.configured === true;
    var working = d.working === true;
    addKV(kv, '状态', configured ? (working ? '已生效（下发给浏览器）' : '已配置，但换取凭证失败') : '未配置（只用 STUN）');
    addKV(kv, 'Key ID', d.key_id_masked ? String(d.key_id_masked) : '—', true);
    addKV(kv, 'API Token', d.api_token_set ? '已设置（不回显）' : '未设置');
    addKV(kv, '凭证有效期', (d.ttl || 0) + ' 秒');
    if (d.fetch_error) addKV(kv, '失败原因', String(d.fetch_error));
    if (d.error) addKV(kv, '配置错误', String(d.error));
    STATE.turn = d;   // 弹窗要用它显示"当前掩码 / 是否已设置"
    return d;
  }).catch(function (e) { toast(failMsg(e), 'bad'); });
}

function saveTurn() {
  var cur = STATE.turn || {};
  openDialog({
    title: '中继配置（Cloudflare TURN）',
    okText: '保存并验证',
    // 保存后会**当场换一次凭证**：填错了 Key ID 必须立刻能看出来，
    // 否则运维会以为配好了，实际跨网络依然打不通。
    note: 'Token 只写不回显。留空表示沿用当前值。保存后会自动验证一次凭证能否换取成功。',
    fields: [
      { name: 'key_id', label: 'Key ID', value: '', placeholder: cur.key_id_masked ? ('当前 ' + cur.key_id_masked + '（留空沿用）') : '例如 ab12cd34...' },
      { name: 'api_token', label: 'API Token', type: 'password', autocomplete: 'new-password', placeholder: cur.api_token_set ? '已设置（留空沿用）' : '粘贴 API Token' },
      { name: 'ttl', label: '凭证有效期（秒，600-86400）', value: String(cur.ttl || 86400) }
    ],
    onSubmit: function (v) {
      var ttl = parseInt(v.ttl, 10) || 86400;
      if (ttl < 600 || ttl > 86400) return '有效期要在 600 到 86400 秒之间';
      return api('/admin/api/turn', { method: 'POST',
          body: { key_id: (v.key_id || '').trim(), api_token: (v.api_token || '').trim(), ttl: ttl } })
        .then(function (d) { if (!d.ok) throw new Error(d.error || '保存失败'); return d; })
        .then(function (d) {
          // 服务端把"存进去了但换不到凭证"也当作成功返回（配置文件确实写了），
          // 所以这里要自己看 message 里有没有"失败"，否则会给出错误的成功提示。
          if (/失败/.test(d.message || '')) throw new Error(d.message);
          return null;
        })
        .catch(function (e) { return failMsg(e); });
    },
    after: function () { toast('中继配置已保存', 'good'); loadTurn(); }
  });
}

function clearTurn() {
  openDialog({
    title: '清除中继配置',
    okText: '清除',
    danger: true,
    note: '清除后只会下发 STUN。同一局域网仍可通话，跨网络大概率打不通。',
    onSubmit: function () {
      return api('/admin/api/turn', { method: 'DELETE' })
        .then(function (d) { if (!d.ok) throw new Error(d.error || '清除失败'); return null; })
        .catch(function (e) { return failMsg(e); });
    },
    after: function () { toast('已清除，回到仅 STUN', 'good'); loadTurn(); }
  });
}

function loadLogs(quiet) {
  var sel = $('log-lines');
  var n = sel && sel.value ? sel.value : '200';
  return api('/admin/api/logs?lines=' + encodeURIComponent(n)).then(function (d) {
    var raw = d.lines !== undefined ? d.lines
            : (d.list !== undefined ? d.list
            : (d.log !== undefined ? d.log
            : (d.text !== undefined ? d.text : d.raw)));
    var box = $('log-box');
    if (!box) return;
    if (typeof raw === 'string') {
      box.textContent = raw || '（日志为空）';
    } else if (Array.isArray(raw)) {
      var out = [];
      for (var i = 0; i < raw.length; i++) out.push(lineText(raw[i]));
      box.textContent = out.length ? out.join('\n') : '（日志为空）';
    } else {
      box.textContent = '（没有读到日志）';
    }
    box.scrollTop = box.scrollHeight;
  }).catch(function (e) {
    if (!quiet) {
      var box2 = $('log-box');
      if (box2) box2.textContent = '读取日志失败：' + failMsg(e);
      toast(failMsg(e), 'bad');
    }
  });
}

/* ---------------- 弹窗 ---------------- */
var DLG = { fields: [], onSubmit: null, after: null, open: false };
function openDialog(opt) {
  opt = opt || {};
  var body = clear($('dlg-body'));
  var nodes = [];
  (opt.fields || []).forEach(function (f) {
    var wrap = el('label', 'field');
    wrap.appendChild(el('span', 'field-label', f.label));
    var inp = el('input', 'input' + (f.mono ? ' mono' : ''));
    inp.type = f.type || 'text';
    inp.value = f.value === undefined ? '' : String(f.value);
    if (f.readonly) inp.readOnly = true;
    if (f.placeholder) inp.placeholder = f.placeholder;
    inp.autocomplete = f.autocomplete || 'off';
    inp.setAttribute('data-name', f.name);
    inp.addEventListener('keydown', function (ev) {
      if (ev.key === 'Enter') { ev.preventDefault(); dlgOk(); }
    });
    wrap.appendChild(inp);
    body.appendChild(wrap);
    nodes.push(inp);
  });
  if (opt.note) body.appendChild(el('p', 'muted small note', opt.note));
  $('dlg-title').textContent = opt.title || '';
  $('dlg-ok').textContent = opt.okText || '确定';
  $('dlg-ok').className = 'btn ' + (opt.danger ? 'danger' : 'primary');
  $('dlg-ok').disabled = false;
  setErr($('dlg-err'), '');
  DLG.fields = opt.fields || [];
  DLG.onSubmit = opt.onSubmit || null;
  DLG.after = opt.after || null;
  DLG.open = true;
  $('dlg-mask').classList.remove('hidden');
  var first = nodes.length ? nodes[0] : null;
  if (first && !first.readOnly) setTimeout(function () { try { first.focus(); } catch (e) {} }, 20);
}
function closeDialog(values, ok) {
  var mask = $('dlg-mask');
  if (mask) mask.classList.add('hidden');
  var after = DLG.after;
  DLG.fields = []; DLG.onSubmit = null; DLG.after = null; DLG.open = false;
  /* 只有真正提交成功才跑 after：取消/ESC 不该弹出"已删除"这种提示 */
  if (ok && typeof after === 'function') after(values);
}
function dlgOk() {
  if (!DLG.open) return;
  var btn = $('dlg-ok');
  if (btn && btn.disabled) return;
  var values = {};
  var nodes = $('dlg-body').querySelectorAll('input');
  for (var i = 0; i < DLG.fields.length && i < nodes.length; i++) {
    values[DLG.fields[i].name] = nodes[i].value;
  }
  if (!DLG.onSubmit) { closeDialog(values, true); return; }
  if (btn) btn.disabled = true;
  setErr($('dlg-err'), '');
  Promise.resolve(DLG.onSubmit(values)).then(function (err) {
    if (btn) btn.disabled = false;
    /* 校验失败返回字符串而不是抛异常：弹窗留着让用户改，不必重填整张表 */
    if (err) { setErr($('dlg-err'), err); return; }
    closeDialog(values, true);
  }).catch(function (e) {
    if (btn) btn.disabled = false;
    setErr($('dlg-err'), failMsg(e));
  });
}

/* ---------------- 启动 ---------------- */
function bindEvents() {
  var form = $('login-form');
  if (form) form.addEventListener('submit', onLogin);
  var theme = $('btn-theme');
  if (theme) theme.addEventListener('click', function () {
    var next = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
    applyTheme(next);
    try { localStorage.setItem('panel-theme', next); } catch (e) {}
  });
  var out = $('btn-logout');
  if (out) out.addEventListener('click', onLogout);
  var tabs = $('tabs');
  if (tabs) tabs.addEventListener('click', function (ev) {
    var b = ev.target.closest ? ev.target.closest('[data-tab]') : null;
    if (b) switchTab(b.getAttribute('data-tab'));
  });
  document.addEventListener('click', function (ev) {
    var r = ev.target.closest ? ev.target.closest('[data-refresh]') : null;
    if (!r) return;
    var what = r.getAttribute('data-refresh');
    if (what === 'overview') loadStatus(false);
    else if (what === 'instances') loadInstances(false);
    else if (what === 'users') loadUsers(false);
    else if (what === 'turn') loadTurn();
    else if (what === 'logs') loadLogs(false);
  });
  var add = $('btn-user-add');
  if (add) add.addEventListener('click', addUser);
  var turnSave = $('turn-save');
  if (turnSave) turnSave.addEventListener('click', saveTurn);
  var turnClear = $('turn-clear');
  if (turnClear) turnClear.addEventListener('click', clearTurn);
  var lines = $('log-lines');
  if (lines) lines.addEventListener('change', function () { loadLogs(false); });
  var cancel = $('dlg-cancel');
  if (cancel) cancel.addEventListener('click', function () { closeDialog(null, false); });
  var ok = $('dlg-ok');
  if (ok) ok.addEventListener('click', dlgOk);
  var mask = $('dlg-mask');
  if (mask) mask.addEventListener('click', function (ev) { if (ev.target === mask) closeDialog(null, false); });
  document.addEventListener('keydown', function (ev) {
    var m = $('dlg-mask');
    if (ev.key === 'Escape' && m && !m.classList.contains('hidden')) closeDialog(null, false);
  });
}
function boot() {
  applyTheme(loadTheme());
  bindEvents();
  /* 先问一次状态：已登录直接进主界面，未登录才显示登录页，省一次无谓的密码输入 */
  api('/admin/api/status', { public401: true }).then(function (d) {
    if (has(d.csrf)) CSRF = String(d.csrf);
    if (d.need_login === false || d.authed === true || d.logged_in === true) { enterMain(d); return; }
    toLogin();
  }).catch(function () { toLogin(); });
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
else boot();
})();
)PANEL";
  return js;
}

}  // namespace panel
