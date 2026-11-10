#pragma once
// WebSocket 信令协议（客户端 <-> 服务端）
//
// 客户端 -> 服务端
//   {"t":"auth","user":"alice","pass":"..."}        登录
//   {"t":"auth","token":"..."}                      用会话 token 免密重连
//   {"t":"users"}                                   拉取在线用户
//   {"t":"call","to":"bob","media":"audio|video"}   发起 1:1 通话
//   {"t":"accept"}                                  接听来电
//   {"t":"reject"}                                  拒绝来电
//   {"t":"hangup"}                                  挂断 / 退出会话
//   {"t":"signal","data":{...}}                     WebRTC SDP / ICE，原样转发给对方
//   {"t":"chat","to":"bob","text":"...","ttl":0}    文字消息
//   {"t":"media","to":"bob","kind":"voice|video|file","name":"","mime":"",
//    "size":0,"duration":0,"data":"<base64>","caption":""}  语音/视频片段，仅转发
//   {"t":"typing","to":"bob","state":true}          正在输入
//   {"t":"ping"}                                    应用层心跳
//
// 服务端 -> 客户端
//   {"t":"hello","ip":"...","secure":true}          连接建立
//   {"t":"auth-ok","user":"alice","display":"爱丽丝","token":"..."}
//   {"t":"auth-fail","reason":"..."}
//   {"t":"users","list":[{"user":"bob","display":"鲍勃","busy":false}]}
//   {"t":"incoming","from":"bob","display":"鲍勃","media":"video"}   来电
//   {"t":"incoming-cancel","from":"bob"}            来电超时取消
//   {"t":"call-start","peer":"bob","display":"鲍勃","media":"video","initiator":true}
//   {"t":"call-end","reason":"hangup"}
//   {"t":"call-fail","reason":"对方正在通话中"}
//   {"t":"signal","from":"bob","display":"鲍勃","data":{...}}
//   {"t":"chat","from":"bob","display":"鲍勃","text":"...","ts":1700000000}
//   {"t":"media","from":"bob","display":"鲍勃","kind":"voice",...,"ts":...}
//   {"t":"typing","from":"bob","state":true}
//   {"t":"error","reason":"..."}
//   {"t":"pong","ts":...}
//
// 规则：同一账号重复登录会踢掉旧连接；来电 45 秒无人接听自动取消；
//       所有消息只在内存中转发，转发完成即释放，不写任何文件。

namespace proto {

constexpr int kMaxTextLength = 4000;                  // 单条文字上限
constexpr size_t kMaxMediaBytes = 12u * 1024 * 1024;  // 单条语音/视频上限（base64 解码后）
constexpr int kHeartbeatSeconds = 25;                 // WebSocket ping 间隔
constexpr int kCallTimeoutSeconds = 45;               // 来电振铃超时

}  // namespace proto
