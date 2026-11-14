#pragma once
// Cap'n Proto RPC（level 0）最小实现，只服务 Cloudflare tunnel 的控制流。
//
// 字节流分帧：**不加任何长度前缀**，每条 capnp 消息靠自己开头的段表自描边界。
// （曾经错误地加过 4 字节长度前缀：本地两端都加时自测能过，但对真实边缘会把
//   前缀当成段表头，整条消息判为畸形并被静默丢弃。）
// rpc.capnp 的消息联合体判别值：abort=1 call=2 return=3 finish=4 bootstrap=8
//
// tunnelrpc.capnp 里我们只用 registrationServer 的三个方法
// （registerConnection=0 / unregisterConnection=1 / updateLocalConfiguration=2）。
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "capnp.h"

namespace ct::rpc {

enum Kind : std::uint16_t {
    kUnimplemented = 0,
    kAbort = 1,
    kCall = 2,
    kReturn = 3,
    kFinish = 4,
    kBootstrap = 8,
};

// tunnelrpc.capnp: RegistrationServer 的接口 id
inline constexpr std::uint64_t kRegistrationServerId = 0xf71695ec7fe85497ull;
inline constexpr std::uint16_t kMethodRegisterConnection = 0;
inline constexpr std::uint16_t kMethodUnregisterConnection = 1;
inline constexpr std::uint16_t kMethodUpdateLocalConfiguration = 2;

class Stream {
public:
    // Message{bootstrap}
    static std::vector<std::uint8_t> encode_bootstrap(std::uint32_t questionId);

    // Message{call}。params 必须在同一 message 内构造，内部指针才有效。
    using ParamsBuilder = std::function<capnp::StructBuilder(capnp::Message&)>;
    static std::vector<std::uint8_t> encode_call(std::uint32_t questionId,
                                                 std::uint32_t importId,
                                                 std::uint64_t interfaceId,
                                                 std::uint16_t methodId,
                                                 const ParamsBuilder& buildParams);

    // Message{finish}
    static std::vector<std::uint8_t> encode_finish(std::uint32_t questionId,
                                                   bool releaseResultCaps);

    // 读未分帧消息的 kind + question/answer id
    static bool peek(const std::uint8_t* msg, std::size_t len, std::uint16_t& kind,
                     std::uint32_t& id);

    // 分帧（当前实现是恒等：消息自带段表即可自描边界，见文件头说明）
    static std::vector<std::uint8_t> frame(const std::vector<std::uint8_t>& msg);
};

// Return 消息的结果结构定位：结构体内容偏移 + 字段宽度
bool return_payload(const std::uint8_t* msg, std::size_t len, std::size_t& structOff,
                    std::uint16_t& dataWords, std::uint16_t& ptrCount, std::string& error);

// Return 里第一个 senderHosted 的 CapDescriptor 的 ExportId（importedCap 要引用它）
bool return_cap_export_id(const std::uint8_t* msg, std::size_t len, std::uint32_t& exportId,
                          std::string& error);

}  // namespace ct::rpc
