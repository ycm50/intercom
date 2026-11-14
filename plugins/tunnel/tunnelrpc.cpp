#include "tunnelrpc.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace ct::rpc {

namespace {

// ---- 段表 ------------------------------------------------------------------
// capnp 的每条消息自带段表：[段数-1][各段字宽…]，随后整体补到 8 字节，段体
// 紧跟其后。capnp::Reader 把这个头写死成 8 字节（也就是单段），所以段表
// 合法性必须在这里自己看一遍。
constexpr std::size_t kHeaderBytes = 8;

std::uint32_t load_u32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}

// 校验段表，产出"段体字节数"。只接受单段：多段消息的段表会长于 8 字节，
// Reader 会整体错位，与其解出一组看起来正常其实错位的 id，不如直接判非法，
// 让上层按协议错误处理（控制流上的消息实际都是单段）。
bool body_of(const std::uint8_t* msg, std::size_t len, std::size_t& bodyBytes) {
    if (msg == nullptr || len < kHeaderBytes) return false;
    if (load_u32(msg) != 0u) return false;  // 段数 - 1，只支持 1 段
    const std::uint32_t words = load_u32(msg + 4);
    // 用减法比较，避免 words * 8 溢出后再越界判断失效。
    if (static_cast<std::size_t>(words) > (len - kHeaderBytes) / 8) return false;
    bodyBytes = static_cast<std::size_t>(words) * 8;
    return true;
}

// ---- 指针字 ----------------------------------------------------------------
// bit0..1 类型（0 = struct，1 = list），bit2..31 有符号偏移（单位是字，
// 基准是指针字的下一字节）。struct 的 bit32..47 是数据段字数、bit48..63 是
// 指针个数；list 的 bit32..34 是元素大小、bit35..63 是元素个数。
constexpr std::uint64_t kKindMask = 0x3u;
constexpr std::uint64_t kKindStruct = 0u;
constexpr std::uint64_t kKindList = 1u;
constexpr std::uint64_t kOffsetMask = 0x3FFFFFFFu;
constexpr std::uint64_t kOffsetSignBit = 1ull << 29;  // 30 位补码的符号位
constexpr std::uint64_t kListCountMask = 0x1FFFFFFFu;
constexpr std::uint64_t kElemComposite = 7u;  // 结构体列表：tag 字 + 定宽元素

// 30 位补码转有符号。手工拼符号位，避免依赖"无符号左移后转有符号"的实现定义行为。
std::int64_t offset_words(std::uint64_t p) {
    const std::uint64_t raw = (p >> 2) & kOffsetMask;
    std::int64_t v = static_cast<std::int64_t>(raw & (kOffsetSignBit - 1));
    if ((raw & kOffsetSignBit) != 0) v -= static_cast<std::int64_t>(kOffsetSignBit << 1);
    return v;
}

// 目标 = 指针字之后 + 偏移。limit 是段体大小，指针不许指到段外。
bool target_of(std::size_t slot, std::uint64_t p, std::size_t limit, std::size_t& target) {
    const std::int64_t t = static_cast<std::int64_t>(slot) + 8 + offset_words(p) * 8;
    if (t < 0 || static_cast<std::size_t>(t) > limit) return false;
    target = static_cast<std::size_t>(t);
    return true;
}

// 空指针槽（全 0 字）在 capnp 里等价于"默认值"，而 Reader 会把 0 当成
// 偏移 0 的结构指针解到下一个字上。所以每次跳转前先看原始字。
bool ptr_slot_empty(const capnp::Reader& rd, std::size_t slot) {
    std::uint64_t w = 0;
    return !rd.read_u64(slot, w) || w == 0;
}

// ---- 结构体列表（Return 的 capTable 就是它）--------------------------------
struct ListView {
    std::size_t dataOff = 0;  // 元素 0 的数据段起点
    std::size_t count = 0;
    std::uint16_t dataWords = 0;
    std::uint16_t ptrCount = 0;
};

// 复合列表：指针的 D 字段是"字宽（不含 tag 字）"，tag 字本身长得像 struct
// 指针，但它的偏移位存的是元素个数。这两处语义对调过，按 struct 指针读会把
// 元素个数当成目标偏移。
bool read_struct_list(const capnp::Reader& rd, std::size_t ptrSlot, ListView& out) {
    out = ListView{};
    std::uint64_t p = 0;
    if (!rd.read_u64(ptrSlot, p)) return false;
    if (p == 0) return true;  // null 指针 == 空列表
    if ((p & kKindMask) != kKindList) return false;

    const std::uint64_t elem = (p >> 32) & 0x7u;
    const std::size_t wordsInList = static_cast<std::size_t>((p >> 35) & kListCountMask);
    std::size_t target = 0;
    if (!target_of(ptrSlot, p, rd.size(), target)) return false;

    if (elem == kElemComposite) {
        std::uint64_t tag = 0;
        if (!rd.read_u64(target, tag)) return false;
        if ((tag & kKindMask) != kKindStruct) return false;
        const std::uint16_t dw = static_cast<std::uint16_t>((tag >> 32) & 0xFFFFu);
        const std::uint16_t pc = static_cast<std::uint16_t>((tag >> 48) & 0xFFFFu);
        const std::size_t elements = static_cast<std::size_t>((tag >> 2) & kOffsetMask);
        if (target + 8 > rd.size()) return false;
        const std::size_t start = target + 8;
        if (wordsInList > (rd.size() - start) / 8) return false;  // 声明的字宽越过段尾
        const std::size_t per = static_cast<std::size_t>(dw) + pc;
        // 元素个数 × 每元素字数 必须落在声明的字宽内，否则按元素跳过界。
        if (per != 0 && elements > wordsInList / per) return false;
        out.dataOff = start;
        out.count = elements;
        out.dataWords = dw;
        out.ptrCount = pc;
        return true;
    }

    // 其余元素大小（1/2/4/8 字节）或指针列表在规范里也能"当成"结构体列表读，
    // 但那种降级读法解不出 CapDescriptor 的数据字（判别字段和 exportId 都在
    // 数据段里），与其绕一圈还是找不到能力，不如明确报格式不符。
    return false;
}

bool element_data_off(const ListView& lv, std::size_t index, std::size_t& off) {
    if (index >= lv.count) return false;
    const std::size_t per = static_cast<std::size_t>(lv.dataWords) + lv.ptrCount;
    off = lv.dataOff + index * per * 8;
    return true;
}

// ---- Return 的三跳定位 -----------------------------------------------------
struct ReturnView {
    std::size_t payloadPtrsOff = 0;  // results Payload 的指针段起点（content=0、capTable=1）
    std::uint16_t payloadPtrCount = 0;
};

// Message → Return → results Payload，三跳定位。return_payload 和
// return_cap_export_id 都要走这三跳，抽出来避免两份偏移各自跑偏。
bool parse_return(const capnp::Reader& rd, ReturnView& out, std::string& error) {
    out = ReturnView{};
    if (ptr_slot_empty(rd, 0)) {
        error = "capnp 根指针为空";
        return false;
    }
    std::size_t rootOff = 0;
    std::uint16_t dw = 0;
    std::uint16_t pc = 0;
    if (!rd.root(rootOff, dw, pc)) {
        error = "capnp 根结构不合法";
        return false;
    }
    std::uint16_t kind = 0;
    if (!rd.read_u16(rootOff, kind)) {
        error = "Message 没有判别字段";
        return false;
    }
    if (kind != kReturn) {
        error = "不是 Return 消息（kind=" + std::to_string(kind) + "）";
        return false;
    }
    if (pc < 1) {
        error = "Message 没有联合体成员指针";
        return false;
    }
    const std::size_t memberSlot = rootOff + static_cast<std::size_t>(dw) * 8;
    if (ptr_slot_empty(rd, memberSlot)) {
        error = "Return 成员指针为空";
        return false;
    }
    std::size_t retOff = 0;
    std::uint16_t retDw = 0;
    std::uint16_t retPc = 0;
    std::size_t retPtrs = 0;
    if (!rd.read_struct_ptr(memberSlot, retOff, retDw, retPc, retPtrs)) {
        error = "Return 结构定位失败";
        return false;
    }
    if (retDw < 1) {
        error = "Return 结构没有数据段，读不出联合体判别字段";
        return false;
    }
    // Return 的联合体判别字段在字节 6（answerId 4 字节 + releaseParamCaps/
    // noFinishNeeded 两个 bool 挤在字节 4 上）。只有 results(0) 分支带 Payload，
    // exception / canceled / … 分支没有 capTable，跑下去只会读到别的结构的字节。
    std::uint16_t which = 0;
    if (!rd.read_u16(retOff + 6, which)) {
        error = "Return 没有联合体判别字段";
        return false;
    }
    if (which != 0) {
        error = "Return 不是 results 分支（which=" + std::to_string(which) + "）";
        return false;
    }
    if (retPc < 1) {
        error = "Return 没有结果 Payload 指针";
        return false;
    }
    if (ptr_slot_empty(rd, retPtrs)) {
        error = "Return 的 results 为空";
        return false;
    }
    // Payload 的数据段宽度是 0（只有 content 和 capTable 两个指针），这里要的
    // 只有它的指针段起点，数据段宽度单独占一个局部量，别让返回值顶着用。
    std::size_t payloadOff = 0;
    std::uint16_t payloadDw = 0;
    if (!rd.read_struct_ptr(retPtrs, payloadOff, payloadDw, out.payloadPtrCount,
                            out.payloadPtrsOff)) {
        error = "results Payload 定位失败";
        return false;
    }
    return true;
}

}  // namespace

// ---- 编码 ------------------------------------------------------------------

std::vector<std::uint8_t> Stream::frame(const std::vector<std::uint8_t>& msg) {
    // 【关键】capnp 的 RPC StreamTransport 在裸流上是把消息**原样连排**的：
    // 每条消息靠自己开头的段表自描边界（首字是"段数-1"，随后是各段字宽），
    // 根本没有长度前缀。
    //
    // 加上 4 字节长度前缀是个很容易犯的错：写端和读端若都加上，本地自测能通过，
    // 但对真实的边缘会把前缀当成段表头去解析，整条消息判为畸形并被静默丢弃 ——
    // 表现就是"注册永远超时，但连接看起来是通的"，非常难查。
    // 补一句对照：同样这套代码在真实边缘上验证过——加了前缀的版本注册永远超时，
    // 去掉前缀后立即注册成功。
    return msg;
}

std::vector<std::uint8_t> Stream::encode_bootstrap(std::uint32_t questionId) {
    capnp::Message m(256);
    // Message：数据段一个字（判别字段是其中的第 0 号 u16），指针段只放联合体成员。
    capnp::StructBuilder root = m.alloc_struct(1, 1);
    m.set_root(root);
    root.set_u16(0, kBootstrap);

    // Bootstrap { questionId @0 :UInt32; deprecatedObjectId @1 :AnyPointer }
    // deprecatedObjectId 是 schema 里必须存在的槽，留成 null（全 0）即表示没有。
    capnp::StructBuilder boot = m.alloc_struct(1, 1);
    boot.set_u32(0, questionId);
    root.set_struct(0, boot);

    return frame(m.finish());
}

std::vector<std::uint8_t> Stream::encode_call(std::uint32_t questionId, std::uint32_t importId,
                                              std::uint64_t interfaceId, std::uint16_t methodId,
                                              const ParamsBuilder& buildParams) {
    capnp::Message m(1024);
    capnp::StructBuilder root = m.alloc_struct(1, 1);
    m.set_root(root);
    root.set_u16(0, kCall);

    // Call 的数据段是 3 个字（24 字节）：
    //   字节 0..3  questionId
    //   字节 4..5  methodId
    //   字节 6..7  sendResultsTo 的判别字段（默认 caller=0，全 0 即"回给调用方"）
    //   字节 8..15 interfaceId
    // 指针段 3 个槽：target @0、params @1、其余留空。
    capnp::StructBuilder call = m.alloc_struct(3, 3);
    call.set_u32(0, questionId);
    call.set_u16(2, methodId);  // 字段下标按 2 字节计，2 == 字节 4
    call.set_u64(1, interfaceId);  // 字段下标按 8 字节计，1 == 字节 8
    root.set_struct(0, call);

    // MessageTarget { union { importedCap @0 :ImportId; promisedAnswer @1 } }
    //
    // 这里必须用 **promisedAnswer**，不是 importedCap —— 实测用 importedCap
    // 时边缘回的是 exception 分支（"registerConnection 被拒绝"），隧道永远
    // 注册不上。
    //
    // 原因：promisedAnswer 是对着**我们自己发出去的问题号**查（bootstrap 用的是
    // questionId 1），而 importedCap 是对着对端的 import 表查。后者在本连接上
    // 没有对应项，边缘只能报错。
    capnp::StructBuilder target = m.alloc_struct(1, 1);
    target.set_union_tag(32, 1);  // 判别字段在字节 4，按位寻址就是位 32；1 = promisedAnswer
    // PromisedAnswer { questionId @0 :QuestionId; transform @1 :List(Op) }
    // transform 留 null：capnp 把空指针当空列表，语义正好是"不做任何变换"。
    capnp::StructBuilder promised = m.alloc_struct(1, 1);
    promised.set_u32(0, importId);  // 现在这个参数表示 bootstrap 的 questionId
    target.set_struct(0, promised);
    call.set_struct(0, target);

    // Payload 只有指针段：content @0、capTable @1。参数里没有能力，capTable 留 null。
    capnp::StructBuilder payload = m.alloc_struct(0, 2);
    call.set_struct(1, payload);

    // params 必须建在同一个 Message 里：结构体指针是段内相对偏移，指向另一条
    // 消息的偏移在那条消息里毫无意义（读端不是崩溃就是读到别的东西）。
    capnp::StructBuilder params = buildParams(m);
    payload.set_struct(0, params);

    return frame(m.finish());
}

std::vector<std::uint8_t> Stream::encode_finish(std::uint32_t questionId,
                                                bool releaseResultCaps) {
    capnp::Message m(128);
    capnp::StructBuilder root = m.alloc_struct(1, 1);
    m.set_root(root);
    root.set_u16(0, kFinish);

    // Finish { questionId @0 :UInt32; releaseResultCaps @1 :Bool = true;
    //          requireEarlyCancellationWorkaround @2 :Bool = true }
    capnp::StructBuilder fin = m.alloc_struct(1, 0);
    fin.set_u32(0, questionId);
    // capnp 的标量存的是"与默认值异或"后的位。releaseResultCaps 的默认值是
    // true，所以线上位是 !v；照 v 直接写会得到相反语义（明确要求释放却写成
    // 不释放，或者反过来让边缘一直留着答案表项）。
    fin.set_bool(32, !releaseResultCaps);  // 字节 4 的 bit0，按位寻址是位 32
    root.set_struct(0, fin);

    return frame(m.finish());
}

// ---- 解码 ------------------------------------------------------------------

bool Stream::peek(const std::uint8_t* msg, std::size_t len, std::uint16_t& kind,
                  std::uint32_t& id) {
    kind = 0;
    id = 0;
    std::size_t bodyBytes = 0;
    if (!body_of(msg, len, bodyBytes)) return false;

    // 传给 Reader 的长度正好卡到段体，让它的越界检查按真实段宽生效。
    capnp::Reader rd(msg, kHeaderBytes + bodyBytes);
    if (ptr_slot_empty(rd, 0)) return false;  // 空根指针不是合法消息
    std::size_t rootOff = 0;
    std::uint16_t dw = 0;
    std::uint16_t pc = 0;
    if (!rd.root(rootOff, dw, pc)) return false;
    if (!rd.read_u16(rootOff, kind)) return false;

    // id 只有四个分支有：bootstrap/call/finish 是 questionId，return 是
    // answerId，而且都落在成员结构的字节 0。abort 的首字段是 Exception、
    // unimplemented 是回显的 Message，都没有 id —— 与其读一个语义不同的字段，
    // 不如留 0 让调用方忽略。
    if (kind != kBootstrap && kind != kCall && kind != kFinish && kind != kReturn) return true;
    if (pc < 1) return true;
    const std::size_t memberSlot = rootOff + static_cast<std::size_t>(dw) * 8;
    if (ptr_slot_empty(rd, memberSlot)) return true;
    std::size_t memberOff = 0;
    if (!rd.read_struct_ptr(memberSlot, memberOff)) return true;
    std::uint32_t v = 0;
    if (rd.read_u32(memberOff, v)) id = v;
    return true;
}

bool return_payload(const std::uint8_t* msg, std::size_t len, std::size_t& structOff,
                    std::uint16_t& dataWords, std::uint16_t& ptrCount, std::string& error) {
    structOff = 0;
    dataWords = 0;
    ptrCount = 0;
    std::size_t bodyBytes = 0;
    if (!body_of(msg, len, bodyBytes)) {
        error = "capnp 段表不合法（只支持单段消息）";
        return false;
    }
    capnp::Reader rd(msg, kHeaderBytes + bodyBytes);

    ReturnView rv;
    if (!parse_return(rd, rv, error)) return false;
    if (rv.payloadPtrCount < 1) {
        error = "results Payload 没有 content 指针";
        return false;
    }
    if (ptr_slot_empty(rd, rv.payloadPtrsOff)) {
        error = "results.content 为空";
        return false;
    }
    std::size_t contentOff = 0;
    std::size_t contentPtrs = 0;  // content 自己的指针段起点，这里用不上，只占位
    if (!rd.read_struct_ptr(rv.payloadPtrsOff, contentOff, dataWords, ptrCount, contentPtrs)) {
        // bootstrap 的 results.content 直接就是能力指针，没有结构体可解；
        // 这种消息走这里属于正常协议形态，但本函数只要结构体。
        error = "results.content 不是结构体（bootstrap 返回的是能力指针）";
        return false;
    }
    structOff = contentOff;
    return true;
}

bool return_cap_export_id(const std::uint8_t* msg, std::size_t len, std::uint32_t& exportId,
                          std::string& error) {
    exportId = 0;
    std::size_t bodyBytes = 0;
    if (!body_of(msg, len, bodyBytes)) {
        error = "capnp 段表不合法（只支持单段消息）";
        return false;
    }
    capnp::Reader rd(msg, kHeaderBytes + bodyBytes);

    ReturnView rv;
    if (!parse_return(rd, rv, error)) return false;
    if (rv.payloadPtrCount < 2) {
        error = "results Payload 没有 capTable 指针";
        return false;
    }
    const std::size_t capSlot = rv.payloadPtrsOff + 8;  // 指针段里 capTable 是第 1 个
    if (ptr_slot_empty(rd, capSlot)) {
        error = "results.capTable 为空";
        return false;
    }
    ListView lv;
    if (!read_struct_list(rd, capSlot, lv)) {
        error = "results.capTable 不是结构体列表";
        return false;
    }
    for (std::size_t i = 0; i < lv.count; ++i) {
        std::size_t elemOff = 0;
        if (!element_data_off(lv, i, elemOff)) break;
        // 数据段不足一个字时读不出判别字段，也就不是能用的能力描述符（比如
        // 早先版本写端的空壳），跳过而不是按指针段去猜。
        if (lv.dataWords < 1) continue;
        std::uint16_t which = 0;
        if (!rd.read_u16(elemOff, which)) continue;
        // CapDescriptor 的联合体：none=0、senderHosted=1、senderPromise=2、
        // receiverHosted=3…。只有 senderHosted(1) 是"对端现在就持有的能力",
        // 它的 ExportId 才能拿来当 importedCap。
        if (which != 1) continue;
        std::uint32_t v = 0;
        if (!rd.read_u32(elemOff + 4, v)) continue;  // exportedCap 在数据字 0 的后半
        exportId = v;
        return true;
    }
    error = "capTable 里没有 senderHosted 能力";
    return false;
}

}  // namespace ct::rpc
