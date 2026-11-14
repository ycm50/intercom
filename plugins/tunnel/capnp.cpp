#include "capnp.h"

#include <cstring>

namespace ct::capnp {

namespace {

// ---- 小端读写 -------------------------------------------------------------
// capnp 线格式规定全部小端。这里不用 reinterpret_cast<std::uint64_t*>：
// 那样既依赖主机字节序，又会在未对齐地址上违反严格别名规则（UB）。
std::uint16_t load_le16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>(static_cast<std::uint16_t>(p[0]) |
                                      static_cast<std::uint16_t>(static_cast<std::uint16_t>(p[1]) << 8));
}

std::uint32_t load_le32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}

std::uint64_t load_le64(const std::uint8_t* p) {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < 8; ++i) v |= static_cast<std::uint64_t>(p[i]) << (i * 8);
    return v;
}

void store_le16(std::uint8_t* p, std::uint16_t v) {
    p[0] = static_cast<std::uint8_t>(v & 0xFFu);
    p[1] = static_cast<std::uint8_t>((v >> 8) & 0xFFu);
}

void store_le32(std::uint8_t* p, std::uint32_t v) {
    for (std::size_t i = 0; i < 4; ++i) p[i] = static_cast<std::uint8_t>((v >> (i * 8)) & 0xFFu);
}

void store_le64(std::uint8_t* p, std::uint64_t v) {
    for (std::size_t i = 0; i < 8; ++i) p[i] = static_cast<std::uint8_t>((v >> (i * 8)) & 0xFFu);
}

// 所有 arena 分配都按 8 字节对齐，段内偏移才是整字，指针偏移字段才能整除。
std::size_t align_up(std::size_t v, std::size_t a) { return a != 0 ? (v + a - 1) / a * a : v; }

// ---- 指针布局 -------------------------------------------------------------
// 一个 64 位指针字的通用布局：
//   bit0..1   类型：0 = struct，1 = list
//   bit2..31  有符号偏移，单位是"字"，基准是"指针字的下一个字节"
// struct 专用：bit32..47 = 数据段字数，bit48..63 = 指针个数
// list   专用：bit32..34 = 元素大小枚举，bit35..63 = 元素个数
//
// 注意元素个数从 bit35 起跳，不是 bit32：3 位元素大小把它挤过去了。把这个位
// 偏 3 位就会把长度写错，读端也就解不出 text。
constexpr std::uint64_t kKindMask = 0x3u;
constexpr std::uint64_t kKindList = 1u;
constexpr std::uint64_t kOffsetMask = 0x3FFFFFFFu;    // 30 位补码
constexpr std::uint64_t kOffsetSignBit = 1ull << 29;  // 30 位补码的符号位
constexpr std::uint64_t kListCountMask = 0x1FFFFFFFu; // 29 位
constexpr std::uint64_t kListElemByte = 2;            // 元素大小枚举：2 = BYTE

std::uint64_t make_struct_ptr(std::int64_t offsetWords, std::uint16_t dataWords,
                              std::uint16_t ptrCount) {
    const std::uint64_t off =
        static_cast<std::uint64_t>(static_cast<std::uint32_t>(offsetWords)) & kOffsetMask;
    return (off << 2) | (static_cast<std::uint64_t>(dataWords) << 32) |
           (static_cast<std::uint64_t>(ptrCount) << 48);
}

// text 与 data 都编码成"字节列表"：元素大小 2，元素个数写在指针里，
// 目标字处直接就是第一个元素。capnp 规范没有"列表首字存长度"这一层，
// 若在内容前多插一个字，真正的 capnp 读端（边缘）会整体错位。
std::uint64_t make_byte_list_ptr(std::int64_t offsetWords, std::uint32_t count) {
    const std::uint64_t off =
        static_cast<std::uint64_t>(static_cast<std::uint32_t>(offsetWords)) & kOffsetMask;
    return kKindList | (off << 2) | (kListElemByte << 32) |
           ((static_cast<std::uint64_t>(count) & kListCountMask) << 35);
}

std::uint16_t ptr_data_words(std::uint64_t p) {
    return static_cast<std::uint16_t>((p >> 32) & 0xFFFFu);
}

std::uint16_t ptr_ptr_count(std::uint64_t p) {
    return static_cast<std::uint16_t>((p >> 48) & 0xFFFFu);
}

std::uint64_t ptr_elem_size(std::uint64_t p) { return (p >> 32) & 0x7u; }
std::uint64_t ptr_list_count(std::uint64_t p) { return (p >> 35) & kListCountMask; }

// 30 位补码转有符号。手工拼符号位而不是 (int32)(raw << 2) >> 2：
// 后者依赖"无符号转有符号超出范围"的实现定义行为。
std::int64_t ptr_offset_words(std::uint64_t p) {
    const std::uint64_t raw = (p >> 2) & kOffsetMask;
    std::int64_t v = static_cast<std::int64_t>(raw & (kOffsetSignBit - 1));
    if ((raw & kOffsetSignBit) != 0) v -= static_cast<std::int64_t>(kOffsetSignBit << 1);
    return v;
}

// 越界检查统一在这里做：off > size 时先判，避免 off + 8 这类加法溢出。
bool fetch_word(const std::uint8_t* base, std::size_t size, std::size_t off,
                std::uint64_t& out) {
    if (base == nullptr || off > size || size - off < 8) return false;
    out = load_le64(base + off);
    return true;
}

// 目标 = 指针字之后 + 偏移（偏移单位是字），且必须落在段体内。
bool target_of(std::size_t slot, std::uint64_t p, std::size_t limit, std::size_t& target) {
    const std::int64_t t = static_cast<std::int64_t>(slot) + 8 + ptr_offset_words(p) * 8;
    if (t < 0 || static_cast<std::size_t>(t) > limit) return false;
    target = static_cast<std::size_t>(t);
    return true;
}

bool struct_extent_fits(std::size_t target, std::uint16_t dataWords, std::uint16_t ptrCount,
                        std::size_t size) {
    const std::size_t need =
        static_cast<std::size_t>(dataWords) * 8 + static_cast<std::size_t>(ptrCount) * 8;
    return target <= size && need <= size - target;
}

}  // namespace

// --- Message ---------------------------------------------------------------

Message::Message(std::size_t reserve) { arena_.reserve(reserve); }

std::size_t Message::allocate(std::size_t bytes, std::size_t align) {
    const std::size_t off = align_up(arena_.size(), align);
    arena_.resize(off + bytes, 0);  // 新增区域先清零：未写到的字段必须是默认值 0
    return off;
}

StructBuilder Message::alloc_struct(std::uint16_t dataWords, std::uint16_t ptrCount) {
    const std::size_t off = allocate(static_cast<std::size_t>(dataWords) * 8 +
                                         static_cast<std::size_t>(ptrCount) * 8,
                                     8);
    return StructBuilder(this, off, dataWords, ptrCount);
}

void Message::write_u16(std::size_t off, std::uint16_t v) {
    if (off > arena_.size() || arena_.size() - off < 2) return;
    store_le16(arena_.data() + off, v);
}

void Message::write_u32(std::size_t off, std::uint32_t v) {
    if (off > arena_.size() || arena_.size() - off < 4) return;
    store_le32(arena_.data() + off, v);
}

void Message::write_u64(std::size_t off, std::uint64_t v) {
    if (off > arena_.size() || arena_.size() - off < 8) return;
    store_le64(arena_.data() + off, v);
}

// off 是字节偏移（与相邻的 write_u16/write_u32 一致），只操作该字节的 bit0。
// 按位定位的 bool 字段走 StructBuilder::set_bool，它自己算位再落到字节上。
void Message::write_bool(std::size_t off, bool v) {
    if (off >= arena_.size()) return;
    const std::uint8_t bit = static_cast<std::uint8_t>(1u << 0);
    if (v) {
        arena_[off] = static_cast<std::uint8_t>(arena_[off] | bit);
    } else {
        arena_[off] = static_cast<std::uint8_t>(arena_[off] & static_cast<std::uint8_t>(~bit));
    }
}

void Message::write_ptr_raw(std::size_t off, std::uint64_t v) {
    if (off > arena_.size() || arena_.size() - off < 8) return;
    store_le64(arena_.data() + off, v);
}

std::vector<std::uint8_t> Message::finish() const {
    const std::size_t bodyBytes = align_up(arena_.size(), 8);

    // 根指针必须占据段体的第一个字，所以先给段首留一个字，再把 arena 整体后移。
    std::vector<std::uint8_t> seg(bodyBytes + 8, 0);
    if (!arena_.empty()) std::memcpy(seg.data() + 8, arena_.data(), arena_.size());

    if (hasRoot_) {
        // 根指针在段体偏移 0。arena 里的偏移相对段体偏移 8，所以指向结构体
        // 数据段的偏移恰好是 (arena 偏移 + 8 - 8)/8 = arena 偏移/8。arena 中
        // 的分配都按 8 对齐，这个除法不会丢位。
        const std::uint64_t p = make_struct_ptr(
            static_cast<std::int64_t>(root_.data_offset() / 8), root_.data_words(),
            root_.ptr_count());
        store_le64(seg.data(), p);
    }

    // 段表：第一个 u32 是 (段数 - 1)，随后每个段的字宽。我们只产出单段，
    // 两个 u32 正好凑满 8 字节边界。若将来需要多段，这里要按段表长度补齐。
    const std::size_t totalWords = seg.size() / 8;
    std::vector<std::uint8_t> out(8 + seg.size(), 0);
    store_le32(out.data(), 0);  // 段数 - 1 == 0
    store_le32(out.data() + 4, static_cast<std::uint32_t>(totalWords));
    std::memcpy(out.data() + 8, seg.data(), seg.size());
    return out;
}

// --- StructBuilder ---------------------------------------------------------

std::size_t StructBuilder::ptr_slot(std::uint16_t index) const {
    return dataOff_ + static_cast<std::size_t>(dataWords_) * 8 +
           static_cast<std::size_t>(index) * 8;
}

void StructBuilder::set_u8(std::uint16_t field, std::uint8_t v) {
    if (m_ == nullptr) return;
    // field 是字节下标。越出数据段就丢弃：写进后面的指针段会把指针改坏，
    // 而这些指针只有写端自己知道怎么修。
    if (field >= dataWords_ * 8u) return;
    const std::size_t off = dataOff_ + field;
    if (off >= m_->arena().size()) return;
    m_->arena()[off] = v;
}

void StructBuilder::set_u16(std::uint16_t field, std::uint16_t v) {
    if (m_ == nullptr || field >= dataWords_ * 4u) return;
    m_->write_u16(dataOff_ + static_cast<std::size_t>(field) * 2, v);
}

void StructBuilder::set_u32(std::uint16_t field, std::uint32_t v) {
    if (m_ == nullptr || field >= dataWords_ * 2u) return;
    m_->write_u32(dataOff_ + static_cast<std::size_t>(field) * 4, v);
}

void StructBuilder::set_u64(std::uint16_t field, std::uint64_t v) {
    if (m_ == nullptr || field >= dataWords_) return;
    m_->write_u64(dataOff_ + static_cast<std::size_t>(field) * 8, v);
}

// bit 是 capnp 的位下标（bool 按位寻址，不是按字节）。
void StructBuilder::set_bool(std::uint16_t bit, bool v) {
    if (m_ == nullptr || bit >= dataWords_ * 64u) return;
    const std::size_t off = dataOff_ + bit / 8;
    if (off >= m_->arena().size()) return;
    const std::uint8_t mask = static_cast<std::uint8_t>(1u << (bit % 8));
    std::uint8_t& byte = m_->arena()[off];
    if (v) {
        byte = static_cast<std::uint8_t>(byte | mask);
    } else {
        byte = static_cast<std::uint8_t>(byte & static_cast<std::uint8_t>(~mask));
    }
}

// 判别值同样是位偏移：capnp 的 union 判别字段可以和别的字段共用字节，
// 所以必须读改写，不能整字节覆盖。
void StructBuilder::set_union_tag(std::uint16_t bitOffset, std::uint16_t value) {
    if (m_ == nullptr || bitOffset >= dataWords_ * 64u) return;
    const std::size_t byte = dataOff_ + static_cast<std::size_t>(bitOffset) / 8;
    const int shift = static_cast<int>(bitOffset % 8);
    std::vector<std::uint8_t>& a = m_->arena();
    // 16 位字段跨字节后最多触及 3 个字节；shift == 0 时只占 2 个，此时按 3 个
    // 去校验会把"写完这个字段刚好到 arena 末尾"的合法情形误判成越界。
    const std::size_t touched = shift == 0 ? 2u : 3u;
    if (byte > a.size() || a.size() - byte < touched) return;

    std::uint32_t cur = static_cast<std::uint32_t>(a[byte]) |
                        (static_cast<std::uint32_t>(a[byte + 1]) << 8) |
                        (static_cast<std::uint32_t>(a[byte + 2]) << 16);
    const std::uint32_t mask = static_cast<std::uint32_t>(0xFFFFu) << shift;
    cur = (cur & ~mask) | ((static_cast<std::uint32_t>(value) << shift) & mask);
    a[byte] = static_cast<std::uint8_t>(cur & 0xFFu);
    a[byte + 1] = static_cast<std::uint8_t>((cur >> 8) & 0xFFu);
    a[byte + 2] = static_cast<std::uint8_t>((cur >> 16) & 0xFFu);
}

void StructBuilder::set_text(std::uint16_t index, const std::string& s) {
    if (m_ == nullptr || index >= ptrCount_) return;
    // 元素个数含结尾 NUL，所以申请 size+1 字节；列表起点按 8 字节对齐。
    const std::size_t payload = m_->allocate(s.size() + 1, 8);
    std::uint8_t* dst = m_->arena().data() + payload;
    if (!s.empty()) std::memcpy(dst, s.data(), s.size());
    dst[s.size()] = 0;

    const std::size_t slot = ptr_slot(index);
    const std::int64_t offWords =
        (static_cast<std::int64_t>(payload) - static_cast<std::int64_t>(slot) - 8) / 8;
    m_->write_ptr_raw(slot, make_byte_list_ptr(offWords, static_cast<std::uint32_t>(s.size() + 1)));
}

void StructBuilder::set_data(std::uint16_t index, const void* d, std::size_t n) {
    if (m_ == nullptr || index >= ptrCount_) return;
    const std::size_t payload = m_->allocate(n, 8);
    if (n != 0 && d != nullptr) std::memcpy(m_->arena().data() + payload, d, n);

    const std::size_t slot = ptr_slot(index);
    const std::int64_t offWords =
        (static_cast<std::int64_t>(payload) - static_cast<std::int64_t>(slot) - 8) / 8;
    m_->write_ptr_raw(slot, make_byte_list_ptr(offWords, static_cast<std::uint32_t>(n)));
}

void StructBuilder::set_struct(std::uint16_t index, const StructBuilder& target) {
    if (m_ == nullptr || index >= ptrCount_) return;
    // 跨消息的指针没有意义（偏移是相对本段体的），静默丢弃比写出乱码好。
    if (target.m_ != m_) return;
    const std::size_t slot = ptr_slot(index);
    const std::int64_t offWords =
        (static_cast<std::int64_t>(target.data_offset()) - static_cast<std::int64_t>(slot) - 8) / 8;
    m_->write_ptr_raw(slot,
                      make_struct_ptr(offWords, target.data_words(), target.ptr_count()));
}

// --- Reader ----------------------------------------------------------------
// Reader 的 base_/size_ 已经由构造函数跳到段体（跳过 8 字节单段段表），
// 因此这里所有偏移都是段体内偏移，和 finish() 里的 arena 偏移差 8。

bool Reader::root(std::size_t& dataOff, std::uint16_t& dataWords,
                  std::uint16_t& ptrCount) const {
    std::uint64_t p = 0;
    if (!fetch_word(base_, size_, 0, p)) return false;
    if ((p & kKindMask) != 0) return false;  // 根必须是 struct 指针

    const std::uint16_t dw = ptr_data_words(p);
    const std::uint16_t pc = ptr_ptr_count(p);
    std::size_t target = 0;
    if (!target_of(0, p, size_, target)) return false;
    if (!struct_extent_fits(target, dw, pc, size_)) return false;

    dataOff = target;
    dataWords = dw;
    ptrCount = pc;
    return true;
}

bool Reader::read_struct_ptr(std::size_t ptrSlot, std::size_t& dataOff) const {
    std::uint64_t p = 0;
    if (!fetch_word(base_, size_, ptrSlot, p)) return false;
    if ((p & kKindMask) != 0) return false;

    // 不知道结构体宽度时只校验目标在段内；具体字段的读取由 read_u16/read_u32…
    // 各自再过一次边界，避免这里假装知道长度。
    std::size_t target = 0;
    if (!target_of(ptrSlot, p, size_, target)) return false;
    dataOff = target;
    return true;
}

bool Reader::read_struct_ptr(std::size_t ptrSlot, std::size_t& dataOff,
                             std::uint16_t& dataWords, std::uint16_t& ptrCount,
                             std::size_t& ptrOff) const {
    std::uint64_t p = 0;
    if (!fetch_word(base_, size_, ptrSlot, p)) return false;
    if ((p & kKindMask) != 0) return false;

    const std::uint16_t dw = ptr_data_words(p);
    const std::uint16_t pc = ptr_ptr_count(p);
    std::size_t target = 0;
    if (!target_of(ptrSlot, p, size_, target)) return false;
    if (!struct_extent_fits(target, dw, pc, size_)) return false;

    dataOff = target;
    dataWords = dw;
    ptrCount = pc;
    ptrOff = target + static_cast<std::size_t>(dw) * 8;
    return true;
}

bool Reader::read_u16(std::size_t off, std::uint16_t& v) const {
    if (base_ == nullptr || off > size_ || size_ - off < 2) return false;
    v = load_le16(base_ + off);
    return true;
}

bool Reader::read_u32(std::size_t off, std::uint32_t& v) const {
    if (base_ == nullptr || off > size_ || size_ - off < 4) return false;
    v = load_le32(base_ + off);
    return true;
}

bool Reader::read_u64(std::size_t off, std::uint64_t& v) const {
    return fetch_word(base_, size_, off, v);
}

bool Reader::list_ptr(std::size_t ptrSlot, std::size_t& dataOff, std::size_t& count) const {
    std::uint64_t p = 0;
    if (!fetch_word(base_, size_, ptrSlot, p)) return false;
    if ((p & kKindMask) != kKindList) return false;
    if (ptr_elem_size(p) != kListElemByte) return false;  // text/data 都必须是字节列表

    std::size_t target = 0;
    if (!target_of(ptrSlot, p, size_, target)) return false;

    // 元素就是一个字节，个数即字节数；用减法比较避免 target + count 溢出。
    const std::size_t n = static_cast<std::size_t>(ptr_list_count(p));
    if (n > size_ - target) return false;

    dataOff = target;
    count = n;
    return true;
}

bool Reader::read_text(std::size_t ptrSlot, std::string& out) const {
    std::size_t off = 0;
    std::size_t count = 0;
    if (!list_ptr(ptrSlot, off, count)) return false;
    // 空指针语义上等同于空 text；capnp 的正常 text 至少含一个 NUL。
    if (count == 0) {
        out.clear();
        return true;
    }
    out.assign(reinterpret_cast<const char*>(base_ + off), count - 1);
    return true;
}

bool Reader::read_blob(std::size_t ptrSlot, std::vector<std::uint8_t>& out) const {
    std::size_t off = 0;
    std::size_t count = 0;
    if (!list_ptr(ptrSlot, off, count)) return false;
    out.assign(base_ + off, base_ + off + count);
    return true;
}

bool Reader::read_bytes(std::size_t ptrSlot, const std::uint8_t*& data, std::size_t& len) const {
    std::size_t off = 0;
    std::size_t count = 0;
    if (!list_ptr(ptrSlot, off, count)) return false;
    data = base_ + off;
    len = count;
    return true;
}

}  // namespace ct::capnp
