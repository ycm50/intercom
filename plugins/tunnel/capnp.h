#pragma once
// Cap'n Proto 线格式的极小子集：只覆盖 Cloudflare tunnel 控制流用到的部分
// （带 data 段与指针段的结构体、text、data blob、结构体指针）。
//
// 为什么手写而不引 capnproto：本项目对外承诺零第三方依赖，而这里只需要
// 编解码固定几个 schema，用一个完整运行时反而更重。
//
// 线格式要点（写实现时对照）：
//   * struct 指针 = 偏移 + 数据字宽 + 指针个数；目标处没有头部，直接是
//     [data 段][ptr 段]。
//   * text/data 指针指向"字节列表"：元素个数编码在指针的 bit35..63，目标处
//     **直接就是第一个元素**，内容前面没有额外的长度字。
//   * 每条消息前面是段表（段数 + 各段字宽），根指针在段体偏移 0。
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ct::capnp {

class Message;

class StructBuilder {
public:
    StructBuilder() = default;
    StructBuilder(Message* m, std::size_t dataOff, std::uint16_t dataWords, std::uint16_t ptrCount)
        : m_(m), dataOff_(dataOff), dataWords_(dataWords), ptrCount_(ptrCount) {}

    void set_u8(std::uint16_t field, std::uint8_t v);
    void set_u16(std::uint16_t field, std::uint16_t v);
    void set_u32(std::uint16_t field, std::uint32_t v);
    void set_u64(std::uint16_t field, std::uint64_t v);
    void set_bool(std::uint16_t bit, bool v);
    // 联合体的判别字段按位定位（capnp 生成代码就是这么写的）
    void set_union_tag(std::uint16_t bitOffset, std::uint16_t value);

    void set_text(std::uint16_t index, const std::string& s);
    void set_data(std::uint16_t index, const void* d, std::size_t n);
    void set_struct(std::uint16_t index, const StructBuilder& target);

    std::size_t data_offset() const { return dataOff_; }
    std::uint16_t data_words() const { return dataWords_; }
    std::uint16_t ptr_count() const { return ptrCount_; }

private:
    std::size_t ptr_slot(std::uint16_t index) const;

    Message* m_ = nullptr;
    std::size_t dataOff_ = 0;
    std::uint16_t dataWords_ = 0;
    std::uint16_t ptrCount_ = 0;
};

class Message {
public:
    explicit Message(std::size_t reserve = 1024);

    StructBuilder alloc_struct(std::uint16_t dataWords, std::uint16_t ptrCount);
    void set_root(const StructBuilder& s) { root_ = s; hasRoot_ = true; }

    std::vector<std::uint8_t> finish() const;

    std::size_t allocate(std::size_t bytes, std::size_t align = 8);

    void write_u16(std::size_t off, std::uint16_t v);
    void write_u32(std::size_t off, std::uint32_t v);
    void write_u64(std::size_t off, std::uint64_t v);
    void write_bool(std::size_t off, bool v);
    void write_ptr_raw(std::size_t off, std::uint64_t v);

    std::vector<std::uint8_t>& arena() { return arena_; }
    const std::vector<std::uint8_t>& arena() const { return arena_; }

private:
    std::vector<std::uint8_t> arena_;
    StructBuilder root_;
    bool hasRoot_ = false;
};

class Reader {
public:
    // 接受 Message::finish() 产出的"带段表"消息；构造时跳过段表。
    Reader(const std::uint8_t* base, std::size_t size) : base_(base), size_(size) {
        if (size_ >= 8) {
            base_ += 8;
            size_ -= 8;
        }
    }

    bool root(std::size_t& dataOff, std::uint16_t& dataWords, std::uint16_t& ptrCount) const;
    bool read_struct_ptr(std::size_t ptrSlot, std::size_t& dataOff) const;
    bool read_struct_ptr(std::size_t ptrSlot, std::size_t& dataOff, std::uint16_t& dataWords,
                         std::uint16_t& ptrCount, std::size_t& ptrOff) const;

    bool read_u16(std::size_t off, std::uint16_t& v) const;
    bool read_u32(std::size_t off, std::uint32_t& v) const;
    bool read_u64(std::size_t off, std::uint64_t& v) const;

    bool read_text(std::size_t ptrSlot, std::string& out) const;
    bool read_blob(std::size_t ptrSlot, std::vector<std::uint8_t>& out) const;
    bool read_bytes(std::size_t ptrSlot, const std::uint8_t*& data, std::size_t& len) const;

    std::size_t size() const { return size_; }

private:
    bool list_ptr(std::size_t ptrSlot, std::size_t& dataOff, std::size_t& count) const;

    const std::uint8_t* base_;
    std::size_t size_;
};

}  // namespace ct::capnp
