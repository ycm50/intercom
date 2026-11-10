#pragma once
// 极简 JSON：自带解析与序列化，不依赖任何第三方库。
// 支持：对象 / 数组 / 字符串 / 数字 / 布尔 / null，保留键顺序，输出合法 UTF-8。
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace jsonx {

class Json {
 public:
  enum class Type { Null, Bool, Number, String, Array, Object };

  Json() = default;
  Json(std::nullptr_t) {}
  Json(bool v) : type_(Type::Bool), bool_(v) {}
  Json(int v) : type_(Type::Number), num_(v) {}
  Json(long v) : type_(Type::Number), num_(static_cast<double>(v)) {}
  Json(long long v) : type_(Type::Number), num_(static_cast<double>(v)) {}
  Json(unsigned v) : type_(Type::Number), num_(v) {}
  Json(unsigned long long v) : type_(Type::Number), num_(static_cast<double>(v)) {}
  Json(double v) : type_(Type::Number), num_(v) {}
  Json(const char *v) : type_(Type::String), str_(v ? v : "") {}
  Json(const std::string &v) : type_(Type::String), str_(v) {}
  Json(std::string &&v) : type_(Type::String), str_(std::move(v)) {}
  Json(std::initializer_list<std::pair<const std::string, Json>> init) {
    type_ = Type::Object;
    for (const auto &kv : init) obj_.emplace_back(kv.first, kv.second);
  }

  static Json object() { Json j; j.type_ = Type::Object; return j; }
  static Json array() { Json j; j.type_ = Type::Array; return j; }

  Type type() const { return type_; }
  bool is_null() const { return type_ == Type::Null; }
  bool is_object() const { return type_ == Type::Object; }
  bool is_array() const { return type_ == Type::Array; }
  bool is_string() const { return type_ == Type::String; }
  bool is_number() const { return type_ == Type::Number; }
  bool is_boolean() const { return type_ == Type::Bool; }
  bool is_integer() const {
    return type_ == Type::Number && std::floor(num_) == num_ && std::fabs(num_) < 9e15;
  }

  bool empty() const {
    if (type_ == Type::Array) return arr_.empty();
    if (type_ == Type::Object) return obj_.empty();
    if (type_ == Type::String) return str_.empty();
    return true;
  }
  size_t size() const {
    if (type_ == Type::Array) return arr_.size();
    if (type_ == Type::Object) return obj_.size();
    return 0;
  }

  template <typename T>
  T get() const;

  // 对象/数组迭代
  class iterator {
   public:
    iterator(Json *j, size_t i) : j_(j), i_(i) {}
    Json &value() const { return j_->type_ == Type::Array ? j_->arr_[i_] : j_->obj_[i_].second; }
    const std::string &key() const { return j_->obj_[i_].first; }
    iterator &operator++() { ++i_; return *this; }
    bool operator!=(const iterator &o) const { return i_ != o.i_; }
    bool operator==(const iterator &o) const { return i_ == o.i_; }
    Json &operator*() const { return value(); }
    Json *operator->() const { return &value(); }

   private:
    Json *j_;
    size_t i_;
  };
  class const_iterator {
   public:
    const_iterator(const Json *j, size_t i) : j_(j), i_(i) {}
    const Json &value() const { return j_->type_ == Type::Array ? j_->arr_[i_] : j_->obj_[i_].second; }
    const std::string &key() const { return j_->obj_[i_].first; }
    const_iterator &operator++() { ++i_; return *this; }
    bool operator!=(const const_iterator &o) const { return i_ != o.i_; }
    bool operator==(const const_iterator &o) const { return i_ == o.i_; }
    const Json &operator*() const { return value(); }
    const Json *operator->() const { return &value(); }

   private:
    const Json *j_;
    size_t i_;
  };

  iterator begin() { return iterator(this, 0); }
  iterator end() { return iterator(this, size()); }
  const_iterator begin() const { return const_iterator(this, 0); }
  const_iterator end() const { return const_iterator(this, size()); }

  iterator find(const std::string &key) {
    if (type_ != Type::Object) return end();
    for (size_t i = 0; i < obj_.size(); ++i) {
      if (obj_[i].first == key) return iterator(this, i);
    }
    return end();
  }
  const_iterator find(const std::string &key) const {
    if (type_ != Type::Object) return end();
    for (size_t i = 0; i < obj_.size(); ++i) {
      if (obj_[i].first == key) return const_iterator(this, i);
    }
    return end();
  }

  Json &operator[](const std::string &key) {
    if (type_ != Type::Object) { type_ = Type::Object; obj_.clear(); }
    for (auto &kv : obj_) if (kv.first == key) return kv.second;
    obj_.emplace_back(key, Json());
    return obj_.back().second;
  }
  Json &operator[](size_t idx) {
    if (type_ != Type::Array) { type_ = Type::Array; arr_.clear(); }
    if (idx >= arr_.size()) arr_.resize(idx + 1);
    return arr_[idx];
  }

  void push_back(const Json &v) {
    if (type_ != Type::Array) { type_ = Type::Array; arr_.clear(); }
    arr_.push_back(v);
  }

  bool as_bool() const { return type_ == Type::Bool && bool_; }
  double as_number() const { return type_ == Type::Number ? num_ : 0; }
  const std::string &as_string() const {
    static const std::string kEmpty;
    return type_ == Type::String ? str_ : kEmpty;
  }

  std::string dump() const {
    std::string out;
    out.reserve(256);
    dump_to(out);
    return out;
  }

  // 解析；失败返回 false
  static bool parse(const std::string &text, Json &out) {
    Json parser;
    size_t pos = 0;
    if (!parser.skip_ws(text, pos)) return false;
    if (!parser.parse_value(text, pos, out)) return false;
    parser.skip_ws(text, pos);
    return true;
  }

 private:
  Type type_ = Type::Null;
  bool bool_ = false;
  double num_ = 0;
  std::string str_;
  std::vector<Json> arr_;
  std::vector<std::pair<std::string, Json>> obj_;

  void dump_to(std::string &out) const {
    switch (type_) {
      case Type::Null: out += "null"; break;
      case Type::Bool: out += bool_ ? "true" : "false"; break;
      case Type::Number: {
        char buf[40];
        if (is_integer()) std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(num_));
        else std::snprintf(buf, sizeof(buf), "%.17g", num_);
        out += buf;
        break;
      }
      case Type::String: dump_string(str_, out); break;
      case Type::Array: {
        out += '[';
        for (size_t i = 0; i < arr_.size(); ++i) {
          if (i) out += ',';
          arr_[i].dump_to(out);
        }
        out += ']';
        break;
      }
      case Type::Object: {
        out += '{';
        for (size_t i = 0; i < obj_.size(); ++i) {
          if (i) out += ',';
          dump_string(obj_[i].first, out);
          out += ':';
          obj_[i].second.dump_to(out);
        }
        out += '}';
        break;
      }
    }
  }

  static void dump_string(const std::string &s, std::string &out) {
    out += '"';
    for (unsigned char c : s) {
      switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
          if (c < 0x20) {
            char buf[8];
            std::snprintf(buf, sizeof(buf), "\\u%04x", c);
            out += buf;
          } else {
            out += static_cast<char>(c);  // UTF-8 原样输出
          }
      }
    }
    out += '"';
  }

  static bool skip_ws(const std::string &s, size_t &pos) {
    while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t' || s[pos] == '\n' || s[pos] == '\r')) {
      ++pos;
    }
    return true;
  }

  bool parse_value(const std::string &s, size_t &pos, Json &out) {
    if (pos >= s.size()) return false;
    char c = s[pos];
    if (c == '{') return parse_object(s, pos, out);
    if (c == '[') return parse_array(s, pos, out);
    if (c == '"') {
      std::string v;
      if (!parse_string(s, pos, v)) return false;
      out = Json(std::move(v));
      return true;
    }
    if (c == 't' && s.compare(pos, 4, "true") == 0) { pos += 4; out = Json(true); return true; }
    if (c == 'f' && s.compare(pos, 5, "false") == 0) { pos += 5; out = Json(false); return true; }
    if (c == 'n' && s.compare(pos, 4, "null") == 0) { pos += 4; out = Json(); return true; }
    return parse_number(s, pos, out);
  }

  bool parse_object(const std::string &s, size_t &pos, Json &out) {
    out = Json::object();
    ++pos;  // {
    skip_ws(s, pos);
    if (pos < s.size() && s[pos] == '}') { ++pos; return true; }
    for (;;) {
      skip_ws(s, pos);
      if (pos >= s.size() || s[pos] != '"') return false;
      std::string key;
      if (!parse_string(s, pos, key)) return false;
      skip_ws(s, pos);
      if (pos >= s.size() || s[pos] != ':') return false;
      ++pos;
      skip_ws(s, pos);
      Json v;
      if (!parse_value(s, pos, v)) return false;
      out[key] = v;
      skip_ws(s, pos);
      if (pos >= s.size()) return false;
      if (s[pos] == ',') { ++pos; continue; }
      if (s[pos] == '}') { ++pos; return true; }
      return false;
    }
  }

  bool parse_array(const std::string &s, size_t &pos, Json &out) {
    out = Json::array();
    ++pos;  // [
    skip_ws(s, pos);
    if (pos < s.size() && s[pos] == ']') { ++pos; return true; }
    for (;;) {
      Json v;
      if (!parse_value(s, pos, v)) return false;
      out.push_back(v);
      skip_ws(s, pos);
      if (pos >= s.size()) return false;
      if (s[pos] == ',') { ++pos; skip_ws(s, pos); continue; }
      if (s[pos] == ']') { ++pos; return true; }
      return false;
    }
  }

  static void append_utf8(std::string &out, unsigned cp) {
    if (cp < 0x80) {
      out += static_cast<char>(cp);
    } else if (cp < 0x800) {
      out += static_cast<char>(0xC0 | (cp >> 6));
      out += static_cast<char>(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
      out += static_cast<char>(0xE0 | (cp >> 12));
      out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
      out += static_cast<char>(0x80 | (cp & 0x3F));
    } else {
      out += static_cast<char>(0xF0 | (cp >> 18));
      out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
      out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
      out += static_cast<char>(0x80 | (cp & 0x3F));
    }
  }

  static bool parse_hex4(const std::string &s, size_t pos, unsigned &out) {
    if (pos + 4 > s.size()) return false;
    out = 0;
    for (int i = 0; i < 4; ++i) {
      char c = s[pos + i];
      out <<= 4;
      if (c >= '0' && c <= '9') out |= static_cast<unsigned>(c - '0');
      else if (c >= 'a' && c <= 'f') out |= static_cast<unsigned>(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') out |= static_cast<unsigned>(c - 'A' + 10);
      else return false;
    }
    return true;
  }

  bool parse_string(const std::string &s, size_t &pos, std::string &out) {
    ++pos;  // "
    out.clear();
    while (pos < s.size()) {
      unsigned char c = static_cast<unsigned char>(s[pos]);
      if (c == '"') { ++pos; return true; }
      if (c == '\\') {
        ++pos;
        if (pos >= s.size()) return false;
        char e = s[pos++];
        switch (e) {
          case '"': out += '"'; break;
          case '\\': out += '\\'; break;
          case '/': out += '/'; break;
          case 'b': out += '\b'; break;
          case 'f': out += '\f'; break;
          case 'n': out += '\n'; break;
          case 'r': out += '\r'; break;
          case 't': out += '\t'; break;
          case 'u': {
            unsigned cp = 0;
            if (!parse_hex4(s, pos, cp)) return false;
            pos += 4;
            if (cp >= 0xD800 && cp <= 0xDBFF && pos + 6 <= s.size() && s[pos] == '\\' &&
                s[pos + 1] == 'u') {
              unsigned lo = 0;
              if (!parse_hex4(s, pos + 2, lo)) return false;
              pos += 6;
              cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
            }
            append_utf8(out, cp);
            break;
          }
          default: return false;
        }
        continue;
      }
      out += static_cast<char>(c);
      ++pos;
    }
    return false;
  }

  bool parse_number(const std::string &s, size_t &pos, Json &out) {
    size_t start = pos;
    if (pos < s.size() && (s[pos] == '-' || s[pos] == '+')) ++pos;
    bool digits = false;
    while (pos < s.size() && s[pos] >= '0' && s[pos] <= '9') { ++pos; digits = true; }
    if (pos < s.size() && s[pos] == '.') {
      ++pos;
      while (pos < s.size() && s[pos] >= '0' && s[pos] <= '9') { ++pos; digits = true; }
    }
    if (digits && pos < s.size() && (s[pos] == 'e' || s[pos] == 'E')) {
      ++pos;
      if (pos < s.size() && (s[pos] == '-' || s[pos] == '+')) ++pos;
      while (pos < s.size() && s[pos] >= '0' && s[pos] <= '9') ++pos;
    }
    if (!digits) return false;
    out = Json(std::strtod(s.substr(start, pos - start).c_str(), nullptr));
    return true;
  }
};

template <>
inline bool Json::get<bool>() const { return as_bool(); }
template <>
inline double Json::get<double>() const { return as_number(); }
template <>
inline long long Json::get<long long>() const { return static_cast<long long>(as_number()); }
template <>
inline int Json::get<int>() const { return static_cast<int>(as_number()); }
template <>
inline std::string Json::get<std::string>() const { return as_string(); }

// 便捷函数
inline bool parse(const std::string &text, Json &out) { return Json::parse(text, out); }
inline std::string dump(const Json &j) { return j.dump(); }

inline std::string str(const Json &j, const char *key, const std::string &def = "") {
  auto it = j.find(key);
  if (it == j.end() || !it->is_string()) return def;
  return it->get<std::string>();
}

inline long long num(const Json &j, const char *key, long long def = 0) {
  auto it = j.find(key);
  if (it == j.end() || !it->is_number()) return def;
  return it->get<long long>();
}

inline bool boolean(const Json &j, const char *key, bool def = false) {
  auto it = j.find(key);
  if (it == j.end() || !it->is_boolean()) return def;
  return it->get<bool>();
}

}  // namespace jsonx