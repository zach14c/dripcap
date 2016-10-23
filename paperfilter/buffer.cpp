#include "buffer.hpp"
#include <iomanip>
#include <sstream>
#include <v8pp/class.hpp>

using namespace v8;

namespace {
int search(const char *str, int strlen, const char *sub, int sublen) {
  if (sublen > strlen)
    return -1;
  if (sublen == 0)
    return 0;
  int index = sublen;
  while (index <= strlen) {
    int shift = sublen;
    for (int i = 0; i < sublen; ++i) {
      char c = str[index - i - 1];
      if (sub[sublen - i - 1] == c) {
        shift--;
        continue;
      }
      for (int j = 1; j < sublen - i; ++j) {
        if (sub[sublen - i - j - 1] == c) {
          shift = j;
          i = sublen;
          break;
        }
      }
    }
    if (shift == 0)
      return index - sublen;
    index += shift;
  }
  return -1;
}
}

class Buffer::Private {
public:
  Private();
  ~Private();

public:
  std::shared_ptr<std::vector<char>> source =
      std::make_shared<std::vector<char>>();
  std::shared_ptr<bool> readonly = std::make_shared<bool>(false);
  size_t start = 0;
  size_t end = 0;
};

Buffer::Private::Private() {}

Buffer::Private::~Private() {}

Buffer::Buffer() : d(new Private()) {}

Buffer::Buffer(const std::shared_ptr<std::vector<char>> &source)
    : d(new Private()) {
  d->source = source;
  d->end = d->source->size();
}

Buffer::Buffer(const v8::FunctionCallbackInfo<v8::Value> &args)
    : d(new Private()) {
  Isolate *isolate = Isolate::GetCurrent();
  const std::shared_ptr<std::vector<char>> &buf =
      std::make_shared<std::vector<char>>();

  if (args[0]->IsString()) {
    const std::string &str = v8pp::from_v8<std::string>(isolate, args[0], "");
    const std::string &type =
        v8pp::from_v8<std::string>(isolate, args[1], "utf8");

    if (type == "utf8") {
      buf->assign(str.begin(), str.end());
    } else if (type == "hex") {
      try {
        if (str.size() % 2 != 0) {
          throw std::invalid_argument("");
        }
        for (size_t i = 0; i < str.size() / 2; ++i) {
          buf->push_back(std::stoul(str.substr(i * 2, 2), nullptr, 16));
        }
      } catch (const std::invalid_argument &e) {
        throw std::invalid_argument("Invalid hex string");
      }
    } else {
      std::string err("Unknown encoding: ");
      throw std::invalid_argument(err + type);
    }
  } else if (args[0]->IsArray()) {
    const auto &array = v8pp::from_v8<std::vector<unsigned char>>(
        isolate, args[0], std::vector<unsigned char>());
    for (unsigned char c : array) {
      buf->push_back(c);
    }
  } else if (Buffer *buffer =
                 v8pp::class_<Buffer>::unwrap_object(isolate, args[0])) {
    buf->assign(buffer->data(), buffer->data() + buffer->length());
  } else {
    args.GetReturnValue().Set(v8pp::throw_ex(
        isolate, "First argument must be a string, Buffer, or Array"));
  }

  d->source = buf;
  d->end = d->source->size();
}

Buffer::~Buffer() {}

size_t Buffer::length() const { return d->end - d->start; }

std::unique_ptr<Buffer> Buffer::slice(size_t start, size_t end) const {
  std::unique_ptr<Buffer> buf(new Buffer(d->source));
  buf->d->readonly = d->readonly;
  buf->d->start = std::min(d->start + start, d->source->size());
  buf->d->end = std::min(buf->d->start + (end - start), d->end);
  return buf;
}

std::unique_ptr<Buffer> Buffer::slice(size_t start) const {
  return slice(start, length());
}

void Buffer::sliceBuffer(
    const v8::FunctionCallbackInfo<v8::Value> &args) const {
  Isolate *isolate = Isolate::GetCurrent();
  size_t s = v8pp::from_v8<size_t>(isolate, args[0], 0);
  size_t e =
      std::min(v8pp::from_v8<size_t>(isolate, args[1], length()), length());
  args.GetReturnValue().Set(
      v8pp::class_<Buffer>::import_external(isolate, slice(s, e).release()));
}

void Buffer::readInt8(const v8::FunctionCallbackInfo<v8::Value> &args) const {
  Isolate *isolate = Isolate::GetCurrent();
  size_t offset = v8pp::from_v8<size_t>(isolate, args[0], 0);
  bool noassert = v8pp::from_v8<bool>(isolate, args[1], true);
  if (!noassert && offset + sizeof(int8_t) > length()) {
    args.GetReturnValue().Set(v8pp::throw_ex(isolate, "index out of range"));
  } else {
    args.GetReturnValue().Set(data(offset)[0]);
  }
}

void Buffer::readInt16BE(
    const v8::FunctionCallbackInfo<v8::Value> &args) const {
  Isolate *isolate = Isolate::GetCurrent();
  size_t offset = v8pp::from_v8<size_t>(isolate, args[0], 0);
  bool noassert = v8pp::from_v8<bool>(isolate, args[1], true);
  if (!noassert && offset + sizeof(int16_t) > length()) {
    args.GetReturnValue().Set(v8pp::throw_ex(isolate, "index out of range"));
  } else {
    const char buf[2] = {data(offset)[1], data(offset)[0]};
    int16_t num = *reinterpret_cast<const int16_t *>(buf);
    args.GetReturnValue().Set(num);
  }
}

void Buffer::readInt32BE(
    const v8::FunctionCallbackInfo<v8::Value> &args) const {
  Isolate *isolate = Isolate::GetCurrent();
  size_t offset = v8pp::from_v8<size_t>(isolate, args[0], 0);
  bool noassert = v8pp::from_v8<bool>(isolate, args[1], true);
  if (!noassert && offset + sizeof(int32_t) > length()) {
    args.GetReturnValue().Set(v8pp::throw_ex(isolate, "index out of range"));
  } else {
    const char buf[4] = {data(offset)[3], data(offset)[2], data(offset)[1],
                         data(offset)[0]};
    int32_t num = *reinterpret_cast<const int32_t *>(buf);
    args.GetReturnValue().Set(num);
  }
}

void Buffer::readUInt8(const v8::FunctionCallbackInfo<v8::Value> &args) const {
  Isolate *isolate = Isolate::GetCurrent();
  size_t offset = v8pp::from_v8<size_t>(isolate, args[0], 0);
  bool noassert = v8pp::from_v8<bool>(isolate, args[1], true);
  if (!noassert && offset + sizeof(uint8_t) > length()) {
    args.GetReturnValue().Set(v8pp::throw_ex(isolate, "index out of range"));
  } else {
    args.GetReturnValue().Set(*reinterpret_cast<const uint8_t *>(data(offset)));
  }
}

void Buffer::readUInt16BE(
    const v8::FunctionCallbackInfo<v8::Value> &args) const {
  Isolate *isolate = Isolate::GetCurrent();
  size_t offset = v8pp::from_v8<size_t>(isolate, args[0], 0);
  bool noassert = v8pp::from_v8<bool>(isolate, args[1], true);
  if (!noassert && offset + sizeof(uint16_t) > length()) {
    args.GetReturnValue().Set(v8pp::throw_ex(isolate, "index out of range"));
  } else {
    const char buf[2] = {data(offset)[1], data(offset)[0]};
    uint16_t num = *reinterpret_cast<const uint16_t *>(buf);
    args.GetReturnValue().Set(num);
  }
}

void Buffer::readUInt32BE(
    const v8::FunctionCallbackInfo<v8::Value> &args) const {
  Isolate *isolate = Isolate::GetCurrent();
  size_t offset = v8pp::from_v8<size_t>(isolate, args[0], 0);
  bool noassert = v8pp::from_v8<bool>(isolate, args[1], true);
  if (!noassert && offset + sizeof(uint32_t) > length()) {
    args.GetReturnValue().Set(v8pp::throw_ex(isolate, "index out of range"));
  } else {
    const char buf[4] = {data(offset)[3], data(offset)[2], data(offset)[1],
                         data(offset)[0]};
    uint32_t num = *reinterpret_cast<const uint32_t *>(buf);
    args.GetReturnValue().Set(num);
  }
}

void Buffer::toString(const v8::FunctionCallbackInfo<v8::Value> &args) const {
  Isolate *isolate = Isolate::GetCurrent();
  const std::string &type =
      v8pp::from_v8<std::string>(isolate, args[0], "utf8");

  if (type == "utf8") {
    args.GetReturnValue().Set(
        v8pp::to_v8(isolate, std::string(data(), length())));
  } else if (type == "hex") {
    std::stringstream stream;
    for (size_t i = 0; i < length(); ++i) {
      stream << std::hex << std::setfill('0') << std::setw(2)
             << static_cast<uint32_t>(
                    *reinterpret_cast<const uint8_t *>(data(i)));
    }
    args.GetReturnValue().Set(v8pp::to_v8(isolate, stream.str()));
  } else {
    std::string err("Unknown encoding: ");
    args.GetReturnValue().Set(v8pp::throw_ex(isolate, (err + type).c_str()));
  }
}

std::string Buffer::valueOf() const {
  size_t tail = std::min(static_cast<size_t>(16), length());
  std::string str("<Buffer");
  std::stringstream stream;
  for (size_t i = 0; i < tail; ++i) {
    stream << " " << std::hex << std::setfill('0') << std::setw(2)
           << static_cast<uint32_t>(
                  *reinterpret_cast<const uint8_t *>(data(i)));
  }
  str += stream.str();
  if (length() > 16)
    str += "...";
  return str + ">";
}

void Buffer::indexOf(const v8::FunctionCallbackInfo<v8::Value> &args) const {
  Isolate *isolate = Isolate::GetCurrent();
  if (Buffer *buffer = v8pp::class_<Buffer>::unwrap_object(isolate, args[0])) {
    args.GetReturnValue().Set(
        search(data(), length(), buffer->data(), buffer->length()));
  } else {
    args.GetReturnValue().Set(1);
  }
}

void Buffer::get(uint32_t index,
                 const v8::PropertyCallbackInfo<v8::Value> &info) const {
  Isolate *isolate = Isolate::GetCurrent();
  if (index >= length()) {
    info.GetReturnValue().Set(v8pp::throw_ex(isolate, "index out of range"));
  } else {
    info.GetReturnValue().Set(static_cast<uint8_t>(*data(index)));
  }
}

const char *Buffer::data(size_t offset) const {
  return d->source->data() + d->start + offset;
}

void Buffer::from(const v8::FunctionCallbackInfo<v8::Value> &args) {
  Local<Object> obj =
      v8pp::class_<Buffer>::create_object(Isolate::GetCurrent(), args);
  args.GetReturnValue().Set(obj);
}

bool Buffer::isBuffer(const v8::Local<v8::Value> &value) {
  return v8pp::class_<Buffer>::unwrap_object(Isolate::GetCurrent(), value);
}

void Buffer::freeze() { *d->readonly = true; }
