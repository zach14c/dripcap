#ifndef BUFFER_HPP
#define BUFFER_HPP

#include <memory>
#include <v8.h>
#include <vector>

class Buffer {
public:
  Buffer();
  Buffer(const std::shared_ptr<std::vector<char>> &source);
  explicit Buffer(const v8::FunctionCallbackInfo<v8::Value> &args);
  ~Buffer();
  Buffer(const Buffer &) = delete;
  Buffer &operator=(const Buffer &) = delete;
  size_t length() const;
  std::unique_ptr<Buffer> slice(size_t start, size_t end) const;
  std::unique_ptr<Buffer> slice(size_t start = 0) const;

  void readInt8(const v8::FunctionCallbackInfo<v8::Value> &args) const;
  void readInt16BE(const v8::FunctionCallbackInfo<v8::Value> &args) const;
  void readInt32BE(const v8::FunctionCallbackInfo<v8::Value> &args) const;

  void readUInt8(const v8::FunctionCallbackInfo<v8::Value> &args) const;
  void readUInt16BE(const v8::FunctionCallbackInfo<v8::Value> &args) const;
  void readUInt32BE(const v8::FunctionCallbackInfo<v8::Value> &args) const;

  void get(uint32_t index,
           const v8::PropertyCallbackInfo<v8::Value> &info) const;
  void sliceBuffer(const v8::FunctionCallbackInfo<v8::Value> &args) const;
  void toString(const v8::FunctionCallbackInfo<v8::Value> &args) const;
  void indexOf(const v8::FunctionCallbackInfo<v8::Value> &args) const;
  std::string valueOf() const;
  const char *data(size_t offset = 0) const;

  void freeze();

public:
  static void from(const v8::FunctionCallbackInfo<v8::Value> &args);
  static bool isBuffer(const v8::Local<v8::Value> &value);

private:
  class Private;
  std::unique_ptr<Private> d;
};

#endif
