#ifndef LARGE_BUFFER_HPP
#define LARGE_BUFFER_HPP

#include <memory>
#include <string>
#include <v8.h>
#include <nan.h>

class LargeBuffer {
public:
  LargeBuffer();
  ~LargeBuffer();
  LargeBuffer(const LargeBuffer &);
  LargeBuffer &operator=(const LargeBuffer &);

  std::string id() const;
  std::string path() const;
  void write(const v8::FunctionCallbackInfo<v8::Value> &args);
  void get(uint32_t index,
           const Nan::PropertyCallbackInfo<v8::Value> &info) const;
  uint32_t length() const;
  static std::string tmpDir();

private:
  class Private;
  std::unique_ptr<Private> d;
};

#endif
