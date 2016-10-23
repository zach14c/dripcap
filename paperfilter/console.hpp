#ifndef CONSOLE_HPP
#define CONSOLE_HPP

#include <memory>
#include <functional>
#include <v8.h>

struct LogMessage;

class Console {
public:
  Console(const std::function<void(const LogMessage &msg)> &logCb,
          const std::string &domain);
  ~Console();
  Console(const Console &) = delete;
  Console &operator=(const Console &) = delete;
  void log(const v8::FunctionCallbackInfo<v8::Value> &args) const;
  void debug(const v8::FunctionCallbackInfo<v8::Value> &args) const;
  void warn(const v8::FunctionCallbackInfo<v8::Value> &args) const;

private:
  class Private;
  std::unique_ptr<Private> d;
};

#endif
