#include "console.hpp"
#include "log_message.hpp"
#include <v8pp/class.hpp>

class Console::Private {
public:
  Private(const std::function<void(const LogMessage &msg)> &logCb,
          const std::string &domain);
  void log(const v8::FunctionCallbackInfo<v8::Value> &args,
           LogMessage::Level level) const;

public:
  std::function<void(const LogMessage &msg)> logCb;
  std::string domain;
};

Console::Private::Private(
    const std::function<void(const LogMessage &msg)> &logCb,
    const std::string &domain)
    : logCb(logCb), domain(domain) {}

void Console::Private::log(const v8::FunctionCallbackInfo<v8::Value> &args,
                           LogMessage::Level level) const {

  LogMessage msg;
  msg.level = level;
  msg.domain = domain;
  for (int i = 0; i < args.Length(); ++i) {
    v8::String::Utf8Value str(args[i]);
    if (*str) {
      msg.message += *str;
      msg.message += " ";
    }
  }
  if (!msg.message.empty()) {
    msg.message.resize(msg.message.size() - 1);
  }
  if (logCb)
    logCb(msg);
}

Console::Console(const std::function<void(const LogMessage &msg)> &logCb,
                 const std::string &domain)
    : d(new Private(logCb, domain)) {}

Console::~Console() {}

void Console::log(const v8::FunctionCallbackInfo<v8::Value> &args) const {
  d->log(args, LogMessage::LEVEL_INFO);
}

void Console::debug(const v8::FunctionCallbackInfo<v8::Value> &args) const {
  d->log(args, LogMessage::LEVEL_DEBUG);
}

void Console::warn(const v8::FunctionCallbackInfo<v8::Value> &args) const {
  d->log(args, LogMessage::LEVEL_WARN);
}
