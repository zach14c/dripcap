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

  v8::Isolate *isolate = v8::Isolate::GetCurrent();
  LogMessage msg;
  msg.level = level;
  msg.domain = domain;
  msg.message = v8pp::from_v8<std::string>(isolate, args[0], "");
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
