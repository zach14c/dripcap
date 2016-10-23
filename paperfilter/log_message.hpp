#ifndef LOG_MESSAGE_HPP
#define LOG_MESSAGE_HPP

#include <string>
#include <v8.h>

struct LogMessage {
  enum Level { LEVEL_DEBUG, LEVEL_INFO, LEVEL_WARN, LEVEL_ERROR };
  Level level = LEVEL_INFO;
  std::string message;
  std::string domain;
  std::string resourceName;
  std::string sourceLine;
  int lineNumber = -1;
  int startPosition = -1;
  int endPosition = -1;
  int startColumn = -1;
  int endColumn = -1;

  std::string key() const;
  static LogMessage fromMessage(v8::Local<v8::Message> msg,
                                const std::string &domain);
};

#endif
