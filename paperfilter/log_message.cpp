#include "log_message.hpp"
#include <v8pp/class.hpp>

LogMessage LogMessage::fromMessage(v8::Local<v8::Message> msg,
                                   const std::string &domain) {
  v8::Isolate *isolate = v8::Isolate::GetCurrent();
  LogMessage logmsg;
  logmsg.level = LEVEL_ERROR;
  logmsg.domain = domain;
  logmsg.message = v8pp::from_v8<std::string>(isolate, msg->Get(), "");
  logmsg.resourceName =
      v8pp::from_v8<std::string>(isolate, msg->GetScriptResourceName(), "");
  logmsg.sourceLine =
      v8pp::from_v8<std::string>(isolate, msg->GetSourceLine(), "");
  logmsg.lineNumber = msg->GetLineNumber();
  logmsg.startPosition = msg->GetStartPosition();
  logmsg.endPosition = msg->GetEndPosition();
  logmsg.startColumn = msg->GetStartColumn();
  logmsg.endColumn = msg->GetEndColumn();
  return logmsg;
}

std::string LogMessage::key() const {
  return "\r\n" + message + "\r\n" + domain + "\r\n" + resourceName + "\r\n" +
         sourceLine;
}
