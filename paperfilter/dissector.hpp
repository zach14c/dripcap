#ifndef DISSECTOR_HPP
#define DISSECTOR_HPP

#include <regex>
#include <string>
#include <v8.h>
#include <vector>

struct Dissector {
public:
  explicit Dissector(v8::Local<v8::Object> option);

public:
  std::string script;
  std::string resourceName;
};

#endif
