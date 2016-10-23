#ifndef PAPER_CONTEXT_HPP
#define PAPER_CONTEXT_HPP

#include <v8.h>

class PaperContext {
public:
  static void init(v8::Isolate *isolate);
  static void init(v8::Local<v8::Object> module);
};

#endif
