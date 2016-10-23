#include "paper_context.hpp"
#include <nan.h>

void Init(v8::Local<v8::Object> exports, v8::Local<v8::Object> module) {
  PaperContext::init(module);
}

NODE_MODULE(paperfilter_internal, Init)
