#include "dissector.hpp"
#include <v8pp/object.hpp>

Dissector::Dissector(v8::Local<v8::Object> option) {
  v8::Isolate *isolate = v8::Isolate::GetCurrent();
  v8pp::get_option(isolate, option, "script", script);
  v8pp::get_option(isolate, option, "resourceName", resourceName);
}
