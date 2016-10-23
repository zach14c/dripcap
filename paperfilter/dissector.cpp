#include "dissector.hpp"
#include <v8pp/object.hpp>

Dissector::Dissector(v8::Local<v8::Object> option) {
  v8::Isolate *isolate = v8::Isolate::GetCurrent();
  v8::Local<v8::Array> namespaceArray;
  if (v8pp::get_option(isolate, option, "namespaces", namespaceArray)) {
    for (uint32_t i = 0; i < namespaceArray->Length(); ++i) {
      v8::Local<v8::Value> ns = namespaceArray->Get(i);
      if (ns->IsString()) {
        namespaces.push_back(v8pp::from_v8<std::string>(isolate, ns, ""));
      } else if (ns->IsRegExp()) {
        regexNamespaces.push_back(std::regex(v8pp::from_v8<std::string>(
            isolate, ns.As<v8::RegExp>()->GetSource(), "")));
      }
    }
  }
  v8pp::get_option(isolate, option, "script", script);
  v8pp::get_option(isolate, option, "resourceName", resourceName);
}
