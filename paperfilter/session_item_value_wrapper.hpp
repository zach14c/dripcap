#ifndef SESSION_ITEM_VALUE_WRAPPER_HPP
#define SESSION_ITEM_VALUE_WRAPPER_HPP

#include "item_value.hpp"
#include <nan.h>
#include <v8pp/class.hpp>

class SessionItemValueWrapper : public Nan::ObjectWrap {
private:
  SessionItemValueWrapper(const ItemValue &value) : value(value) {}
  SessionItemValueWrapper(const SessionItemValueWrapper &) = delete;
  SessionItemValueWrapper &operator=(const SessionItemValueWrapper &) = delete;

public:
  static NAN_MODULE_INIT(Init) {
    v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
    tpl->InstanceTemplate()->SetInternalFieldCount(1);
    tpl->SetClassName(Nan::New("Item").ToLocalChecked());
    v8::Local<v8::ObjectTemplate> otl = tpl->InstanceTemplate();
    Nan::SetAccessor(otl, Nan::New("data").ToLocalChecked(), data);
    Nan::SetAccessor(otl, Nan::New("type").ToLocalChecked(), type);
    constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
  }

  static NAN_METHOD(New) { info.GetReturnValue().Set(info.This()); }

  static inline Nan::Persistent<v8::Function> &constructor() {
    static Nan::Persistent<v8::Function> my_constructor;
    return my_constructor;
  }

  static NAN_GETTER(data) {
    SessionItemValueWrapper *wrapper =
        ObjectWrap::Unwrap<SessionItemValueWrapper>(info.Holder());
    info.GetReturnValue().Set(wrapper->value.data());
  }

  static NAN_GETTER(type) {
    SessionItemValueWrapper *wrapper =
        ObjectWrap::Unwrap<SessionItemValueWrapper>(info.Holder());
    info.GetReturnValue().Set(
        v8pp::to_v8(v8::Isolate::GetCurrent(), wrapper->value.type()));
  }

  static v8::Local<v8::Object> create(const ItemValue &value) {
    v8::Local<v8::Function> cons = Nan::New(constructor());
    v8::Local<v8::Value> argv[1] = {
        v8::Isolate::GetCurrent()->GetCurrentContext()->Global()};
    v8::Local<v8::Object> obj = cons->NewInstance(1, argv);
    SessionItemValueWrapper *wrapper = new SessionItemValueWrapper(value);
    wrapper->Wrap(obj);
    return obj;
  }

private:
  ItemValue value;
};

#endif
