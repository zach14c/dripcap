#ifndef SESSION_LARGE_BUFFER_WRAPPER_HPP
#define SESSION_LARGE_BUFFER_WRAPPER_HPP

#include "large_buffer.hpp"
#include <nan.h>
#include <v8pp/class.hpp>

class SessionLargeBufferWrapper : public Nan::ObjectWrap {
private:
  SessionLargeBufferWrapper(const LargeBuffer &buf) : buf(buf) {}
  SessionLargeBufferWrapper(const SessionLargeBufferWrapper &) = delete;
  SessionLargeBufferWrapper &
  operator=(const SessionLargeBufferWrapper &) = delete;

public:
  static NAN_MODULE_INIT(Init) {
    v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
    tpl->InstanceTemplate()->SetInternalFieldCount(1);
    tpl->SetClassName(Nan::New("LargeBuffer").ToLocalChecked());
    v8::Local<v8::ObjectTemplate> otl = tpl->InstanceTemplate();
    Nan::SetAccessor(otl, Nan::New("id").ToLocalChecked(), id);
    Nan::SetAccessor(otl, Nan::New("path").ToLocalChecked(), path);
    Nan::SetAccessor(otl, Nan::New("length").ToLocalChecked(), length);
    Nan::SetIndexedPropertyHandler(otl, get);
    constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
  }

  static NAN_METHOD(New) { info.GetReturnValue().Set(info.This()); }

  static inline Nan::Persistent<v8::Function> &constructor() {
    static Nan::Persistent<v8::Function> my_constructor;
    return my_constructor;
  }

  static NAN_GETTER(id) {
    SessionLargeBufferWrapper *wrapper =
        ObjectWrap::Unwrap<SessionLargeBufferWrapper>(info.Holder());
    info.GetReturnValue().Set(
        v8pp::to_v8(v8::Isolate::GetCurrent(), wrapper->buf.id()));
  }

  static NAN_GETTER(path) {
    SessionLargeBufferWrapper *wrapper =
        ObjectWrap::Unwrap<SessionLargeBufferWrapper>(info.Holder());
    info.GetReturnValue().Set(
        v8pp::to_v8(v8::Isolate::GetCurrent(), wrapper->buf.path()));
  }

  static NAN_GETTER(length) {
    SessionLargeBufferWrapper *wrapper =
        ObjectWrap::Unwrap<SessionLargeBufferWrapper>(info.Holder());
    info.GetReturnValue().Set(wrapper->buf.length());
  }

  static NAN_INDEX_GETTER(get) {
    SessionLargeBufferWrapper *wrapper =
        ObjectWrap::Unwrap<SessionLargeBufferWrapper>(info.Holder());
    wrapper->buf.get(index, info);
  }

  static v8::Local<v8::Object> create(const LargeBuffer &buf) {
    v8::Local<v8::Function> cons = Nan::New(constructor());
    v8::Local<v8::Value> argv[1] = {
        v8::Isolate::GetCurrent()->GetCurrentContext()->Global()};
    v8::Local<v8::Object> obj = cons->NewInstance(1, argv);
    SessionLargeBufferWrapper *wrapper = new SessionLargeBufferWrapper(buf);
    wrapper->Wrap(obj);
    return obj;
  }

private:
  LargeBuffer buf;
};

#endif
