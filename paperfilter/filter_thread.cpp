#include "filter_thread.hpp"
#include "log_message.hpp"
#include "packet.hpp"
#include "packet_store.hpp"
#include "paper_context.hpp"
#include "console.hpp"
#include <cstdlib>
#include <nan.h>
#include <thread>
#include <v8pp/class.hpp>
#include <v8pp/json.hpp>
#include <v8pp/object.hpp>

namespace {
class ArrayBufferAllocator : public v8::ArrayBuffer::Allocator {
public:
  ArrayBufferAllocator() {}
  ~ArrayBufferAllocator() {}

  virtual void *Allocate(size_t size) { return calloc(1, size); }
  virtual void *AllocateUninitialized(size_t size) { return malloc(size); }
  virtual void Free(void *data, size_t) { free(data); }
};
}

class FilterThread::Private {
public:
  Private(const std::shared_ptr<Context> &ctx);
  ~Private();

public:
  std::thread thread;
  std::shared_ptr<Context> ctx;
  int storeHandlerId;
  bool closed = false;
};

FilterThread::Private::Private(const std::shared_ptr<Context> &ctx) : ctx(ctx) {
  storeHandlerId = ctx->store->addHandler(
      [this](uint32_t maxSeq) { this->ctx->cond.notify_all(); });

  thread = std::thread([this]() {
    Context &ctx = *this->ctx;

    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator = new ArrayBufferAllocator();
    v8::Isolate *isolate = v8::Isolate::New(create_params);

    // workaround for chromium task runner
    char dummyData[128] = {0};
    isolate->SetData(0, dummyData);

    {
      v8::Isolate::Scope isolate_scope(isolate);
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      v8::TryCatch try_catch;
      PaperContext::init(isolate);

      v8::Local<v8::Object> console =
          v8pp::class_<Console>::create_object(isolate, ctx.logCb, "filter");
      isolate->GetCurrentContext()->Global()->Set(
          v8pp::to_v8(isolate, "console"), console);

      v8::Local<v8::Value> filter = v8pp::json_parse(isolate, ctx.filter);
      v8::Local<v8::Object> moduleObj = v8::Object::New(isolate);
      context->Global()->Set(v8::String::NewFromUtf8(isolate, "module"),
                             moduleObj);

      v8::Local<v8::Function> func;
      Nan::MaybeLocal<Nan::BoundScript> script = Nan::CompileScript(
          v8pp::to_v8(isolate, "(function(){" + ctx.script + "})()"));

      if (!script.IsEmpty()) {
        Nan::RunScript(script.ToLocalChecked());
        v8::Local<v8::Value> result =
            moduleObj->Get(v8::String::NewFromUtf8(isolate, "exports"));

        if (!result.IsEmpty() && result->IsFunction()) {
          func = result.As<v8::Function>();
        }
      }

      if (func.IsEmpty()) {
        if (ctx.logCb) {
          ctx.logCb(LogMessage::fromMessage(try_catch.Message(), "filter"));
        }
      } else {
        v8::Handle<v8::Value> args[1] = {filter};
        v8::Local<v8::Value> result =
            func->Call(isolate->GetCurrentContext()->Global(), 1, args);
        if (!result.IsEmpty() && result->IsFunction()) {
          func = result.As<v8::Function>();
        }
      }

      if (func.IsEmpty()) {
        if (ctx.logCb) {
          ctx.logCb(LogMessage::fromMessage(try_catch.Message(), "filter"));
        }
      } else {
        while (true) {
          std::unique_lock<std::mutex> lock(ctx.mutex);
          ctx.cond.wait(lock, [this, &ctx] {
            return ctx.maxSeq < ctx.store->maxSeq() || closed;
          });
          if (closed)
            break;
          if (ctx.maxSeq < ctx.store->maxSeq()) {
            uint32_t seq = ++ctx.maxSeq;
            lock.unlock();
            const std::shared_ptr<Packet> &pkt = ctx.store->get(seq);
            lock.lock();

            v8::Handle<v8::Value> args[1] = {
                v8pp::class_<Packet>::reference_external(isolate, pkt.get())};
            v8::Local<v8::Value> result =
                func->Call(isolate->GetCurrentContext()->Global(), 1, args);

            v8pp::class_<Packet>::unreference_external(isolate, pkt.get());
            if (result.IsEmpty()) {
              if (ctx.logCb) {
                ctx.logCb(
                    LogMessage::fromMessage(try_catch.Message(), "filter"));
              }
            } else {
              ctx.packets.insert(pkt->seq(), result->BooleanValue());
            }
          }
        }
      }
    }

    isolate->Dispose();
  });
}

FilterThread::Private::~Private() {
  this->ctx->store->removeHandler(storeHandlerId);
  {
    std::unique_lock<std::mutex> lock(this->ctx->mutex);
    closed = true;
    this->ctx->cond.notify_all();
  }
  if (thread.joinable())
    thread.join();
}

FilterThread::FilterThread(const std::shared_ptr<Context> &ctx)
    : d(new Private(ctx)) {}

FilterThread::~FilterThread() {}
