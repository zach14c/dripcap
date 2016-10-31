#include "filter_thread.hpp"
#include "log_message.hpp"
#include "packet.hpp"
#include "layer.hpp"
#include "item_value.hpp"
#include "packet_store.hpp"
#include "paper_context.hpp"
#include "console.hpp"
#include <cstdlib>
#include <nan.h>
#include <thread>
#include <v8pp/class.hpp>
#include <v8pp/json.hpp>
#include <v8pp/object.hpp>
#include <json11.hpp>

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

typedef std::function<v8::Local<v8::Value>(const Packet &)> FilterFunc;

class FilterThread::Private {
public:
  Private(const std::shared_ptr<Context> &ctx);
  ~Private();
  FilterFunc makeFilter(const json11::Json &json) const;

public:
  std::thread thread;
  std::shared_ptr<Context> ctx;
  int storeHandlerId;
  bool closed = false;
};

FilterFunc FilterThread::Private::makeFilter(const json11::Json &json) const {
  v8::Isolate *isolate = v8::Isolate::GetCurrent();

  const std::string &type = json["type"].string_value();

  if (type == "MemberExpression") {
    const json11::Json &property = json["property"];
    const std::string &propertyType = property["type"].string_value();
    FilterFunc propertyFunc;

    if (propertyType == "Identifier") {
      const std::string &name = property["name"].string_value();
      propertyFunc = [isolate, name](const Packet &) {
        return v8pp::to_v8(isolate, name);
      };
    } else {
      propertyFunc = makeFilter(property);
    }

    const FilterFunc &objectFunc = makeFilter(json["object"]);

    return FilterFunc([isolate, objectFunc, propertyFunc](
                          const Packet &pkt) -> v8::Local<v8::Value> {
      v8::Local<v8::Value> object = objectFunc(pkt);
      v8::Local<v8::Value> property = propertyFunc(pkt);

      const std::string &name =
          v8pp::from_v8<std::string>(isolate, property, "");
      if (name.empty())
        return v8::Null(isolate);

      if (const Layer *layer =
              v8pp::class_<Layer>::unwrap_object(isolate, object)) {
        const std::unordered_map<std::string, ItemValue> &attrs =
            layer->attrs();
        const auto it = attrs.find(name);
        if (it != attrs.end()) {
          return it->second.data();
        }
      }

      return v8::Null(isolate);
    });
  } else if (type == "BinaryExpression") {
    const FilterFunc &lf = makeFilter(json["left"]);
    const FilterFunc &rf = makeFilter(json["right"]);
    const std::string &op = json["operator"].string_value();
    if (op == ">") {
      return FilterFunc([isolate, lf, rf](const Packet &pkt) {
        return v8::Boolean::New(isolate, lf(pkt)->NumberValue() >
                                             rf(pkt)->NumberValue());
      });
    } else if (op == "==") {
      return FilterFunc([isolate, lf, rf](const Packet &pkt) {
        return v8::Boolean::New(isolate, lf(pkt)->Equals(rf(pkt)));
      });
    }
  } else if (type == "Literal") {
    const json11::Json &regex = json["regex"];
    if (regex.is_object()) {
      const std::string &value = json["value"].string_value();
      return FilterFunc(
          [isolate, value](const Packet &pkt) -> v8::Local<v8::Value> {
            Nan::MaybeLocal<Nan::BoundScript> script =
                Nan::CompileScript(v8pp::to_v8(isolate, value));
            if (!script.IsEmpty()) {
              Nan::MaybeLocal<v8::Value> result =
                  Nan::RunScript(script.ToLocalChecked());
              if (!result.IsEmpty()) {
                return result.ToLocalChecked();
              }
            }
            return v8::Null(isolate);
          });
    } else {
      const std::string &value = json["value"].dump();
      return FilterFunc(
          [isolate, value](const Packet &pkt) -> v8::Local<v8::Value> {
            return v8pp::json_parse(isolate, value);
          });
    }
  } else if (type == "Identifier") {
    const std::string &name = json["name"].string_value();
    return FilterFunc([isolate,
                       name](const Packet &pkt) -> v8::Local<v8::Value> {
      std::function<std::shared_ptr<Layer>(
          const std::string &name,
          const std::unordered_map<std::string, std::shared_ptr<Layer>> &)>
          findLayer;
      findLayer = [&findLayer](
          const std::string &name,
          const std::unordered_map<std::string, std::shared_ptr<Layer>>
              &layers) {
        for (const auto &pair : layers) {
          if (pair.second->alias() == name) {
            return pair.second;
          }
        }
        for (const auto &pair : layers) {
          const std::shared_ptr<Layer> &layer =
              findLayer(name, pair.second->layers());
          if (layer) {
            return layer;
          }
        }
        return std::shared_ptr<Layer>();
      };
      const std::shared_ptr<Layer> &layer = findLayer(name, pkt.layers());
      if (layer) {
        return v8pp::class_<Layer>::reference_external(isolate, layer.get());
      }
      return v8::Null(isolate);
    });
  }

  return FilterFunc([isolate](const Packet &) { return v8::Null(isolate); });
}

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

      std::string err;
      json11::Json json = json11::Json::parse(ctx.filter, err);
      const FilterFunc &func = makeFilter(json);

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
          v8::Local<v8::Value> result = func(*pkt);

          v8::String::Utf8Value utf8(result);
          printf(">>> %s\n", *utf8);
          lock.lock();
          ctx.packets.insert(pkt->seq(), result->BooleanValue());
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
