#include "dissector_thread.hpp"
#include "log_message.hpp"
#include "console.hpp"
#include "layer.hpp"
#include "packet.hpp"
#include "packet_queue.hpp"
#include "paper_context.hpp"
#include "stream_chunk.hpp"
#include <cstdlib>
#include <nan.h>
#include <thread>
#include <unordered_set>
#include <v8.h>
#include <v8pp/class.hpp>
#include <v8pp/object.hpp>

using namespace v8;

namespace {
class ArrayBufferAllocator : public v8::ArrayBuffer::Allocator {
public:
  ArrayBufferAllocator() {}
  ~ArrayBufferAllocator() {}

  virtual void *Allocate(size_t size) { return malloc(size); }
  virtual void *AllocateUninitialized(size_t size) { return malloc(size); }
  virtual void Free(void *data, size_t) { free(data); }
};

struct DissectorFunc {
  std::vector<std::string> namespaces;
  std::vector<std::regex> regexNamespaces;
  v8::UniquePersistent<v8::Function> func;
};
}

class DissectorThread::Private {
public:
  Private(const std::shared_ptr<Context> &ctx);
  ~Private();
  const std::vector<const DissectorFunc *> &findDessector(
      const std::string &ns, const std::vector<DissectorFunc> &dissectors,
      std::unordered_map<std::string, std::vector<const DissectorFunc *>>
          *nsMap);

public:
  std::thread thread;
  std::shared_ptr<Context> ctx;
};

DissectorThread::Private::Private(const std::shared_ptr<Context> &ctx)
    : ctx(ctx) {
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
          v8pp::class_<Console>::create_object(isolate, ctx.logCb, "dissector");
      isolate->GetCurrentContext()->Global()->Set(
          v8pp::to_v8(isolate, "console"), console);

      std::vector<DissectorFunc> dissectors;
      std::unordered_map<std::string, std::vector<const DissectorFunc *>> nsMap;

      for (const Dissector &diss : ctx.dissectors) {
        v8::Local<v8::Object> moduleObj = v8::Object::New(isolate);
        context->Global()->Set(v8::String::NewFromUtf8(isolate, "module"),
                               moduleObj);

        v8::Local<v8::Function> func;
        Nan::MaybeLocal<Nan::BoundScript> script = Nan::CompileScript(
            v8pp::to_v8(isolate, "(function(){" + diss.script + "})()"),
            v8::ScriptOrigin(v8pp::to_v8(isolate, diss.resourceName)));
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
            ctx.logCb(
                LogMessage::fromMessage(try_catch.Message(), "dissector"));
          }
        } else {
          v8::Local<v8::Array> namespaces;
          std::vector<std::string> stringNamespaces;
          std::vector<std::regex> regexNamespaces;

          if (v8pp::get_option(isolate, func, "namespaces", namespaces)) {
            for (uint32_t i = 0; i < namespaces->Length(); ++i) {
              v8::Local<v8::Value> ns = namespaces->Get(i);
              if (ns->IsString()) {
                stringNamespaces.push_back(
                    v8pp::from_v8<std::string>(isolate, ns, ""));
              } else if (ns->IsRegExp()) {
                regexNamespaces.push_back(std::regex(v8pp::from_v8<std::string>(
                    isolate, ns.As<v8::RegExp>()->GetSource(), "")));
              }
            }
          }

          dissectors.push_back(
              {stringNamespaces, regexNamespaces,
               v8::UniquePersistent<v8::Function>(isolate, func)});
        }
      }

      while (true) {
        auto pkt = ctx.queue->pop();
        if (!pkt)
          return;

        v8::Local<v8::Object> packetObj =
            v8pp::class_<Packet>::reference_external(isolate, pkt.get());

        std::unordered_map<std::string, std::shared_ptr<Layer>> layers =
            pkt->layers();

        std::unordered_set<std::string> usedNs;
        std::vector<std::unique_ptr<StreamChunk>> streams;

        while (!layers.empty()) {
          std::unordered_map<std::string, std::shared_ptr<Layer>> nextLayers;

          for (const auto &pair : layers) {
            usedNs.insert(pair.first);
            pair.second->setPacket(pkt);

            for (const DissectorFunc *diss :
                 findDessector(pair.first, dissectors, &nsMap)) {
              v8::Local<v8::Function> func =
                  v8::Local<v8::Function>::New(isolate, diss->func);
              v8::Local<v8::Object> obj = func->NewInstance();
              if (obj.IsEmpty()) {
                if (ctx.logCb) {
                  ctx.logCb(LogMessage::fromMessage(try_catch.Message(),
                                                    "dissector"));
                }
              } else {
                v8::Local<v8::Value> analyze =
                    obj->Get(v8pp::to_v8(isolate, "analyze"));
                if (!analyze.IsEmpty() && analyze->IsFunction()) {
                  v8::Local<v8::Function> analyzeFunc =
                      analyze.As<v8::Function>();
                  v8::Local<v8::Object> layerObj =
                      v8pp::class_<Layer>::reference_external(
                          isolate, pair.second.get());
                  v8::Handle<v8::Value> args[2] = {packetObj, layerObj};
                  v8::Local<v8::Value> result = analyzeFunc->Call(
                      isolate->GetCurrentContext()->Global(), 2, args);

                  v8pp::class_<Layer>::unreference_external(isolate,
                                                            pair.second.get());

                  std::vector<std::shared_ptr<Layer>> childLayers;

                  if (result.IsEmpty()) {
                    if (ctx.logCb) {
                      ctx.logCb(LogMessage::fromMessage(try_catch.Message(),
                                                        "dissector"));
                    }
                  } else if (result->IsArray()) {
                    v8::Local<v8::Array> array = result.As<v8::Array>();
                    for (uint32_t i = 0; i < array->Length(); ++i) {
                      if (Layer *layer = v8pp::class_<Layer>::unwrap_object(
                              isolate, array->Get(i))) {
                        childLayers.push_back(std::make_shared<Layer>(*layer));
                      } else if (StreamChunk *stream =
                                     v8pp::class_<StreamChunk>::unwrap_object(
                                         isolate, array->Get(i))) {
                        auto chunk = std::unique_ptr<StreamChunk>(
                            new StreamChunk(*stream));
                        if (!chunk->layer()) {
                          chunk->setLayer(pair.second);
                        }
                        streams.push_back(std::move(chunk));
                      }
                    }
                  } else if (Layer *layer = v8pp::class_<Layer>::unwrap_object(
                                 isolate, result)) {
                    childLayers.push_back(std::make_shared<Layer>(*layer));
                  } else if (StreamChunk *stream =
                                 v8pp::class_<StreamChunk>::unwrap_object(
                                     isolate, result)) {
                    auto chunk =
                        std::unique_ptr<StreamChunk>(new StreamChunk(*stream));
                    if (!chunk->layer()) {
                      chunk->setLayer(pair.second);
                    }
                    streams.push_back(std::move(chunk));
                  }

                  for (const auto &child : childLayers) {
                    nextLayers[child->ns()] = child;
                    pair.second->layers()[child->ns()] = child;
                  }
                }
              }
            }
          }

          for (const std::string &ns : usedNs) {
            nextLayers.erase(ns);
          }
          nextLayers.swap(layers);
        }

        v8pp::class_<Packet>::unreference_external(isolate, pkt.get());

        uint32_t seq = pkt->seq();

        if (ctx.packetCb)
          ctx.packetCb(pkt);

        if (ctx.streamsCb)
          ctx.streamsCb(seq, std::move(streams));
      }
    }

    isolate->Dispose();
  });
}

DissectorThread::Private::~Private() {
  if (thread.joinable())
    thread.join();
}

const std::vector<const DissectorFunc *> &
DissectorThread::Private::findDessector(
    const std::string &ns, const std::vector<DissectorFunc> &dissectors,
    std::unordered_map<std::string, std::vector<const DissectorFunc *>>
        *nsMap) {
  static const std::vector<DissectorFunc *> null;

  auto it = nsMap->find(ns);
  if (it != nsMap->end())
    return it->second;

  std::vector<const DissectorFunc *> &funcs = (*nsMap)[ns];
  for (const auto &diss : dissectors) {
    for (const std::string &dissNs : diss.namespaces) {
      if (dissNs == ns) {
        funcs.push_back(&diss);
        break;
      }
    }
    if (funcs.empty()) {
      for (const std::regex &regex : diss.regexNamespaces) {
        if (std::regex_match(ns, regex)) {
          funcs.push_back(&diss);
          break;
        }
      }
    }
  }

  return funcs;
}

DissectorThread::DissectorThread(const std::shared_ptr<Context> &ctx)
    : d(new Private(ctx)) {}

DissectorThread::~DissectorThread() {}
