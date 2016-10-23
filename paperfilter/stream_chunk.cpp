#include "stream_chunk.hpp"
#include "buffer.hpp"
#include "item_value.hpp"
#include "layer.hpp"
#include <v8pp/class.hpp>

using namespace v8;

class StreamChunk::Private {
public:
  std::string ns;
  std::string id;
  std::shared_ptr<Layer> layer;
  std::unordered_map<std::string, ItemValue> attrs;
  bool end = false;
};

StreamChunk::StreamChunk(const std::string &ns, const std::string &id,
                         v8::Local<v8::Object> obj)
    : d(std::make_shared<Private>()) {
  d->ns = ns;
  d->id = id;
  if (Layer *layer =
          v8pp::class_<Layer>::unwrap_object(v8::Isolate::GetCurrent(), obj)) {
    d->layer = std::make_shared<Layer>(*layer);
  }
}

StreamChunk::StreamChunk(const StreamChunk &stream) : d(stream.d) {}

StreamChunk::~StreamChunk() {}

std::string StreamChunk::ns() const { return d->ns; }

std::string StreamChunk::id() const { return d->id; }

std::shared_ptr<Layer> StreamChunk::layer() const { return d->layer; }

void StreamChunk::setLayer(const std::shared_ptr<Layer> &layer) {
  d->layer = layer;
}

void StreamChunk::setEnd(bool end) { d->end = end; }

bool StreamChunk::end() const { return d->end; }

void StreamChunk::setAttr(const std::string &name, v8::Local<v8::Object> obj) {
  Isolate *isolate = Isolate::GetCurrent();
  if (ItemValue *item = v8pp::class_<ItemValue>::unwrap_object(isolate, obj)) {
    d->attrs.emplace(name, *item);
  }
}

v8::Local<v8::Value> StreamChunk::attr(const std::string &name) const {
  const auto it = d->attrs.find(name);
  if (it == d->attrs.end())
    return v8::Local<v8::Value>();
  Isolate *isolate = Isolate::GetCurrent();
  return v8pp::class_<ItemValue>::import_external(isolate,
                                                  new ItemValue(it->second));
}
