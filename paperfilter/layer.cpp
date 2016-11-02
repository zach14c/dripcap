#include "layer.hpp"
#include "buffer.hpp"
#include "large_buffer.hpp"
#include "item.hpp"
#include <v8pp/class.hpp>

using namespace v8;

class Layer::Private {
public:
  std::string ns;
  std::string name;
  std::string alias;
  std::string summary;
  std::string extension;
  std::string range;
  std::unordered_map<std::string, std::shared_ptr<Layer>> layers;
  std::weak_ptr<Packet> pkt;
  std::vector<Item> items;
  std::unordered_map<std::string, ItemValue> attrs;
  std::unique_ptr<Buffer> payload;
  std::unique_ptr<LargeBuffer> largePayload;
};

Layer::Layer(const std::string &ns) : d(std::make_shared<Private>()) {
  d->ns = ns;
}

Layer::~Layer() {}

std::string Layer::ns() const { return d->ns; }

void Layer::setNs(const std::string &ns) { d->ns = ns; }

std::string Layer::name() const { return d->name; }

void Layer::setName(const std::string &name) { d->name = name; }

std::string Layer::alias() const { return d->alias; }

void Layer::setAlias(const std::string &alias) { d->alias = alias; }

std::string Layer::summary() const { return d->summary; };

void Layer::setSummary(const std::string &summary) { d->summary = summary; }

std::string Layer::extension() const { return d->extension; };

void Layer::setExtension(const std::string &extension) {
  d->extension = extension;
}

std::string Layer::range() const { return d->range; };

void Layer::setRange(const std::string &range) { d->range = range; }

void Layer::addLayer(const std::shared_ptr<Layer> &layer) {
  d->layers[layer->ns()] = std::move(layer);
}

std::unordered_map<std::string, std::shared_ptr<Layer>> &Layer::layers() const {
  return d->layers;
}

v8::Local<v8::Object> Layer::layersObject() const {
  Isolate *isolate = Isolate::GetCurrent();
  v8::Local<v8::Object> obj = v8::Object::New(isolate);
  for (const auto &pair : d->layers) {
    obj->Set(
        v8pp::to_v8(isolate, pair.first),
        v8pp::class_<Layer>::reference_external(isolate, pair.second.get()));
  }
  return obj;
}

void Layer::setPacket(const std::shared_ptr<Packet> &pkt) { d->pkt = pkt; }

std::shared_ptr<Packet> Layer::packet() const { return d->pkt.lock(); }

void Layer::addItem(v8::Local<v8::Object> obj) {
  Isolate *isolate = Isolate::GetCurrent();
  if (Item *item = v8pp::class_<Item>::unwrap_object(isolate, obj)) {
    d->items.emplace_back(*item);
  } else if (obj->IsObject()) {
    d->items.emplace_back(obj);
  }
}

std::vector<Item> Layer::items() const { return d->items; }

std::unique_ptr<Buffer> Layer::payload() const {
  if (d->payload) {
    return d->payload->slice();
  }
  return nullptr;
}

std::unique_ptr<LargeBuffer> Layer::largePayload() const {
  if (d->largePayload) {
    return std::unique_ptr<LargeBuffer>(new LargeBuffer(*d->largePayload));
  }
  return nullptr;
}

void Layer::setPayload(std::unique_ptr<Buffer> buffer) {
  if (buffer) {
    d->payload = buffer->slice();
  }
  d->largePayload.reset();
}

void Layer::setPayloadBuffer(v8::Local<v8::Object> obj) {
  Isolate *isolate = Isolate::GetCurrent();
  if (Buffer *buffer = v8pp::class_<Buffer>::unwrap_object(isolate, obj)) {
    d->payload = buffer->slice();
    d->largePayload.reset();
  } else if (LargeBuffer *buffer =
                 v8pp::class_<LargeBuffer>::unwrap_object(isolate, obj)) {
    d->largePayload.reset(new LargeBuffer(*buffer));
    d->payload.reset();
  }
}

v8::Local<v8::Object> Layer::payloadBuffer() const {
  Isolate *isolate = Isolate::GetCurrent();
  if (d->payload) {
    return v8pp::class_<Buffer>::import_external(isolate,
                                                 d->payload->slice().release());
  } else if (d->largePayload) {
    return v8pp::class_<LargeBuffer>::create_object(isolate, *d->largePayload);
  } else {
    return v8::Local<v8::Object>();
  }
}

void Layer::setAttr(const std::string &name, v8::Local<v8::Value> obj) {
  Isolate *isolate = Isolate::GetCurrent();
  if (ItemValue *item = v8pp::class_<ItemValue>::unwrap_object(isolate, obj)) {
    d->attrs.emplace(name, *item);
  } else {
    d->attrs.emplace(name, ItemValue(obj));
  }
}

std::unordered_map<std::string, ItemValue> Layer::attrs() const {
  return d->attrs;
}

v8::Local<v8::Value> Layer::attr(const std::string &name) const {
  const auto it = d->attrs.find(name);
  if (it == d->attrs.end())
    return v8::Local<v8::Value>();
  Isolate *isolate = Isolate::GetCurrent();
  return v8pp::class_<ItemValue>::import_external(isolate,
                                                  new ItemValue(it->second));
}
