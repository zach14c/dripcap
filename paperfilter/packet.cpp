#include "packet.hpp"
#include "buffer.hpp"
#include "large_buffer.hpp"
#include "layer.hpp"
#include "session_item_value_wrapper.hpp"
#include <chrono>
#include <ctime>
#include <node_buffer.h>
#include <pcap.h>
#include <v8pp/class.hpp>
#include <v8pp/object.hpp>

namespace {
std::shared_ptr<Layer> leafLayer(
    const std::unordered_map<std::string, std::shared_ptr<Layer>> &layers) {
  if (layers.empty())
    return std::shared_ptr<Layer>();
  const std::shared_ptr<Layer> &layer = layers.begin()->second;
  const std::shared_ptr<Layer> &child = leafLayer(layer->layers());
  if (child) {
    return child;
  } else {
    return layer;
  }
}

void getAttrs(
    const std::unordered_map<std::string, std::shared_ptr<Layer>> &layers,
    std::unordered_map<std::string, ItemValue> *values) {
  for (const auto &pair : layers) {
    getAttrs(pair.second->layers(), values);
  }
  for (const auto &pair : layers) {
    const std::shared_ptr<Layer> &layer = pair.second;
    const std::unordered_map<std::string, ItemValue> &attrs = layer->attrs();
    for (const auto &vpair : attrs) {
      if (values->count(vpair.first) == 0) {
        values->insert(vpair);
      }
    }
  }
}
}

using namespace v8;

class Packet::Private {
public:
  Private();
  ~Private();

public:
  uint32_t seq = 0;
  uint32_t ts_sec = std::chrono::seconds(std::time(NULL)).count();
  uint32_t ts_nsec = 0;
  uint32_t length = 0;
  std::string summary;
  std::string extension;
  std::unique_ptr<Buffer> payload;
  std::unique_ptr<LargeBuffer> largePayload;
  std::unordered_map<std::string, std::shared_ptr<Layer>> layers;
};

Packet::Private::Private() {}

Packet::Private::~Private() {}

Packet::Packet(v8::Local<v8::Object> option) : d(new Private()) {
  Isolate *isolate = Isolate::GetCurrent();
  v8pp::get_option(isolate, option, "ts_sec", d->ts_sec);
  v8pp::get_option(isolate, option, "ts_nsec", d->ts_nsec);
  v8pp::get_option(isolate, option, "summary", d->summary);
  v8pp::get_option(isolate, option, "extension", d->extension);
  v8pp::get_option(isolate, option, "length", d->length);
  Local<Value> payload = option->Get(v8pp::to_v8(isolate, "payload"));
  if (node::Buffer::HasInstance(payload)) {
    auto buffer = std::make_shared<std::vector<char>>();
    buffer->assign(node::Buffer::Data(payload),
                   node::Buffer::Data(payload) + node::Buffer::Length(payload));
    d->payload.reset(new Buffer(buffer));
    d->payload->freeze();
  }
}

Packet::Packet(std::unique_ptr<Layer> layer) : d(new Private()) {
  if (std::unique_ptr<Buffer> payload = layer->payload()) {
    d->payload = std::move(payload);
    d->payload->freeze();
    d->length = d->payload->length();
  } else if (std::unique_ptr<LargeBuffer> payload = layer->largePayload()) {
    d->largePayload = std::move(payload);
    d->length = d->largePayload->length();
  }
  addLayer(std::make_shared<Layer>(*layer));
}

Packet::Packet(const struct pcap_pkthdr *h, const uint8_t *bytes)
    : d(new Private()) {
  d->ts_sec = h->ts.tv_sec;
  d->ts_nsec = h->ts.tv_usec;
  d->length = h->len;
  auto buffer = std::make_shared<std::vector<char>>();
  buffer->assign(bytes, bytes + h->caplen);
  d->payload.reset(new Buffer(buffer));
  d->payload->freeze();
}

Packet::~Packet() {}

uint32_t Packet::seq() const { return d->seq; }

void Packet::setSeq(uint32_t id) { d->seq = id; }

uint32_t Packet::ts_sec() const { return d->ts_sec; }

uint32_t Packet::ts_nsec() const { return d->ts_nsec; }

std::string Packet::summary() const { return d->summary; }

std::string Packet::extension() const { return d->extension; }

uint32_t Packet::length() const { return d->length; }

std::unique_ptr<Buffer> Packet::payload() const {
  if (d->payload) {
    return d->payload->slice();
  }
  return nullptr;
}

std::unique_ptr<LargeBuffer> Packet::largePayload() const {
  if (d->largePayload) {
    return std::unique_ptr<LargeBuffer>(new LargeBuffer(*d->largePayload));
  }
  return nullptr;
}

std::string Packet::name() const {
  const std::shared_ptr<Layer> &leaf = leafLayer(layers());
  if (leaf) {
    if (leaf->name().empty()) {
      return leaf->ns();
    } else {
      return leaf->name();
    }
  } else {
    return std::string();
  }
}

std::string Packet::ns() const {
  const std::shared_ptr<Layer> &leaf = leafLayer(layers());
  if (leaf) {
    return leaf->ns();
  } else {
    return std::string();
  }
}

v8::Local<v8::Value> Packet::timestamp() const {
  Isolate *isolate = Isolate::GetCurrent();
  return v8::Date::New(isolate, (d->ts_sec * 1000.0) + (d->ts_nsec / 1000.0));
}

v8::Local<v8::Object> Packet::attrs() const {
  Isolate *isolate = Isolate::GetCurrent();
  std::unordered_map<std::string, ItemValue> values;
  getAttrs(layers(), &values);

  v8::Local<v8::Object> obj = v8::Object::New(isolate);
  for (const auto &pair : values) {
    obj->Set(v8pp::to_v8(isolate, pair.first),
             SessionItemValueWrapper::create(pair.second));
  }
  return obj;
}

v8::Local<v8::Object> Packet::payloadBuffer() const {
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

void Packet::addLayer(const std::shared_ptr<Layer> &layer) {
  d->layers[layer->ns()] = layer;
}

const std::unordered_map<std::string, std::shared_ptr<Layer>> &
Packet::layers() const {
  return d->layers;
}

v8::Local<v8::Object> Packet::layersObject() const {
  Isolate *isolate = Isolate::GetCurrent();
  v8::Local<v8::Object> obj = v8::Object::New(isolate);
  for (const auto &pair : d->layers) {
    obj->Set(
        v8pp::to_v8(isolate, pair.first),
        v8pp::class_<Layer>::reference_external(isolate, pair.second.get()));
  }
  return obj;
}
