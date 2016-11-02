#include "paper_context.hpp"
#include "buffer.hpp"
#include "item.hpp"
#include "item_value.hpp"
#include "large_buffer.hpp"
#include "layer.hpp"
#include "packet.hpp"
#include "console.hpp"
#include "stream_chunk.hpp"
#include <v8pp/class.hpp>
#include <v8pp/module.hpp>

using namespace v8;

namespace {
void initModule(v8pp::module *module, v8::Isolate *isolate) {
  v8pp::class_<Console> Console_class(isolate);
  Console_class.set("log", &Console::log);
  Console_class.set("debug", &Console::debug);
  Console_class.set("warn", &Console::warn);

  v8pp::class_<Packet> Packet_class(isolate);
  Packet_class.set("seq", v8pp::property(&Packet::seq));
  Packet_class.set("ts_sec", v8pp::property(&Packet::ts_sec));
  Packet_class.set("ts_nsec", v8pp::property(&Packet::ts_nsec));
  Packet_class.set("length", v8pp::property(&Packet::length));
  Packet_class.set("payload", v8pp::property(&Packet::payloadBuffer));
  Packet_class.set("layers", v8pp::property(&Packet::layersObject));

  v8pp::class_<Buffer> Buffer_class(isolate);
  Buffer_class.ctor<const v8::FunctionCallbackInfo<v8::Value> &>();
  Buffer_class.set("from", &Buffer::from);
  Buffer_class.set("isBuffer", &Buffer::isBuffer);
  Buffer_class.set("length", v8pp::property(&Buffer::length));
  Buffer_class.set("slice", &Buffer::sliceBuffer);
  Buffer_class.set("toString", &Buffer::toString);
  Buffer_class.set("valueOf", &Buffer::valueOf);
  Buffer_class.set("indexOf", &Buffer::indexOf);
  Buffer_class.set("readInt8", &Buffer::readInt8);
  Buffer_class.set("readInt16BE", &Buffer::readInt16BE);
  Buffer_class.set("readInt32BE", &Buffer::readInt32BE);
  Buffer_class.set("readUInt8", &Buffer::readUInt8);
  Buffer_class.set("readUInt16BE", &Buffer::readUInt16BE);
  Buffer_class.set("readUInt32BE", &Buffer::readUInt32BE);

  Buffer_class.class_function_template()
      ->PrototypeTemplate()
      ->SetIndexedPropertyHandler(
          [](uint32_t index, const PropertyCallbackInfo<Value> &info) {
            Buffer *buffer = v8pp::class_<Buffer>::unwrap_object(
                Isolate::GetCurrent(), info.This());
            if (buffer) {
              buffer->get(index, info);
            }
          });

  v8pp::class_<Layer> Layer_class(isolate);
  Layer_class.ctor<const std::string &>();
  Layer_class.set("namespace", v8pp::property(&Layer::ns, &Layer::setNs));
  Layer_class.set("name", v8pp::property(&Layer::name, &Layer::setName));
  Layer_class.set("alias", v8pp::property(&Layer::alias, &Layer::setAlias));
  Layer_class.set("summary",
                  v8pp::property(&Layer::summary, &Layer::setSummary));
  Layer_class.set("extension",
                  v8pp::property(&Layer::extension, &Layer::setExtension));
  Layer_class.set("range", v8pp::property(&Layer::range, &Layer::setRange));
  Layer_class.set("payload", v8pp::property(&Layer::payloadBuffer,
                                            &Layer::setPayloadBuffer));
  Layer_class.set("layers", v8pp::property(&Layer::layersObject));
  Layer_class.set("addItem", &Layer::addItem);
  Layer_class.set("attr", &Layer::attr);
  Layer_class.set("setAttr", &Layer::setAttr);

  v8pp::class_<Item> Item_class(isolate);
  Item_class.ctor<const v8::FunctionCallbackInfo<v8::Value> &>();
  Item_class.set("name", v8pp::property(&Item::name, &Item::setName));
  Item_class.set("range", v8pp::property(&Item::range, &Item::setRange));
  Item_class.set("value", v8pp::property(&Item::valueObject, &Item::setValue));
  Item_class.set("addItem", &Item::addItem);
  Item_class.set("attr", &Item::attr);
  Item_class.set("setAttr", &Item::setAttr);

  v8pp::class_<ItemValue> ItemValue_class(isolate);
  ItemValue_class.ctor<const v8::FunctionCallbackInfo<v8::Value> &>();
  ItemValue_class.set("data", v8pp::property(&ItemValue::data));
  ItemValue_class.set("type", v8pp::property(&ItemValue::type));

  v8pp::class_<StreamChunk> StreamChunk_class(isolate);
  StreamChunk_class
      .ctor<const std::string &, const std::string &, v8::Local<v8::Object>>();
  StreamChunk_class.set("namespace", v8pp::property(&StreamChunk::ns));
  StreamChunk_class.set("id", v8pp::property(&StreamChunk::id));
  StreamChunk_class.set("attr", &StreamChunk::attr);
  StreamChunk_class.set("setAttr", &StreamChunk::setAttr);
  StreamChunk_class.set(
      "end", v8pp::property(&StreamChunk::end, &StreamChunk::setEnd));

  v8pp::class_<LargeBuffer> LargeBuffer_class(isolate);
  LargeBuffer_class.ctor<>();
  LargeBuffer_class.set("write", &LargeBuffer::write);
  LargeBuffer_class.set("length", v8pp::property(&LargeBuffer::length));

  module->set("Buffer", Buffer_class);
  module->set("Layer", Layer_class);
  module->set("Item", Item_class);
  module->set("Value", ItemValue_class);
  module->set("StreamChunk", StreamChunk_class);
  module->set("LargeBuffer", LargeBuffer_class);
}
}

void PaperContext::init(v8::Isolate *isolate) {
  v8pp::module dripcap(isolate);
  initModule(&dripcap, isolate);
  Local<FunctionTemplate> require = FunctionTemplate::New(
      isolate, [](FunctionCallbackInfo<Value> const &args) {
        Isolate *isolate = Isolate::GetCurrent();
        const std::string &name =
            v8pp::from_v8<std::string>(isolate, args[0], "");
        if (name == "dripcap") {
          args.GetReturnValue().Set(args.Data());
        } else {
          std::string err("Cannot find module '");
          args.GetReturnValue().Set(
              v8pp::throw_ex(isolate, (err + name + "'").c_str()));
        }
      }, dripcap.new_instance());

  isolate->GetCurrentContext()->Global()->Set(v8pp::to_v8(isolate, "require"),
                                              require->GetFunction());
}

void PaperContext::init(v8::Local<v8::Object> module) {
  Isolate *isolate = Isolate::GetCurrent();
  v8pp::module dripcap(isolate);
  initModule(&dripcap, isolate);
  module->Set(v8pp::to_v8(isolate, "exports"), dripcap.new_instance());
}
