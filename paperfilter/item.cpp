#include "item.hpp"
#include "item_value.hpp"
#include <v8pp/class.hpp>
#include <v8pp/object.hpp>
#include <vector>

using namespace v8;

class Item::Private {
public:
  std::string name;
  std::string range;
  ItemValue value;
  std::vector<Item> children;
  std::unordered_map<std::string, ItemValue> attrs;
};

Item::Item() : d(new Private()) {}

Item::Item(const v8::FunctionCallbackInfo<v8::Value> &args) : Item(args[0]) {}

Item::Item(v8::Local<v8::Value> value) : d(new Private()) {
  Isolate *isolate = Isolate::GetCurrent();
  if (!value.IsEmpty() && value->IsObject()) {
    v8::Local<v8::Object> obj = value.As<v8::Object>();
    v8pp::get_option(isolate, obj, "name", d->name);
    v8pp::get_option(isolate, obj, "range", d->range);

    v8::Local<v8::Object> value;
    if (v8pp::get_option(isolate, obj, "value", value)) {
      setValue(value);
    }

    v8::Local<v8::Array> children;
    if (v8pp::get_option(isolate, obj, "children", children)) {
      for (uint32_t i = 0; i < children->Length(); ++i) {
        v8::Local<v8::Value> child = children->Get(i);
        if (child->IsObject())
          addChild(child.As<v8::Object>());
      }
    }
  }
}

Item::Item(const Item &item) : d(new Private(*item.d)) {}

Item::~Item() {}

std::string Item::name() const { return d->name; }

void Item::setName(const std::string &name) { d->name = name; }

std::string Item::range() const { return d->range; }

void Item::setRange(const std::string &range) { d->range = range; }

v8::Local<v8::Object> Item::valueObject() const {
  Isolate *isolate = Isolate::GetCurrent();
  return v8pp::class_<ItemValue>::import_external(isolate,
                                                  new ItemValue(d->value));
}

ItemValue Item::value() const { return d->value; }

void Item::setValue(v8::Local<v8::Object> value) {
  Isolate *isolate = Isolate::GetCurrent();
  if (ItemValue *iv = v8pp::class_<ItemValue>::unwrap_object(isolate, value)) {
    d->value = *iv;
  }
}

std::vector<Item> Item::children() const { return d->children; }

void Item::addChild(v8::Local<v8::Object> obj) {
  Isolate *isolate = Isolate::GetCurrent();
  if (Item *item = v8pp::class_<Item>::unwrap_object(isolate, obj)) {
    d->children.emplace_back(*item);
  } else if (obj->IsObject()) {
    d->children.emplace_back(obj);
  }
}

void Item::setAttrObject(const std::string &name, v8::Local<v8::Object> obj) {
  Isolate *isolate = Isolate::GetCurrent();
  if (ItemValue *item = v8pp::class_<ItemValue>::unwrap_object(isolate, obj)) {
    d->attrs.emplace(name, *item);
  }
}

std::unordered_map<std::string, ItemValue> Item::attrs() const {
  return d->attrs;
}

v8::Local<v8::Value> Item::attr(const std::string &name) const {
  const auto it = d->attrs.find(name);
  if (it == d->attrs.end())
    return v8::Local<v8::Value>();
  Isolate *isolate = Isolate::GetCurrent();
  return v8pp::class_<ItemValue>::import_external(isolate,
                                                  new ItemValue(it->second));
}
