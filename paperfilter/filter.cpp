#include "filter.hpp"
#include "layer.hpp"
#include "packet.hpp"
#include "item_value.hpp"
#include <json11.hpp>
#include <nan.h>
#include <v8pp/class.hpp>
#include <v8pp/json.hpp>
#include <v8pp/object.hpp>

FilterFunc makeFilter(const json11::Json &json) {
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

FilterFunc makeFilter(const std::string &jsonstr) {
  std::string err;
  json11::Json json = json11::Json::parse(jsonstr, err);
  return makeFilter(json);
}
