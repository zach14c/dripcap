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
    } else if (op == "<") {
      return FilterFunc([isolate, lf, rf](const Packet &pkt) {
        return v8::Boolean::New(isolate, lf(pkt)->NumberValue() <
                                             rf(pkt)->NumberValue());
      });
    } else if (op == ">=") {
      return FilterFunc([isolate, lf, rf](const Packet &pkt) {
        return v8::Boolean::New(isolate, lf(pkt)->NumberValue() >=
                                             rf(pkt)->NumberValue());
      });
    } else if (op == "<=") {
      return FilterFunc([isolate, lf, rf](const Packet &pkt) {
        return v8::Boolean::New(isolate, lf(pkt)->NumberValue() <=
                                             rf(pkt)->NumberValue());
      });
    } else if (op == "==") {
      return FilterFunc([isolate, lf, rf](const Packet &pkt) {
        return v8::Boolean::New(isolate, lf(pkt)->Equals(rf(pkt)));
      });
    } else if (op == "!=") {
      return FilterFunc([isolate, lf, rf](const Packet &pkt) {
        return v8::Boolean::New(isolate, !lf(pkt)->Equals(rf(pkt)));
      });
    } else if (op == "+") {
      return FilterFunc([isolate, lf, rf](const Packet &pkt) {
        return v8::Number::New(isolate,
                               lf(pkt)->NumberValue() + rf(pkt)->NumberValue());
      });
    } else if (op == "-") {
      return FilterFunc([isolate, lf, rf](const Packet &pkt) {
        return v8::Number::New(isolate,
                               lf(pkt)->NumberValue() + rf(pkt)->NumberValue());
      });
    } else if (op == "*") {
      return FilterFunc([isolate, lf, rf](const Packet &pkt) {
        return v8::Number::New(isolate,
                               lf(pkt)->NumberValue() + rf(pkt)->NumberValue());
      });
    } else if (op == "/") {
      return FilterFunc([isolate, lf, rf](const Packet &pkt) {
        return v8::Number::New(isolate,
                               lf(pkt)->NumberValue() + rf(pkt)->NumberValue());
      });
    } else if (op == "%") {
      return FilterFunc([isolate, lf, rf](const Packet &pkt) {
        return v8::Number::New(isolate,
                               lf(pkt)->Int32Value() % rf(pkt)->Int32Value());
      });
    } else if (op == "&") {
      return FilterFunc([isolate, lf, rf](const Packet &pkt) {
        return v8::Number::New(isolate,
                               lf(pkt)->Int32Value() & rf(pkt)->Int32Value());
      });
    } else if (op == "|") {
      return FilterFunc([isolate, lf, rf](const Packet &pkt) {
        return v8::Number::New(isolate,
                               lf(pkt)->Int32Value() | rf(pkt)->Int32Value());
      });
    } else if (op == "^") {
      return FilterFunc([isolate, lf, rf](const Packet &pkt) {
        return v8::Number::New(isolate,
                               lf(pkt)->Int32Value() ^ rf(pkt)->Int32Value());
      });
    } else if (op == ">>") {
      return FilterFunc([isolate, lf, rf](const Packet &pkt) {
        return v8::Number::New(isolate,
                               lf(pkt)->Int32Value() >> rf(pkt)->Int32Value());
      });
    } else if (op == "<<") {
      return FilterFunc([isolate, lf, rf](const Packet &pkt) {
        return v8::Number::New(isolate, lf(pkt)->Int32Value()
                                            << rf(pkt)->Int32Value());
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

  } else if (type == "LogicalExpression") {
    const std::string &op = json["operator"].string_value();
    const FilterFunc &lf = makeFilter(json["left"]);
    const FilterFunc &rf = makeFilter(json["right"]);
    if (op == "||") {
      return FilterFunc(
          [isolate, lf, rf](const Packet &pkt) -> v8::Local<v8::Value> {
            v8::Local<v8::Value> value = lf(pkt);
            return value->BooleanValue() ? value : rf(pkt);
          });
    } else {
      return FilterFunc(
          [isolate, lf, rf](const Packet &pkt) -> v8::Local<v8::Value> {
            v8::Local<v8::Value> value = lf(pkt);
            return !value->BooleanValue() ? value : rf(pkt);
          });
    }
  } else if (type == "UnaryExpression") {
    const FilterFunc &func = makeFilter(json["argument"]);
    const std::string &op = json["operator"].string_value();
    if (op == "+") {
      return FilterFunc(
          [isolate, func](const Packet &pkt) -> v8::Local<v8::Value> {
            return v8pp::to_v8(isolate, func(pkt)->NumberValue());
          });
    } else if (op == "-") {
      return FilterFunc(
          [isolate, func](const Packet &pkt) -> v8::Local<v8::Value> {
            return v8pp::to_v8(isolate, -func(pkt)->NumberValue());
          });
    } else if (op == "!") {
      return FilterFunc(
          [isolate, func](const Packet &pkt) -> v8::Local<v8::Value> {
            return v8pp::to_v8(isolate, !func(pkt)->BooleanValue());
          });
    } else if (op == "~") {
      return FilterFunc(
          [isolate, func](const Packet &pkt) -> v8::Local<v8::Value> {
            return v8pp::to_v8(isolate, ~func(pkt)->Int32Value());
          });
    }
  } else if (type == "CallExpression") {
    const FilterFunc &cf = makeFilter(json["callee"]);
    std::vector<FilterFunc> argFuncs;
    for (const json11::Json &item : json["arguments"].array_items()) {
      argFuncs.push_back(makeFilter(item));
    }
    return FilterFunc([isolate, cf,
                       argFuncs](const Packet &pkt) -> v8::Local<v8::Value> {
      v8::Local<v8::Value> func = cf(pkt);
      if (func->IsFunction()) {
        std::vector<v8::Local<v8::Value>> args;
        for (const FilterFunc &arg : argFuncs) {
          args.push_back(arg(pkt));
        }
        return func.As<v8::Object>()->CallAsFunction(
            isolate->GetCurrentContext()->Global(), args.size(), args.data());
      }
      return v8::Null(isolate);
    });
  } else if (type == "ConditionalExpression") {
    const FilterFunc &tf = makeFilter(json["test"]);
    const FilterFunc &cf = makeFilter(json["consequent"]);
    const FilterFunc &af = makeFilter(json["alternate"]);
    return FilterFunc(
        [isolate, tf, cf, af](const Packet &pkt) -> v8::Local<v8::Value> {
          return tf(pkt)->BooleanValue() ? cf(pkt) : af(pkt);
        });
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

/*
module.exports = function makeFilter(node) {
  switch (node.type) {
    case 'MemberExpression':
    {
      let objFunc = makeFilter(node.object);
      let propFunc;
      if (node.property.type === 'Identifier') {
        propFunc = () => node.property.name;
      } else {
        propFunc = makeFilter(node.property);
      }
      return function(pkt) {
        try {
          let obj = objFunc(pkt);
          let prop = propFunc(pkt);
          if (typeof obj.attr === 'function') {
            let attr = obj.attr(prop);
            if (attr != null) {
              return attr;
            }
          }
          if ((obj.attrs != null) && prop in obj.attrs) {
            return obj.attrs[prop];
          }
          if ((obj.data != null) && prop in obj.data) {
            return obj.data[prop];
          }
          if (prop in obj) {
            return obj[prop];
          }
        } catch (error) {
          return null;
        }
        return null;
      };
    }
    case 'Identifier':
      return function(pkt) {
        if (node.name in pkt) {
          return pkt[node.name];
        }
        let find = function(layers, name) {
          for (let ns in layers) {
            let layer = layers[ns];
            if (layer.name === name) {
              return layer;
            }
            if (layer.alias === name) {
              return layer;
            }
            let found = find(layer.layers, name);
            if (found != null) {
              return found;
            }
          }
          return null;
        }
        let found = find(pkt.layers, node.name);
        if (found != null) {
          return found;
        }
        if (node.name === '$') {
          return pkt;
        }
        let global = ('global', eval)('this');
        if (node.name in global) {
          return global[node.name];
        }
        return null;
      };
      break;
    default:
      throw new SyntaxError();
  }
};

*/
