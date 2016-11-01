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

/*
module.exports = function makeFilter(node) {
  switch (node.type) {
    case 'LogicalExpression':
      switch (node.operator) {
        case '||':
          {
            let lf = makeFilter(node.left);
            let rf = makeFilter(node.right);
            return pkt => lf(pkt) || rf(pkt);
          }
        case '&&':
          {
            let lf = makeFilter(node.left);
            let rf = makeFilter(node.right);
            return pkt => lf(pkt) && rf(pkt);
          }
        default:
          throw new SyntaxError();
      }
    case 'ConditionalExpression':
    {
      let tf = makeFilter(node.test);
      let cf = makeFilter(node.consequent);
      let af = makeFilter(node.alternate);
      return function(pkt) {
        if (tf(pkt)) {
          return cf(pkt);
        } else {
          return af(pkt);
        }
      };
    }
    case 'BinaryExpression':
    {
      let lf = makeFilter(node.left);
      let rf = makeFilter(node.right);
      switch (node.operator) {
        case '>':
          return pkt => lf(pkt) > rf(pkt);
        case '<':
          return pkt => lf(pkt) < rf(pkt);
        case '<=':
          return pkt => lf(pkt) <= rf(pkt);
        case '>=':
          return pkt => lf(pkt) >= rf(pkt);
        case '==':
          return function(pkt) {
            let lhs = lf(pkt);
            let rhs = rf(pkt);
            if ((lhs != null) && (lhs.equals != null)) {
              return lhs.equals(rhs);
            }
            if ((rhs != null) && (rhs.equals != null)) {
              return rhs.equals(lhs);
            }
            return lhs === rhs;
          };
        case '!=':
          return pkt => lf(pkt) !== rf(pkt);
        case '+':
          return pkt => lf(pkt) + rf(pkt);
        case '-':
          return pkt => lf(pkt) - rf(pkt);
        case '*':
          return pkt => lf(pkt) * rf(pkt);
        case '/':
          return pkt => lf(pkt) / rf(pkt);
        case '%':
          return pkt => lf(pkt) % rf(pkt);
        case '&':
          return pkt => lf(pkt) & rf(pkt);
        case '|':
          return pkt => lf(pkt) | rf(pkt);
        case '^':
          return pkt => lf(pkt) ^ rf(pkt);
        case '>>':
          return pkt => lf(pkt) >> rf(pkt);
        case '<<':
          return pkt => lf(pkt) << rf(pkt);
        default:
          throw new SyntaxError();
      }
    }
    case 'SequenceExpression':
    {
      let ef = node.expressions.map(e => makeFilter(e));
      return function(pkt) {
        let res = null;
        for (let f of ef) {
          res = f(pkt);
        }
        return res;
      };
    }
    case 'CallExpression':
    {
      let cf = makeFilter(node.callee);
      let af = node.arguments.map(a => makeFilter(a));
      return function(pkt) {
        let args = af.map(f => f(pkt));
        let obj = cf(pkt);
        if (obj != null) {
          return obj.apply(this, args);
        } else {
          return null;
        }
      };
    }
    case 'UnaryExpression':
    {
      let f = makeFilter(node.argument);
      switch (node.operator) {
        case '+':
          return pkt => +f(pkt);
        case '-':
          return pkt => -f(pkt);
        case '!':
          return pkt => !f(pkt);
        case '~':
          return pkt => ~f(pkt);
        default:
          throw new SyntaxError();
      }
    }
    case 'Literal':
      if (node.regex != null) {
        let reg = new RegExp(node.regex.pattern, node.regex.flags);
        return () => reg;
      } else {
        return () => node.value;
      }
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
