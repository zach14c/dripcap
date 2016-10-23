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
