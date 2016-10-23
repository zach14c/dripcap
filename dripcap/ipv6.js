import {Value} from 'dripcap';

export function IPv6Address(buffer) {
  let hex = buffer.toString('hex');
  let str = '';
  for (let i = 0; i < 8; ++i) {
    str += hex.substr(i * 4, 4).replace(/0{0,3}/, '');
    str += ':';
  }
  str = str.substr(0, str.length - 1);
  let seq = str.match(/:0:(?:0:)+/g);
  if (seq != null) {
    seq.sort((a, b) => {
      b.length - a.length;
    });
    str = str.replace(seq[0], '::');
  }
  return new Value(str, 'dripcap/ipv6/addr');
}

export function IPv6Host(addr, port) {
  let val = `${addr}:${port}`
  return new Value(val, 'dripcap/ipv6/host');
}

export default function () {}
