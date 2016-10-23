import {Value} from 'dripcap';

export function IPv4Address(buffer) {
  let val = `${buffer[0]}.${buffer[1]}.${buffer[2]}.${buffer[3]}`
  return new Value(val, 'dripcap/ipv4/addr');
}

export function IPv4Host(addr, port) {
  let val = `${addr}:${port}`
  return new Value(val, 'dripcap/ipv4/host');
}

export default function () {}
