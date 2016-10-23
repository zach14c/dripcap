import {Value} from 'dripcap';

export function MACAddress(buffer) {
  let val = buffer.toString('hex').replace(/..(?=.)/g, '$&:');
  return new Value(val, 'dripcap/mac');
}

export default function () {}
