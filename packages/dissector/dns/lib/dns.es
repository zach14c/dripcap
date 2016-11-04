import {Layer, Item, Value} from 'dripcap';
import {Flags, Enum} from 'dripcap/utils';

export default class DNSDissector {
  static get namespaces() {
    return ['::Ethernet::IPv4::UDP'];
  }

  analyze(packet, parentLayer) {
    let layer = new Layer(parentLayer.namespace + '::DNS');
    layer.name = 'DNS';
    layer.id = 'dns';

    let id = parentLayer.payload.readUInt16BE(0);
    let flags0 = parentLayer.payload.readUInt8(2);
    let flags1 = parentLayer.payload.readUInt8(3);
    let qr = !!(flags0 >> 7);

    let opcodeNumber = (flags0 >> 3) & 0b00001111;
    if (!(opcodeNumber in operationTable)) {
      throw new Error('wrong DNS opcode');
    }
    let opcode = Enum(operationTable, opcodeNumber);
    let opcodeName = operationTable[opcodeNumber];

    let aa = !!((flags0 >> 2) & 1);
    let tc = !!((flags0 >> 1) & 1);
    let rd = !!((flags0 >> 0) & 1);
    let ra = !!(flags1 >> 7);

    if (flags1 & 0b01110000) {
      throw new Error('reserved bits must be zero');
    }

    let rcodeNumber = flags1 & 0b00001111;
    if (!(rcodeNumber in recordTable)) {
      throw new Error('wrong DNS rcode');
    }
    let rcode = Enum(recordTable, rcodeNumber);
    let rcodeName = recordTable[rcodeNumber];

    let qdCount = parentLayer.payload.readUInt16BE(4);
    let anCount = parentLayer.payload.readUInt16BE(6);
    let nsCount = parentLayer.payload.readUInt16BE(8);
    let arCount = parentLayer.payload.readUInt16BE(10);

    layer.addItem({
      name: 'ID',
      value: id,
      range: '0:2'
    });
    layer.setAttr('id', id);

    layer.addItem({
      name: 'Query/Response Flag',
      value: qr,
      range: '2:3'
    });
    layer.setAttr('qr', qr);

    layer.addItem({
      name: 'Operation Code',
      value: opcode,
      range: '2:3'
    });
    layer.setAttr('opcode', opcode);

    layer.addItem({
      name: 'Authoritative Answer Flag',
      value: aa,
      range: '2:3'
    });
    layer.setAttr('aa', aa);

    layer.addItem({
      name: 'Truncation Flag',
      value: tc,
      range: '2:3'
    });
    layer.setAttr('tc', tc);

    layer.addItem({
      name: 'Recursion Desired',
      value: rd,
      range: '2:3'
    });
    layer.setAttr('rd', rd);

    layer.addItem({
      name: 'Recursion Available',
      value: ra,
      range: '3:4'
    });
    layer.setAttr('ra', ra);

    layer.addItem({
      name: 'Response Code',
      value: rcode,
      range: '3:4'
    });
    layer.setAttr('rcode', rcode);

    layer.addItem({
      name: 'Question Count',
      value: qdCount,
      range: '4:6'
    });
    layer.setAttr('qdCount', qdCount);

    layer.addItem({
      name: 'Answer Record Count',
      value: anCount,
      range: '6:8'
    });
    layer.setAttr('anCount', anCount);

    layer.addItem({
      name: 'Authority Record Count',
      value: nsCount,
      range: '8:10'
    });
    layer.setAttr('nsCount', nsCount);

    layer.addItem({
      name: 'Additional Record Count',
      value: arCount,
      range: '10:12'
    });
    layer.setAttr('arCount', arCount);

    layer.payload = parentLayer.payload.slice(12);
    layer.addItem({
      name: 'Payload',
      value: layer.payload,
      range: '12:'
    });

    layer.summary = `[${opcodeName}] [${rcodeName}] qd:${qdCount} an:${anCount} ns:${nsCount} ar:${arCount}`;
    return [layer];
  }
}

let operationTable = {
  0: 'QUERY',
  1: 'IQUERY',
  2: 'STATUS',
  4: 'NOTIFY',
  5: 'UPDATE',
};

let recordTable = {
  0: 'No Error',
  1: 'Format Error',
  2: 'Server Failure',
  3: 'Name Error',
  4: 'Not Implemented',
  5: 'Refused',
  6: 'YX Domain',
  7: 'YX RR Set',
  8: 'NX RR Set',
  9: 'Not Auth',
  10: 'Not Zone',
};
