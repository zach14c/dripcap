import {Layer, Item, Value} from 'dripcap';
import {Flags, Enum} from 'dripcap/utils';
import {IPv4Address} from 'dripcap/ipv4';
import {MACAddress} from 'dripcap/mac';

export default class ARPDissector {
  static get namespaces() {
    return ['::Ethernet::<ARP>'];
  }

  analyze(packet, parentLayer) {

    let layer = new Layer('::Ethernet::ARP');
    layer.name = 'ARP';
    layer.alias = 'arp';

    let htypeNumber = parentLayer.payload.readUInt16BE(0);
    let htype = Enum(hardwareTable, htypeNumber);
    layer.addItem({
      name: 'Hardware type',
      value: htype,
      range: '0:2'
    });
    layer.setAttr('htype', htype);

    let ptypeNumber = parentLayer.payload.readUInt16BE(2);
    let ptype = Enum(protocolTable, ptypeNumber);
    layer.addItem({
      name: 'Protocol type',
      value: ptype,
      range: '2:4'
    });
    layer.setAttr('ptype', ptype);

    let hlen = parentLayer.payload.readUInt8(4);
    layer.addItem({
      name: 'Hardware length',
      value: hlen,
      range: '4:5'
    });
    layer.setAttr('hlen', hlen);

    let plen = parentLayer.payload.readUInt8(5);
    layer.addItem({
      name: 'Protocol length',
      value: plen,
      range: '5:6'
    });
    layer.setAttr('plen', plen);

    let operationNumber = parentLayer.payload.readUInt16BE(6);
    let operation = Enum(operationTable, operationNumber);
    let operationName = operationTable[operationNumber];
    layer.addItem({
      name: 'Operation',
      value: operation,
      range: '6:8'
    });
    layer.setAttr('operation', operation);

    let sha = MACAddress(parentLayer.payload.slice(8, 14));
    layer.addItem({
      name: 'Sender hardware address',
      value: sha,
      range: '8:14'
    });
    layer.setAttr('sha', sha);

    let spa = IPv4Address(parentLayer.payload.slice(14, 18));
    layer.addItem({
      name: 'Sender protocol address',
      value: spa,
      range: '14:18'
    });
    layer.setAttr('spa', spa);

    let tha = MACAddress(parentLayer.payload.slice(18, 24));
    layer.addItem({
      name: 'Target hardware address',
      value: tha,
      range: '18:24'
    });
    layer.setAttr('tha', tha);

    let tpa = IPv4Address(parentLayer.payload.slice(24, 28));
    layer.addItem({
      name: 'Target protocol address',
      value: tpa,
      range: '24:28'
    });
    layer.setAttr('tpa', tpa);

    layer.summary = `[${operationName.toUpperCase()}] ${sha.data}-${spa.data} -> ${tha.data}-${tpa.data}`;

    return [layer];
  }
}

let hardwareTable = {
  0x1: 'Ethernet'
};

let protocolTable = {
  0x0800: 'IPv4',
  0x86DD: 'IPv6'
};

let operationTable = {
  0x1: 'request',
  0x2: 'reply'
};
