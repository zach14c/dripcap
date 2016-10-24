import {Layer, Item, Value} from 'dripcap';
import {IPv4Host} from 'dripcap/ipv4';
import {IPv6Host} from 'dripcap/ipv6';

export default class UDPDissector {
  static get namespaces() {
    return [/::Ethernet::\w+::<UDP>/];
  }

  analyze(packet, parentLayer) {
    let layer = new Layer(parentLayer.namespace.replace('<UDP>', 'UDP'));
    layer.name = 'UDP';
    layer.alias = 'udp';

    let source = parentLayer.payload.readUInt16BE(0);
    layer.addItem({
      name: 'Source port',
      value: new Value(source),
      range: '0:2'
    });

    let destination = parentLayer.payload.readUInt16BE(2);
    layer.addItem({
      name: 'Destination port',
      value: new Value(destination),
      range: '2:4'
    });

    let srcAddr = parentLayer.attr('src');
    let dstAddr = parentLayer.attr('dst');
    if (srcAddr.type === 'dripcap/ipv4/addr') {
      layer.setAttr('src', IPv4Host(srcAddr.data, source));
      layer.setAttr('dst', IPv4Host(dstAddr.data, destination));
    } else if (srcAddr.type === 'dripcap/ipv6/addr') {
      layer.setAttr('src', IPv6Host(srcAddr.data, source));
      layer.setAttr('dst', IPv6Host(dstAddr.data, destination));
    }

    let length = new Value(parentLayer.payload.readUInt16BE(4));
    layer.addItem({
      name: 'Length',
      value: length,
      range: '4:6'
    });
    layer.setAttr('length', length);

    let checksum = new Value(parentLayer.payload.readUInt16BE(6));
    layer.addItem({
      name: 'Checksum',
      value: checksum,
      range: '6:8'
    });
    layer.setAttr('checksum', checksum);

    layer.range = '8:'+ length.data;
    layer.payload = parentLayer.payload.slice(8, length.data);

    layer.addItem({
      name: 'Payload',
      value: new Value(layer.payload),
      range: '8:' + length.data
    });

    layer.summary = `${layer.attr('src').data} -> ${layer.attr('dst').data}`;
    return [layer];
  }
}
