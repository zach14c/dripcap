import {Layer, Item, Value} from 'dripcap';
import {Enum} from 'dripcap/utils';
import {MACAddress} from 'dripcap/mac';

export default class Dissector {
  analyze(packet, parentLayer) {
    let layer = new Layer('::Ethernet');
    layer.name = 'Ethernet';
    layer.alias = 'eth';

    let destination = MACAddress(parentLayer.payload.slice(0, 6));
    layer.addItem({
      name: 'Destination',
      value: destination,
      range: '0:6'
    });
    layer.setAttr('dst', destination);

    let source = MACAddress(parentLayer.payload.slice(6, 12));
    layer.addItem({
      name: 'Source',
      value: source,
      range: '6:12'
    });
    layer.setAttr('src', source);

    let protocolName;
    let type = parentLayer.payload.readUInt16BE(12);
    if (type <= 1500) {
      layer.addItem({
        name: 'Length',
        value: new Value(type),
        range: '12:14'
      });
    } else {
      let table = {
        0x0800: 'IPv4',
        0x0806: 'ARP',
        0x0842: 'WoL',
        0x809B: 'AppleTalk',
        0x80F3: 'AARP',
        0x86DD: 'IPv6'
      };

      let etherType = Enum(table, type);
      layer.addItem({
        name: 'EtherType',
        value: etherType,
        range: '12:14'
      });
      layer.setAttr('etherType', etherType);

      protocolName = table[type];
      if (protocolName != null) {
        layer.namespace = `::Ethernet::<${protocolName}>`;
      }
    }

    layer.summary = `${source.data} -> ${destination.data}`;
    if (protocolName != null) {
      layer.summary = `[${protocolName}] ` + layer.summary;
    }

    layer.range = '14:';
    layer.payload = parentLayer.payload.slice(14);
    layer.addItem({
      name: 'Payload',
      value: new Value(layer.payload),
      range: '14:'
    });

    return [layer];
  }
};
