import {Layer, Item, Value, StreamChunk} from 'dripcap';
import {Flags, Enum} from 'dripcap/utils';
import {IPv4Host} from 'dripcap/ipv4';
import {IPv6Host} from 'dripcap/ipv6';

export default class Dissector {
  static get namespaces() {
    return [/::Ethernet::\w+::<TCP>/];
  }

  analyze(packet, parentLayer) {
    let layer = new Layer(parentLayer.namespace.replace('<TCP>', 'TCP'));
    layer.name = 'TCP';
    layer.id = 'tcp';

    let source = parentLayer.payload.readUInt16BE(0);
    layer.addItem({
      name: 'Source port',
      value: source,
      range: '0:2'
    });

    let destination = parentLayer.payload.readUInt16BE(2);
    layer.addItem({
      name: 'Destination port',
      value: destination,
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

    let seq = parentLayer.payload.readUInt32BE(4);
    layer.addItem({
      name: 'Sequence number',
      value: seq,
      range: '4:8'
    });
    layer.setAttr('seq', seq);

    let ack = parentLayer.payload.readUInt32BE(8);
    layer.addItem({
      name: 'Acknowledgment number',
      value: ack,
      range: '8:12'
    });
    layer.setAttr('ack', ack);

    let dataOffset = parentLayer.payload.readUInt8(12) >> 4;
    layer.addItem({
      name: 'Data offset',
      value: dataOffset,
      range: '12:13'
    });
    layer.setAttr('dataOffset', dataOffset);

    let table = {
      'NS': 0x1 << 8,
      'CWR': 0x1 << 7,
      'ECE': 0x1 << 6,
      'URG': 0x1 << 5,
      'ACK': 0x1 << 4,
      'PSH': 0x1 << 3,
      'RST': 0x1 << 2,
      'SYN': 0x1 << 1,
      'FIN': 0x1 << 0,
    };

    let flags = Flags(table, parentLayer.payload.readUInt8(13) |
      ((parentLayer.payload.readUInt8(12) & 0x1) << 8));

    layer.addItem({
      name: 'Flags',
      value: flags,
      data: '12:14',
      items: [
        {
          name: 'NS',
          value: flags.data['NS'],
          range: '12:13'
        },
        {
          name: 'CWR',
          value: flags.data['CWR'],
          range: '13:14'
        },
        {
          name: 'ECE',
          value: flags.data['ECE'],
          range: '13:14'
        },
        {
          name: 'URG',
          value: flags.data['URG'],
          range: '13:14'
        },
        {
          name: 'ACK',
          value: flags.data['ACK'],
          range: '13:14'
        },
        {
          name: 'PSH',
          value: flags.data['PSH'],
          range: '13:14'
        },
        {
          name: 'RST',
          value: flags.data['RST'],
          range: '13:14'
        },
        {
          name: 'SYN',
          value: flags.data['SYN'],
          range: '13:14'
        },
        {
          name: 'FIN',
          value: flags.data['FIN'],
          range: '13:14'
        }
      ]
    });

    let window = parentLayer.payload.readUInt16BE(14);
    layer.addItem({
      name: 'Window size',
      value: window,
      range: '14:16'
    });
    layer.setAttr('window', window);

    let checksum = parentLayer.payload.readUInt16BE(16);
    layer.addItem({
      name: 'Checksum',
      value: checksum,
      range: '16:18'
    });
    layer.setAttr('checksum', checksum);

    let urgent = parentLayer.payload.readUInt16BE(18);
    layer.addItem({
      name: 'Urgent pointer',
      value: urgent,
      range: '18:20'
    })
    layer.setAttr('urgent', urgent);

    let optionDataOffset = dataOffset * 4;
    let optionItems = [];
    let option = {
      name: 'Options',
      range: '20:' + optionDataOffset,
      items: []
    };

    let optionOffset = 20;

    while (optionDataOffset > optionOffset) {
      switch (parentLayer.payload[optionOffset]) {
        case 0:
          optionOffset = optionDataOffset;
          break;

        case 1:
          option.items.push({
            name: 'NOP',
            range: `${optionOffset}:${optionOffset + 1}`
          });
          optionOffset++;
          break;

        case 2:
          optionItems.push('Maximum segment size');
          option.items.push({
            name: 'Maximum segment size',
            value: parentLayer.payload.readUInt16BE(optionOffset + 2),
            range: `${optionOffset}:${optionOffset + 4}`
          });
          optionOffset += 4;
          break;

        case 3:
          optionItems.push('Window scale');
          option.items.push({
            name: 'Window scale',
            value: parentLayer.payload.readUInt8(optionOffset + 2),
            range: `${optionOffset}:${optionOffset + 3}`
          });
          optionOffset += 3;
          break;

        case 4:
          optionItems.push('Selective ACK permitted');
          option.items.push({
            name: 'Selective ACK permitted',
            range: `${optionOffset}:${optionOffset + 2}`
          });
          optionOffset += 2;
          break;

        // TODO: https://tools.ietf.org/html/rfc2018
        case 5:
          let length = parentLayer.payload.readUInt8(optionOffset + 1);
          optionItems.push('Selective ACK');
          option.items.push({
            name: 'Selective ACK',
            value: parentLayer.payload.slice(optionOffset + 2, optionOffset + length),
            data: `${optionOffset}:${optionOffset + length}`
          });

          optionOffset += length;
          break;

        case 8:
          let mt = parentLayer.payload.readUInt32BE(optionOffset + 2);
          let et = parentLayer.payload.readUInt32BE(optionOffset + 2);
          optionItems.push('Timestamps');
          option.items.push({
            name: 'Timestamps',
            value: `${mt} - ${et}`,
            range: `${optionOffset}:${optionOffset + 10}`,
            items: [{
              name: 'My timestamp',
              value: mt,
              range: `${optionOffset + 2}:${optionOffset + 6}`
            }, {
              name: 'Echo reply timestamp',
              value: et,
              range: `${optionOffset + 6}:${optionOffset + 10}`
            }]
          });
          optionOffset += 10;
          break;

        default:
          throw new Error('unknown option');
      }
    }

    option.value = optionItems.join(',');
    layer.addItem(option);

    layer.range = optionDataOffset + ':';
    layer.payload = parentLayer.payload.slice(optionDataOffset);
    layer.addItem({
      name: 'Payload',
      value: layer.payload,
      range: optionDataOffset + ':'
    });

    layer.summary = `${layer.attr('src').data} -> ${layer.attr('dst').data} seq:${seq} ack:${ack}`;

    let id = layer.attr('src').data + '/' + layer.attr('dst').data;
    let chunk = new StreamChunk(parentLayer.namespace, id, layer);
    chunk.setAttr('payload', layer.payload);
    chunk.setAttr('seq', seq);

    if (flags.data['FIN'] && flags.data['ACK']) {
      chunk.end = true;
    }

    return [layer, chunk];
  }
};
