import {Layer, Value, StreamChunk} from 'dripcap';

export default class Dissector {
  static get namespaces() {
    return [/::Ethernet::\w+::<TCP>/];
  }

  constructor() {
    this.seq = -1;
    this.length = 0;
  }

  analyze(packet, parentLayer, chunk) {

    if (parentLayer.payload.length > 0) {
      let ns = chunk.namespace.replace('<TCP>', 'TCP');
      let stream = new StreamChunk(ns, chunk.id, parentLayer);
      let payload = chunk.attr('payload').data;
      let seq = chunk.attr('seq').data;

      if (this.seq < 0) {
        this.length += payload.length;
        stream.setAttr('payload', new Value(payload));
      } else {
        let start = this.seq + this.length;
        let length = payload.length;
        if (start > seq) {
          length -= (start - seq);
        }
        this.length += length;
        stream.setAttr('payload', new Value(payload));
      }
      this.seq = seq;
      return [stream];
    }

  }
};
