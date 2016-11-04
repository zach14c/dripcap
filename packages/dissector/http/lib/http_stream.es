import {Layer, Value, StreamChunk, LargeBuffer} from 'dripcap';

export default class Dissector {
  static get namespaces() {
    return [/::Ethernet::\w+::TCP/];
  }

  analyze(packet, parentLayer, chunk) {
    let payload = chunk.attr('payload').data;
    let body = payload.toString('utf8');
    let re = /(GET|POST) (\S+) (HTTP\/(0\.9|1\.0|1\.1))\r\n/;
    let m = body.match(re);
    if (m != null) {
      let layer = new Layer(chunk.namespace + '::HTTP');
      layer.name = 'HTTP';
      layer.id = 'http';

      let large = new LargeBuffer();
      large.write(payload);
      layer.payload = large;

      let method = m[1];
      let cursor = method.length;

      layer.addItem({
        name: 'Method',
        value: method,
        range: '0:' + cursor
      });
      layer.setAttr('method', method);

      let path = m[2];
      cursor++;
      layer.addItem({
        name: 'Path',
        value: path,
        range: cursor + ':' + (cursor + path.length)
      });
      layer.setAttr('path', path);

      let version = m[3];
      cursor += path.length + 1;
      layer.addItem({
        name: 'Version',
        value: version,
        range: cursor + ':' + (cursor + version.length)
      });

      layer.setAttr('version', version);
      layer.setAttr('src', parentLayer.attr('src'));
      layer.setAttr('dst', parentLayer.attr('dst'));
      return [layer];
    }
  }
};
