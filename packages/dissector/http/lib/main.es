import {
  Session
} from 'dripcap';

export default class TCP {
  activate() {
    Session.registerStreamDissector(`${__dirname}/http_stream.es`);
  }

  deactivate() {
    Session.unregisterStreamDissector(`${__dirname}/http_stream.es`);
  }
}
