import {
  Session
} from 'dripcap';

export default class TCP {
  activate() {
    Session.registerDissector([/::Ethernet::\w+::<TCP>/], `${__dirname}/tcp.es`);
    Session.registerStreamDissector([/::Ethernet::\w+::<TCP>/], `${__dirname}/tcp_stream.es`);
  }

  deactivate() {
    Session.unregisterDissector(`${__dirname}/tcp.es`);
    Session.unregisterStreamDissector(`${__dirname}/tcp_stream.es`);
  }
}
