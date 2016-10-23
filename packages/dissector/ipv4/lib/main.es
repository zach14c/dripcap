import {
  Session
} from 'dripcap';

export default class IPv4 {
  activate() {
    Session.registerDissector(['::Ethernet::<IPv4>'], `${__dirname}/ipv4.es`);
  }

  deactivate() {
    Session.unregisterDissector(`${__dirname}/ipv4.es`);
  }
}
