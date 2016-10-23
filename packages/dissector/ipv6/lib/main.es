import {
  Session
} from 'dripcap';

export default class IPv6 {
  activate() {
    Session.registerDissector(['::Ethernet::<IPv6>'], `${__dirname}/ipv6.es`);
  }

  deactivate() {
    Session.unregisterDissector(`${__dirname}/ipv6.es`);
  }
}
