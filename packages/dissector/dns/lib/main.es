import {
  Session
} from 'dripcap';

export default class DNS {
  activate() {
    Session.registerDissector(['::Ethernet::IPv4::UDP'], `${__dirname}/dns.es`);
  }

  deactivate() {
    Session.unregisterDissector(`${__dirname}/dns.es`);
  }
}
