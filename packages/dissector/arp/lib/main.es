import {
  Session
} from 'dripcap';

export default class ARP {
  activate() {
    Session.registerDissector(`${__dirname}/arp.es`);
  }

  deactivate() {
    Session.unregisterDissector(`${__dirname}/arp.es`);
  }
}
