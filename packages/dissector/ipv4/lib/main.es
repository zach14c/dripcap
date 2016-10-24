import {
  Session
} from 'dripcap';

export default class IPv4 {
  activate() {
    Session.registerDissector(`${__dirname}/ipv4.es`);
  }

  deactivate() {
    Session.unregisterDissector(`${__dirname}/ipv4.es`);
  }
}
