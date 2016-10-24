import {
  Session
} from 'dripcap';

export default class DNS {
  activate() {
    Session.registerDissector(`${__dirname}/dns.es`);
  }

  deactivate() {
    Session.unregisterDissector(`${__dirname}/dns.es`);
  }
}
