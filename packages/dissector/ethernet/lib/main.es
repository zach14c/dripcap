import {
  Session
} from 'dripcap';

export default class Ethernet {
  activate() {
    Session.registerDissector(['::<Ethernet>'], `${__dirname}/eth.es`);
  }

  deactivate() {
    Session.unregisterDissector(`${__dirname}/eth.es`);
  }
}
