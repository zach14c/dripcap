import {
  EventEmitter
} from 'events';
import config from './config';
import {Session} from 'paperfilter';

export default class SessionInterface extends EventEmitter {
  constructor(parent) {
    super();
    this.parent = parent;
    this.list = [];
    this._dissectors = [];
    this._streamDissectors = [];
  }

  async getInterfaceList() {
    return Session.devices;
  }

  registerDissector(script) {
    this._dissectors.push({
      script
    });
  }

  registerStreamDissector(script) {
    this._streamDissectors.push({
      script
    });
  }

  unregisterDissector(script) {
    let index = this._dissectors.find(e => e.path === script);
    if (index != null) {
      this._dissectors.splice(index, 1);
    }
  }

  unregisterStreamDissector(script) {
    let index = this._streamDissectors.find(e => e.path === script);
    if (index != null) {
      this._streamDissectors.splice(index, 1);
    }
  }

  async create(iface = '', options = {}) {
    let option = {
      namespace: '::<Ethernet>',
      dissectors: this._dissectors,
      stream_dissectors: this._streamDissectors
    };

    let sess = await Session.create(option);
    sess.interface = iface;

    this.parent.pubsub.pub('core:capturing-settings', {
      iface,
      options
    });

    return sess;
  }
}
