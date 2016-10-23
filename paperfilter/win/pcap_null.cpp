#include "../packet.hpp"
#include "pcap.hpp"
#include <mutex>

class Pcap::Private {
public:
  Private(const std::shared_ptr<Context> &ctx);

public:
  std::shared_ptr<Context> ctx;
  std::string networkInterface;
  bool promiscuous = false;
  int snaplen = 2048;
};

Pcap::Private::Private(const std::shared_ptr<Context> &ctx) : ctx(ctx) {}

Pcap::Pcap(const std::shared_ptr<Context> &ctx) : d(new Private(ctx)) {}

Pcap::~Pcap() { stop(); }

std::vector<Pcap::Device> Pcap::devices() {
  std::vector<Device> devs;
  return devs;
}

void Pcap::setInterface(const std::string &ifs) { d->networkInterface = ifs; }

std::string Pcap::networkInterface() const { return d->networkInterface; }

void Pcap::setPromiscuous(bool promisc) { d->promiscuous = promisc; }

bool Pcap::promiscuous() const { return d->promiscuous; }

void Pcap::setSnaplen(int len) { d->snaplen = len; }

int Pcap::snaplen() const { return d->snaplen; }

bool Pcap::setBPF(const std::string &filter, std::string *error) {
  return true;
}

void Pcap::start() {}

void Pcap::stop() {}
