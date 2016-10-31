#include "pcap.hpp"
#include "../packet.hpp"
#include "../log_message.hpp"
#include <mutex>
#include <pcap.h>
#include <signal.h>
#include <thread>
#include <winsock2.h>
#include <iphlpapi.h>

#ifndef PCAP_NETMASK_UNKNOWN
#define PCAP_NETMASK_UNKNOWN 0xffffffff
#endif

#ifdef _WIN32
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "iphlpapi.lib")
#endif

class Pcap::Private {
public:
  Private(const std::shared_ptr<Context> &ctx);

public:
  std::mutex mutex;
  std::thread thread;
  pcap_t *pcap = nullptr;

  std::shared_ptr<Context> ctx;
  bpf_program bpf = {0, nullptr};
  std::string networkInterface;
  bool promiscuous = false;
  int snaplen = 2048;
};

Pcap::Private::Private(const std::shared_ptr<Context> &ctx) : ctx(ctx) {}

Pcap::Pcap(const std::shared_ptr<Context> &ctx) : d(new Private(ctx)) {}

Pcap::~Pcap() { stop(); }

std::vector<Pcap::Device> Pcap::devices() {
  std::vector<Device> devs;
  static const int guidLen = 38;

  std::unordered_map<std::string, std::string> descriptions;
  {
    PMIB_IFTABLE ifTable = nullptr;
    DWORD dwSize = 0;
    if (GetIfTable(nullptr, &dwSize, 0) == ERROR_INSUFFICIENT_BUFFER) {
      ifTable = static_cast<MIB_IFTABLE *>(malloc(dwSize));
    }

    if (GetIfTable(ifTable, &dwSize, 0) == NO_ERROR) {
      if (ifTable->dwNumEntries > 0) {
        for (IF_INDEX i = 1; i <= ifTable->dwNumEntries; i++) {
          MIB_IFROW MibIfRow;
          MibIfRow.dwIndex = i;
          if (GetIfEntry(&MibIfRow) == NO_ERROR) {
            char name[512];
            wcstombs(name, MibIfRow.wszName, sizeof(name));
            descriptions[name + (strlen(name) - guidLen)] =
                reinterpret_cast<const char *>(MibIfRow.bDescr);
          }
        }
      }
    }
    free(ifTable);
  }

  pcap_if_t *alldevsp;
  char err[PCAP_ERRBUF_SIZE] = {'\0'};
  if (pcap_findalldevs(&alldevsp, err) < 0) {
    return devs;
  }

  for (pcap_if_t *ifs = alldevsp; ifs; ifs = ifs->next) {
    Device dev;
    dev.id = ifs->name;
    dev.name = ifs->name;
    const auto &it =
        descriptions.find(ifs->name + (strlen(ifs->name) - guidLen));
    if (it != descriptions.end()) {
      dev.name = it->second;
    } else {
      dev.name = ifs->name;
    }
    if (ifs->description)
      dev.description = ifs->description;
    dev.loopback = ifs->flags & PCAP_IF_LOOPBACK;
    dev.link = -1;

    pcap_t *pcap = pcap_open_live(ifs->name, 1600, false, 0, err);
    if (pcap) {
      dev.link = pcap_datalink(pcap);
      pcap_close(pcap);
    }

    devs.push_back(dev);
  }

  pcap_freealldevs(alldevsp);
  return devs;
}

void Pcap::setInterface(const std::string &ifs) { d->networkInterface = ifs; }

std::string Pcap::networkInterface() const { return d->networkInterface; }

void Pcap::setPromiscuous(bool promisc) { d->promiscuous = promisc; }

bool Pcap::promiscuous() const { return d->promiscuous; }

void Pcap::setSnaplen(int len) { d->snaplen = len; }

int Pcap::snaplen() const { return d->snaplen; }

bool Pcap::setBPF(const std::string &filter, std::string *error) {
  pcap_freecode(&d->bpf);
  d->bpf.bf_len = 0;
  d->bpf.bf_insns = nullptr;

  if (filter.empty())
    return true;

  char err[PCAP_ERRBUF_SIZE] = {'\0'};
  pcap_t *pcap = pcap_open_live(d->networkInterface.c_str(), d->snaplen,
                                d->promiscuous, 1, err);
  if (!pcap) {
    if (error)
      error->assign(err);
    return false;
  }

  if (pcap_compile(pcap, &d->bpf, filter.c_str(), true, PCAP_NETMASK_UNKNOWN) <
      0) {
    if (error)
      error->assign(pcap_geterr(pcap));
    pcap_close(pcap);
    return false;
  }

  pcap_close(pcap);
  return true;
}

void Pcap::start() {
  stop();

  std::lock_guard<std::mutex> lock(d->mutex);
  char err[PCAP_ERRBUF_SIZE] = {'\0'};

  d->pcap = pcap_open_live(d->networkInterface.c_str(), d->snaplen,
                           d->promiscuous, 1, err);
  if (!d->pcap) {
    if (d->ctx->logCb) {
      LogMessage msg;
      msg.level = LogMessage::LEVEL_ERROR;
      msg.message = std::string("pcap_open_live() failed: ") + err;
      msg.domain = "pcap";
      d->ctx->logCb(msg);
    }
    return;
  }

  if (d->bpf.bf_len > 0 && pcap_setfilter(d->pcap, &d->bpf) < 0) {
    if (d->ctx->logCb) {
      LogMessage msg;
      msg.level = LogMessage::LEVEL_ERROR;
      msg.message = "pcap_setfilter() failed";
      msg.domain = "pcap";
      d->ctx->logCb(msg);
    }
    pcap_close(d->pcap);
    d->pcap = nullptr;
    return;
  }

  d->thread = std::thread([this]() {
    pcap_loop(
        d->pcap,
        0, [](u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
          Pcap &self = *reinterpret_cast<Pcap *>(user);
          if (self.d->ctx->packetCb) {
            self.d->ctx->packetCb(
                std::unique_ptr<Packet>(new Packet(h, bytes)));
          }
        }, reinterpret_cast<u_char *>(this));
    {
      std::lock_guard<std::mutex> lock(d->mutex);
      pcap_close(d->pcap);
      d->pcap = nullptr;
    }
  });
}

void Pcap::stop() {
  {
    std::lock_guard<std::mutex> lock(d->mutex);
    if (d->pcap)
      pcap_breakloop(d->pcap);
  }
  if (d->thread.joinable())
    d->thread.join();
}
