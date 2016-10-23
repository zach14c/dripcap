#ifndef PCAP_HPP
#define PCAP_HPP

#include <functional>
#include <memory>
#include <string>
#include <vector>

class Packet;
struct LogMessage;

class Pcap {
public:
  struct Context {
    std::function<void(std::unique_ptr<Packet>)> packetCb;
    std::function<void(const LogMessage &)> logCb;
  };
  struct Device {
    std::string id;
    std::string name;
    std::string description;
    int link = 0;
    bool loopback = false;
  };

public:
  Pcap(const std::shared_ptr<Context> &ctx);
  ~Pcap();
  static std::vector<Device> devices();
  void setInterface(const std::string &ifs);
  std::string networkInterface() const;
  void setPromiscuous(bool promisc);
  bool promiscuous() const;
  void setSnaplen(int len);
  int snaplen() const;
  bool setBPF(const std::string &filter, std::string *error);

  void start();
  void stop();

private:
  class Private;
  std::unique_ptr<Private> d;
};

#endif
