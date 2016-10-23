#ifndef PACKET_HPP
#define PACKET_HPP

#include <memory>
#include <string>
#include <unordered_map>
#include <v8.h>
#include <vector>

class Layer;
class Buffer;
class LargeBuffer;
struct pcap_pkthdr;

class Packet {
public:
  Packet(v8::Local<v8::Object> option);
  Packet(std::unique_ptr<Layer> layer);
  Packet(const struct pcap_pkthdr *h, const uint8_t *bytes);
  ~Packet();
  Packet(const Packet &) = delete;
  Packet &operator=(const Packet &) = delete;

  uint32_t seq() const;
  void setSeq(uint32_t id);

  uint32_t ts_sec() const;
  uint32_t ts_nsec() const;
  uint32_t length() const;
  std::string summary() const;
  std::string extension() const;

  std::string name() const;
  std::string ns() const;
  v8::Local<v8::Value> timestamp() const;
  v8::Local<v8::Object> attrs() const;

  std::unique_ptr<Buffer> payload() const;
  std::unique_ptr<LargeBuffer> largePayload() const;
  v8::Local<v8::Object> payloadBuffer() const;

  void addLayer(const std::shared_ptr<Layer> &layer);
  const std::unordered_map<std::string, std::shared_ptr<Layer>> &layers() const;
  v8::Local<v8::Object> layersObject() const;

private:
  class Private;
  std::unique_ptr<Private> d;
};

#endif
