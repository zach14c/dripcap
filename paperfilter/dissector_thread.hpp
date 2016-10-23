#ifndef DISSECTOR_THREAD_HPP
#define DISSECTOR_THREAD_HPP

#include "dissector.hpp"
#include <functional>
#include <memory>
#include <vector>

class Packet;
class PacketQueue;
class StreamChunk;
struct LogMessage;

class DissectorThread {
public:
  struct Context {
    PacketQueue *queue;
    std::vector<Dissector> dissectors;
    std::function<void(const std::shared_ptr<Packet> &)> packetCb;
    std::function<void(uint32_t, std::vector<std::unique_ptr<StreamChunk>>)>
        streamsCb;
    std::function<void(const LogMessage &)> logCb;
  };

public:
  DissectorThread(const std::shared_ptr<Context> &ctx);
  ~DissectorThread();
  DissectorThread(const DissectorThread &) = delete;
  DissectorThread &operator=(const DissectorThread &) = delete;

private:
  class Private;
  std::unique_ptr<Private> d;
};

#endif
