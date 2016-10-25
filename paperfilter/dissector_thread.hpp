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
struct DissectorSharedContext;

class DissectorThread {
public:
  DissectorThread(const std::shared_ptr<DissectorSharedContext> &ctx);
  ~DissectorThread();
  DissectorThread(const DissectorThread &) = delete;
  DissectorThread &operator=(const DissectorThread &) = delete;

private:
  class Private;
  std::unique_ptr<Private> d;
};

#endif
