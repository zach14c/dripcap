#ifndef FILTER_THREAD_HPP
#define FILTER_THREAD_HPP

#include "filtered_packet_store.hpp"
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

class Packet;
class PacketStore;
struct LogMessage;

class FilterThread {
public:
  struct Context {
    std::mutex mutex;
    std::condition_variable cond;
    uint32_t maxSeq = 0;
    PacketStore *store = nullptr;
    FilteredPacketStore packets;
    std::string filter;
    std::string script;
    std::function<void(const LogMessage &)> logCb;
  };

public:
  FilterThread(const std::shared_ptr<Context> &ctx);
  ~FilterThread();
  FilterThread(const FilterThread &) = delete;
  FilterThread &operator=(const FilterThread &) = delete;

private:
  class Private;
  std::unique_ptr<Private> d;
};

#endif
