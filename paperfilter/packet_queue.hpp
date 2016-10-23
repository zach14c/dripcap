#ifndef PACKET_QUEUE_HPP
#define PACKET_QUEUE_HPP

#include <condition_variable>
#include <memory>
#include <mutex>
#include <queue>

class Packet;

class PacketQueue {
public:
  PacketQueue();
  ~PacketQueue();
  PacketQueue(const PacketQueue &) = delete;
  PacketQueue &operator=(const PacketQueue &) = delete;
  void push(std::unique_ptr<Packet> packet);
  std::shared_ptr<Packet> pop();
  void close();

private:
  class Private;
  std::unique_ptr<Private> d;
};

#endif
