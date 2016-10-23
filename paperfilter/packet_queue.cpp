#include "packet_queue.hpp"
#include "packet.hpp"

class PacketQueue::Private {
public:
  std::queue<std::shared_ptr<Packet>> queue;
  std::mutex mutex;
  std::condition_variable cond;
  bool closed = false;
  uint32_t packetSeq = 0;
};

PacketQueue::PacketQueue() : d(new Private()) {}

PacketQueue::~PacketQueue() { close(); }

void PacketQueue::push(std::unique_ptr<Packet> pkt) {
  std::lock_guard<std::mutex> lock(d->mutex);
  if (d->closed)
    return;
  pkt->setSeq(++d->packetSeq);
  d->queue.push(std::move(pkt));
  d->cond.notify_one();
}

std::shared_ptr<Packet> PacketQueue::pop() {
  std::unique_lock<std::mutex> lock(d->mutex);
  d->cond.wait(lock, [this] { return !d->queue.empty() || d->closed; });
  if (d->closed)
    return std::shared_ptr<Packet>();
  std::shared_ptr<Packet> pkt = std::move(d->queue.front());
  d->queue.pop();
  return pkt;
}

void PacketQueue::close() {
  std::lock_guard<std::mutex> lock(d->mutex);
  d->closed = true;
  d->cond.notify_all();
}
