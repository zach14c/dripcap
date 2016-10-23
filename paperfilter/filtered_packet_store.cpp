#include "filtered_packet_store.hpp"
#include <map>
#include <unordered_map>
#include <uv.h>

class FilteredPacketStore::Private {
public:
  Private();
  ~Private();

public:
  uv_rwlock_t rwlock;
  std::unordered_map<int, std::function<void(uint32_t)>> handlers;
  uint32_t maxSeq = 0;
  std::map<uint32_t, bool> queue;
  std::vector<uint32_t> packets;
};

FilteredPacketStore::Private::Private() { uv_rwlock_init(&rwlock); }

FilteredPacketStore::Private::~Private() { uv_rwlock_destroy(&rwlock); }

FilteredPacketStore::FilteredPacketStore() : d(new Private()) {}

FilteredPacketStore::~FilteredPacketStore() {}

std::vector<uint32_t> FilteredPacketStore::get(uint32_t start,
                                               uint32_t end) const {
  std::vector<uint32_t> seq;
  if (start > end)
    return seq;
  uv_rwlock_rdlock(&d->rwlock);
  for (uint32_t i = start; i <= end && i < d->packets.size(); ++i)
    seq.push_back(d->packets[i]);
  uv_rwlock_rdunlock(&d->rwlock);
  return seq;
}

uint32_t FilteredPacketStore::get(uint32_t index) const {
  uint32_t seq = 0;
  uv_rwlock_rdlock(&d->rwlock);
  if (index < d->packets.size())
    seq = d->packets[index];
  uv_rwlock_rdunlock(&d->rwlock);
  return seq;
}

void FilteredPacketStore::insert(uint32_t seq, bool match) {
  uv_rwlock_wrlock(&d->rwlock);
  d->queue[seq] = match;
  uint32_t maxSeq = d->maxSeq;
  auto it = d->queue.find(maxSeq + 1);
  for (; it != d->queue.end(); maxSeq++, it = d->queue.find(maxSeq + 1)) {
    if (it->second) {
      d->packets.push_back(it->first);
    }
  }
  if (d->maxSeq < maxSeq) {
    d->maxSeq = maxSeq;
    d->queue.erase(d->queue.begin(), it);
    for (const auto &pair : d->handlers) {
      if (pair.second)
        pair.second(size());
    }
  }
  uv_rwlock_wrunlock(&d->rwlock);
}

uint32_t FilteredPacketStore::size() const { return d->packets.size(); }

int FilteredPacketStore::addHandler(const std::function<void(uint32_t)> &cb) {
  static int handlerId = 0;
  int id = ++handlerId;
  uv_rwlock_wrlock(&d->rwlock);
  d->handlers[id] = cb;
  uv_rwlock_wrunlock(&d->rwlock);
  return id;
}

void FilteredPacketStore::removeHandler(int id) {
  uv_rwlock_wrlock(&d->rwlock);
  d->handlers.erase(id);
  uv_rwlock_wrunlock(&d->rwlock);
}
