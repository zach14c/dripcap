#ifndef FILTERED_PACKET_STORE_HPP
#define FILTERED_PACKET_STORE_HPP

#include <vector>
#include <memory>
#include <functional>

class FilteredPacketStore {
public:
  FilteredPacketStore();
  ~FilteredPacketStore();
  FilteredPacketStore(const FilteredPacketStore &) = delete;
  FilteredPacketStore &operator=(const FilteredPacketStore &) = delete;
  void insert(uint32_t seq, bool match);
  std::vector<uint32_t> get(uint32_t start, uint32_t end) const;
  uint32_t get(uint32_t index) const;
  uint32_t size() const;
  int addHandler(const std::function<void(uint32_t)> &cb);
  void removeHandler(int id);

private:
  class Private;
  std::unique_ptr<Private> d;
};

#endif
