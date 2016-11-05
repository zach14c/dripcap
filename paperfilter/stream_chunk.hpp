#ifndef STREAM_CHUNK_HPP
#define STREAM_CHUNK_HPP

#include <memory>
#include <unordered_map>
#include <string>
#include <v8.h>
#include "item_value.hpp"

class Layer;

class StreamChunk {
public:
  StreamChunk(v8::Local<v8::Object> obj);
  StreamChunk(const StreamChunk &stream);
  ~StreamChunk();
  StreamChunk &operator=(const StreamChunk &) = delete;
  std::string ns() const;
  std::string id() const;
  std::shared_ptr<Layer> layer() const;
  void setLayer(const std::shared_ptr<Layer> &layer);
  void setAttr(const std::string &name, v8::Local<v8::Value> obj);
  std::unordered_map<std::string, ItemValue> attrs() const;
  void setEnd(bool end);
  bool end() const;

private:
  class Private;
  std::shared_ptr<Private> d;
};

#endif
