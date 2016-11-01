#ifndef FILTER_HPP
#define FILTER_HPP

#include <v8.h>
#include <functional>

class Packet;

typedef std::function<v8::Local<v8::Value>(Packet *)> FilterFunc;

FilterFunc makeFilter(const std::string &jsonstr);

#endif
