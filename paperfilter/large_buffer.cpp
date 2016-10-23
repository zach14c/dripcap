#include "large_buffer.hpp"
#include "buffer.hpp"
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <fstream>
#include <random>
#include <sstream>
#include <v8pp/class.hpp>
#include <sys/stat.h>

#ifdef _WIN32
#include <direct.h>
#endif

namespace {
std::string randomId() {
  std::random_device dev;
  std::mt19937_64 generator(dev());
  std::uniform_int_distribution<int> dist(0, 255);
  std::stringstream stream;
  for (size_t i = 0; i < 16; ++i) {
    stream << std::hex << std::setfill('0') << std::setw(2) << dist(generator);
  }
  return stream.str();
}

std::string getTmpDir() {
  std::string path = "/tmp";
  const char *envs[] = {"TMP", "TEMP", "TMPDIR", "TEMPDIR"};
  for (const char *env : envs) {
    const char *tmp = std::getenv(env);
    if (tmp && strlen(tmp)) {
      path = tmp;
      break;
    }
  }
  path += "/paperfilter_" + randomId();
#ifdef _WIN32
  _mkdir(path.c_str());
#else
  mkdir(path.c_str(), 0755);
#endif
  return path;
}
}

std::string LargeBuffer::tmpDir() {
  static const std::string path = getTmpDir();
  return path;
}

class LargeBuffer::Private {
public:
  std::string id = randomId();
  std::ofstream ofs;
  std::ifstream ifs;
  int length = -1;
};

LargeBuffer::LargeBuffer() : d(new Private) {}

LargeBuffer::LargeBuffer(const LargeBuffer &other) : d(new Private) {
  *this = other;
}

LargeBuffer &LargeBuffer::operator=(const LargeBuffer &other) {
  if (&other == this)
    return *this;
  d->id = other.d->id;
  d->length = other.d->length;
  return *this;
}

LargeBuffer::~LargeBuffer() {}

std::string LargeBuffer::id() const { return d->id; }

std::string LargeBuffer::path() const { return tmpDir() + "/" + d->id; }

void LargeBuffer::write(const v8::FunctionCallbackInfo<v8::Value> &args) {
  if (!d->ofs.is_open()) {
    d->ofs.open(path(), std::ios::app | std::ios::binary);
  }
  if (d->ofs) {
    v8::Isolate *isolate = v8::Isolate::GetCurrent();
    if (Buffer *buffer =
            v8pp::class_<Buffer>::unwrap_object(isolate, args[0])) {
      d->ofs.write(buffer->data(), buffer->length());
      d->ofs.flush();
      if (d->length < 0)
        d->length = 0;
      d->length += buffer->length();
    } else if (LargeBuffer *buffer =
                   v8pp::class_<LargeBuffer>::unwrap_object(isolate, args[0])) {
      std::ifstream ifs;
      ifs.open(buffer->path(), std::ios::binary);
      while (ifs.good()) {
        char buf[2048];
        ifs.read(buf, sizeof(buf));
        d->ofs.write(buf, ifs.gcount());
      }
      d->ofs.flush();
    }
  }
}

void LargeBuffer::get(uint32_t index,
                      const Nan::PropertyCallbackInfo<v8::Value> &info) const {
  v8::Isolate *isolate = v8::Isolate::GetCurrent();
  if (index >= length()) {
    info.GetReturnValue().Set(v8pp::throw_ex(isolate, "index out of range"));
  } else {
    if (!d->ifs.is_open()) {
      d->ifs.open(path(), std::ios::binary);
    }
    d->ifs.seekg(index, std::ios::beg);
    info.GetReturnValue().Set(d->ifs.get());
  }
}

uint32_t LargeBuffer::length() const {
  if (d->length >= 0)
    return d->length;
  if (!d->ifs.is_open()) {
    d->ifs.open(path(), std::ios::binary);
    if (!d->ifs) {
      return 0;
    }
  }

  d->ifs.seekg(0, std::ios::end);
  d->length = d->ifs.tellg();
  d->ifs.seekg(0, std::ios::beg);
  return d->length;
}
