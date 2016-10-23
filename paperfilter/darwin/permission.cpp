#include "permission.hpp"
#include <cstdlib>
#include <dirent.h>
#include <string>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <unistd.h>

bool Permission::test() {
  DIR *dp = opendir("/dev");
  if (dp == nullptr)
    return false;

  bool ok = true;
  struct dirent *ep;
  while ((ep = readdir(dp))) {
    std::string name(ep->d_name);
    if (name.find("bpf") == 0) {
      struct stat buf;
      if (stat(("/dev/" + name).c_str(), &buf) < 0 ||
          !(buf.st_mode & S_IRGRP)) {
        ok = false;
        break;
      }
    }
  }

  closedir(dp);
  return ok;
}
