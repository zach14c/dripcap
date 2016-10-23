#!/usr/bin/env bash

if [[ "$TRAVIS_OS_NAME" == "linux" ]]; then
  export CC=gcc-5
  export CXX=g++-5
  export DISPLAY=:99.0
  sh -e /etc/init.d/xvfb start +extension RANDR;
  sleep 3

  curl -O https://dripcap.org/storage/libpcap-1.7.4.tar.gz
  tar xzf libpcap-1.7.4.tar.gz
  (cd libpcap-1.7.4 && ./configure -q --enable-shared=no && make -j2 && sudo make install)
fi

if [[ "$TRAVIS_OS_NAME" == "osx" ]]; then
  brew update > /dev/null
  brew install jq

  curl -o- -L https://yarnpkg.com/install.sh | bash
  export PATH="$HOME/.yarn/bin:$PATH"

  yarn global add node-gyp mocha
  yarn
fi

npm install --depth 0 -g node-gyp mocha
npm install --depth 0

for i in {1..10}; do npm test; test $? -ne 0 && exit 1; done
exit 0
