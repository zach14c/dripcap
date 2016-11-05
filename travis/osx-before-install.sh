brew update
brew install nvm gpg jq
nvm install 7

export PATH=/usr/local/opt/gnupg/libexec/gpgbin:$PATH
export CC=clang
export CXX=clang++
