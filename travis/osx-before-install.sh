brew update
brew install nvm gpg v8 rocksdb jq
export PATH=/usr/local/opt/gnupg/libexec/gpgbin:$PATH

mkdir ~/.nvm
export NVM_DIR=~/.nvm
. $(brew --prefix nvm)/nvm.sh

nvm install $NODE_VERSION
nvm use --delete-prefix $NODE_VERSION

export ELECTRON_VERSION=`jq .devDependencies.electron package.json -r`
echo $ELECTRON_VERSION

mkdir ~/.electron
curl -L -o ~/.electron/electron-v${ELECTRON_VERSION}-darwin-x64.zip https://github.com/electron/electron/releases/download/v${ELECTRON_VERSION}/electron-v${ELECTRON_VERSION}-darwin-x64.zip
curl -L -o ~/.electron/SHASUMS256.txt-${ELECTRON_VERSION} https://github.com/electron/electron/releases/download/v${ELECTRON_VERSION}/SHASUMS256.txt
npm install --depth 0 -g electron@${ELECTRON_VERSION}

export CC=clang
export CXX=clang++
