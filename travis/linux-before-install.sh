rm -rf ~/.nvm && git clone https://github.com/creationix/nvm.git ~/.nvm
(cd ~/.nvm && git checkout `git describe --abbrev=0 --tags`)
source ~/.nvm/nvm.sh
nvm install 7

sudo apt-key adv --keyserver pgp.mit.edu --recv D101F7899D41F3C3
echo "deb http://dl.yarnpkg.com/debian/ stable main" | sudo tee /etc/apt/sources.list.d/yarn.list

export CC="gcc-5"
export CXX="g++-5"
wget https://dripcap.org/storage/libpcap-1.7.4.tar.gz
tar xzf libpcap-1.7.4.tar.gz
(cd libpcap-1.7.4 && ./configure -q --enable-shared=no && make -j2 && sudo make install)

export DISPLAY=':99.0'
