chmod -R g-w debian
gulp debian
cd .debian
chrpath -r /usr/share/dripcap ./usr/share/dripcap/dripcap
fakeroot dpkg-deb --build . ../dripcap-linux-amd64.deb
cd ..
fakeroot alien --to-rpm -k --scripts dripcap-linux-amd64.deb
mv *.rpm dripcap-linux-amd64.rpm
