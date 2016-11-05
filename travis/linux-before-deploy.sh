chmod -R g-w debian
gulp out
gulp debian
mv .builtapp/Dripcap-linux-x64 .debian/usr/share/dripcap
mv .debian/usr/share/dripcap/Dripcap .debian/usr/share/dripcap/dripcap
cd .debian
chrpath -r /usr/share/dripcap ./usr/share/dripcap/dripcap
fakeroot dpkg-deb --build . ../dripcap-linux-amd64.deb
cd ..
fakeroot alien --to-rpm -k --scripts dripcap-linux-amd64.deb
mv *.rpm dripcap-linux-amd64.rpm
