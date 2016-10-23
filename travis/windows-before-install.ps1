choco install jq make

Copy-Item -Path ../dripcap -Destination ../dripcap2 -Recurse

$env:NO_WPCAP = "true"
npm config set loglevel error
npm install --depth 0 -g gulp electron babel-cli node-gyp
npm install --depth 0 nan babel-plugin-add-module-exports babel-plugin-transform-async-to-generator babel-plugin-transform-es2015-modules-commonjs
npm install --depth 0
