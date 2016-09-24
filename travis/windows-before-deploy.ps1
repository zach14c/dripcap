if($env:APPVEYOR_REPO_TAG_NAME -ne $null){
  cd ../dripcap2
  $env:NOWINPCAP = ""
  npm install --depth 0 babel-plugin-add-module-exports babel-plugin-transform-async-to-generator babel-plugin-transform-es2015-modules-commonjs
  npm install --depth 0
  gulp win32
  mv .builtapp\Dripcap-win32-x64 .builtapp\Dripcap
  Compress-Archive -Path .builtapp\Dripcap -DestinationPath ..\dripcap\dripcap-windows-amd64.zip
}
