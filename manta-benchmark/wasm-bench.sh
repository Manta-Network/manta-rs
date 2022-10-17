#!/bin/sh

rm -rf bench-debug-pkg bench-release-pkg
wasm-pack build --debug --out-dir bench-debug-pkg
wasm-pack build --release --out-dir bench-release-pkg
cd ./www
npm install
npm run start