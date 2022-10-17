#!/bin/sh

rm -rf snap-debug-pkg snap-release-pkg
wasm-pack build --debug --target web --out-dir snap-debug-pkg
wasm-pack build --release --target web --out-dir snap-release-pkg