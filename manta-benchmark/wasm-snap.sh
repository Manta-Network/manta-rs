#!/bin/sh

rm -r pkg
wasm-pack build --target web --release # --debug