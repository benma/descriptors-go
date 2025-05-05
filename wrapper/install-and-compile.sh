#!/bin/bash

apt-get update
apt-get install -y \
    clang-16 gcc-multilib

ln -s /usr/bin/clang-16 /usr/local/bin/clang

rustup target add wasm32-wasip1
cargo build --release --target wasm32-wasip1

chmod -R 777 target
