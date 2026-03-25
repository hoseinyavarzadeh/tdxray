#!/bin/bash

rm -rf llama.cpp
git clone https://github.com/ggml-org/llama.cpp
cd llama.cpp
git checkout 381174bbdaf10d6a80dc2099f284b20544d86962
git apply ../0000-llama-cpp.patch
mkdir build && cd build
cmake -S .. -DCMAKE_INSTALL_PREFIX="/usr"
make -j$(nproc)
sudo make install

