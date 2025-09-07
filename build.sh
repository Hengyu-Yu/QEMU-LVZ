#!/bin/bash
current_dir=$(pwd)
mkdir -p build
cd build
../configure --target-list=loongarch64-softmmu --disable-werror --disable-kvm --enable-debug
make -j 256
cd ${current_dir}
