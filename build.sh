#!/bin/bash
export PATH="/usr/bin:/bin:$PATH"
current_dir=$(pwd)

if [ -d "build" ]; then
    rm -rf build
fi
mkdir -p build
cd build
../configure --target-list=loongarch64-softmmu --disable-werror --disable-kvm --enable-debug
make -j 256
cd ${current_dir}

