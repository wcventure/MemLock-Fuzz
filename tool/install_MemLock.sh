#!/bin/bash

# For Mac
if [ $(command uname) = "Darwin" ]; then
    if ! [ -x "$(command -v greadlink)"  ]; then
        brew install coreutils
    fi
    BIN_PATH=$(greadlink -f "$0")
    ROOT_DIR=$(dirname $(dirname $BIN_PATH))
# For Linux
else
    BIN_PATH=$(readlink -f "$0")
    ROOT_DIR=$(dirname $(dirname $BIN_PATH))
fi

set -euxo pipefail

if ! [ -d "${ROOT_DIR}/clang+llvm"  ]; then
	${ROOT_DIR}/tool/install_llvm.sh
fi

export PATH=${ROOT_DIR}/clang+llvm/bin:$PATH
export LD_LIBRARY_PATH=${ROOT_DIR}/clang+llvm/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
export CC=clang
export CXX=clang++

PREFIX=${PREFIX:-${ROOT_DIR}/tool/MemLock/build}



cd ${ROOT_DIR}/tool/MemLock
make clean
make
cd ${ROOT_DIR}/tool/MemLock/llvm_mode
make
cd ${ROOT_DIR}/tool/MemLock
make install

cd ${ROOT_DIR}/tool/AFL-2.52b
make clean
make
cd ${ROOT_DIR}/tool/AFL-2.52b/llvm_mode
make
cd ${ROOT_DIR}/tool/AFL-2.52b
make install
