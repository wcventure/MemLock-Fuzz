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

set -eux

LINUX_VER=${LINUX_VER:-ubuntu-16.04}
LLVM_VER=${LLVM_VER:-6.0.1}
PREFIX=${ROOT_DIR}

LLVM_DEP_URL=https://releases.llvm.org/${LLVM_VER}
TAR_NAME=clang+llvm-${LLVM_VER}-x86_64-linux-gnu-${LINUX_VER}

wget -c ${LLVM_DEP_URL}/${TAR_NAME}.tar.xz
tar -C ${PREFIX} -xf ${TAR_NAME}.tar.xz
rm ${TAR_NAME}.tar.xz
rm -rf ${PREFIX}/clang+llvm
mv ${PREFIX}/${TAR_NAME} ${PREFIX}/clang+llvm
cp -rf ${PREFIX}/clang+llvm/ ${PREFIX}/ua_asan
mv ${PREFIX}/ua_asan ${PREFIX}/clang+llvm

if [ -d "${ROOT_DIR}/tool/MemLock/LLVMlib_asan_6.0.1" ]; then
	rm -rf ${ROOT_DIR}/tool/MemLock/LLVMlib_asan_6.0.1
fi
git clone https://github.com/ICSE2020-MemLock/LLVMlib_asan.git ${ROOT_DIR}/tool/MemLock/LLVMlib_asan_6.0.1
tar -zxvf ${ROOT_DIR}/tool/MemLock/LLVMlib_asan_6.0.1/libclang_rt.asan-x86_64.tar.gz -C ${ROOT_DIR}/tool/MemLock/LLVMlib_asan_6.0.1
cp -rf ${ROOT_DIR}/tool/MemLock/LLVMlib_asan_6.0.1/* ${ROOT_DIR}/clang+llvm/ua_asan/lib/clang/6.0.1/lib/linux/
rm -rf ${ROOT_DIR}/tool/MemLock/LLVMlib_asan_6.0.1/

set +x
