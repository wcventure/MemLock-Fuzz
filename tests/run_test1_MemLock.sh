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

if ! [ -d "${ROOT_DIR}/tool/MemLock/build/bin" ]; then
    ${ROOT_DIR}/tool/install_MemLock.sh
fi

export PATH=${ROOT_DIR}/clang+llvm/bin:$PATH
export LD_LIBRARY_PATH=${ROOT_DIR}/clang+llvm/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
export AFL_PATH=${ROOT_DIR}/tool/MemLock

if [ $(command llvm-config --version) == "6.0.1" ] && [ $(command llvm-config --version) == "12.0.0" ]; then
    echo ""
    echo "You can simply run tool/build_MemLock.sh to build the environment."
    echo ""
    echo "Please set:"
    echo "export PATH=$PREFIX/clang+llvm/bin:\$PATH"
    echo "export LD_LIBRARY_PATH=$PREFIX/clang+llvm/lib:\$LD_LIBRARY_PATH"
elif ! [ -d "${ROOT_DIR}/clang+llvm/bin"  ]; then
    echo ""
    echo "You can simply run tool/build_MemLock.sh to build the environment."
    echo ""
    echo "Please set:"
    echo "export PATH=$PREFIX/clang+llvm/bin:\$PATH"
    echo "export LD_LIBRARY_PATH=$PREFIX/clang+llvm/lib:\$LD_LIBRARY_PATH"
else
    echo "start ..."
    cd ${ROOT_DIR}/tests/test1
    ${ROOT_DIR}/tool/MemLock/build/bin/memlock-stack-clang -g -O0 -fsanitize=address example1.c -o example1MemLock
    if [ -d "${ROOT_DIR}/tests/test1/in"  ]; then
        rm -rf in
    fi
    mkdir in
    echo a > in/testcase
    i=0
    for ((i=1; i<100; i++))
    do
        if ! [ -d "${ROOT_DIR}/tests/test1/out_MemLock$i" ]; then
            break
        fi
    done
    export ASAN_OPTIONS=detect_odr_violation=0:allocator_may_return_null=1:abort_on_error=1:symbolize=0:detect_leaks=0
    ${ROOT_DIR}/tool/MemLock/build/bin/memlock-stack-fuzz -i ${ROOT_DIR}/tests/test1/in -o ${ROOT_DIR}/tests/test1/out_MemLock$i -m none -d -t 5000 -- ${ROOT_DIR}/tests/test1/example1MemLock @@
fi
