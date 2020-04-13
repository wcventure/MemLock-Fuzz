FROM ubuntu:16.04

RUN cp /etc/apt/sources.list /etc/apt/sources.list.bak
RUN sed -i s:/archive.ubuntu.com:/mirrors.tuna.tsinghua.edu.cn/ubuntu:g /etc/apt/sources.list
RUN apt-get clean
RUN apt-get update --fix-missing
RUN apt-get install -y wget git build-essential tmux cmake libtool automake autoconf autotools-dev m4 autopoint help2man bison flex texinfo zlib1g-dev libexpat1-dev libfreetype6 libfreetype6-dev sudo --fix-missing

RUN mkdir -p /workdir/MemLock

WORKDIR /workdir/MemLock
COPY . /workdir/MemLock

ENV PATH "/workdir/MemLock/clang+llvm/bin:$PATH"
ENV LD_LIBRARY_PATH "/workdir/MemLock/clang+llvm/lib:$LD_LIBRARY_PATH"

RUN tool/install_llvm.sh
RUN tool/install_MemLock.sh