FROM ubuntu:xenial
MAINTAINER Venkkatesh Sekar

RUN apt-get -y update && \
    apt-get -y install build-essential curl clang git \
      cmake libelf-dev libelf1 libiberty-dev libboost-all-dev  && \
    ln -s /usr/bin/llvm-config-3.8 /usr/bin/llvm-config && \
    curl -L http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz | tar zxf - && \
    ( cd afl-* && make ) && \
    ( cd afl-*/llvm_mode && make ) && \
    ( cd afl-* && make install ) && \
    ln -s `ls -1d afl-* | head -1` afl && \
    rm -rf /afl* && \
    apt-get -y autoremove && \
    rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    pip3 install flask kafka

CMD /bin/bash