FROM ubuntu:latest as build

LABEL maintainer="Venkkatesh Sekar"
ENV TZ=Europe/London
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

WORKDIR /agent

RUN apt-get -y update && \
    apt-get -y install build-essential curl clang git \
      cmake libelf-dev libelf1 libiberty-dev libboost-all-dev  && \
    ln -s /usr/bin/llvm-config-10 /usr/bin/llvm-config && \
    curl -L https://github.com/google/AFL/archive/refs/tags/v2.57b.tar.gz | tar zxf - &&\
    ( cd AFL-* && make ) && \
    ( cd AFL-*/llvm_mode && make ) && \
    ( cd AFL-* && make install ) && \
    ln -s `ls -1d AFL-* | head -1` afl && \
    rm -rf AFL-* && \
    apt-get -y autoremove && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements.txt

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    pip3 install --no-cache-dir -r requirements.txt

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc git && \
    git clone https://github.com/Rup0rt/pcapfix.git && \
    (cd pcapfix && make) && \
    (cd pcapfix && make install) && \
    rm -rf pcapfix && \
    apt-get -y autoremove && \
    rm -rf /var/lib/apt/lists/*

COPY *.py ./
COPY config/agent.cfg config/agent.cfg
COPY config/fuzzing.cfg config/fuzzing.cfg


CMD ["-f","/dev/null"]
ENTRYPOINT ["tail"]