FROM ubuntu:22.04

RUN apt-get update
RUN apt-get install -y software-properties-common

# System deps
RUN apt-get update
RUN apt-get install -y \
    autoconf \
    automake \
    build-essential \
    cmake \
    libtool \
    llvm-14 \
    llvm-14-dev \
    clang-14 \
    make \
    ninja-build \
    sudo \
    unzip \
    zlib1g-dev \
    patchelf

RUN apt-get clean autoclean
RUN apt-get autoremove -y

# Copy this code into place
COPY . /code

# Create a build directory
WORKDIR /build

RUN cmake -G Ninja /code -DCMAKE_BUILD_TYPE=RelWithDebInfo
RUN ninja
RUN ninja install
RUN patchelf --add-needed /usr/local/lib/libWAVM.so /usr/local/bin/wavm

WORKDIR /code/AFLplusplus
RUN make WAFL_MODE=1 TEST_MMAP=1 install


# setup example program for fuzzing
RUN apt-get install -y git wget tar
WORKDIR /
RUN wget -q https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-20/wasi-sdk-20.0-linux.tar.gz && \
    tar xvf wasi-sdk-20.0-linux.tar.gz
ENV WASI_SDK_PATH=/wasi-sdk-20.0
RUN git clone https://github.com/AFLplusplus/fuzzer-challenges
RUN cd fuzzer-challenges && \
    /wasi-sdk-20.0/bin/clang -O0 -g --target=wasm32-wasi test-u8.c -D__AFL_COMPILER -o test-u8.wasm

RUN cd fuzzer-challenges/libfuzzer && \
    /wasi-sdk-20.0/bin/clang++ -O0 -g --target=wasm32-wasi SimpleTest.cpp -fno-exceptions -D__AFL_COMPILER -o SimpleTest.wasm
ENV AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_BIN_CHECK=1
RUN mkdir /in && mkdir /out && echo seed > /in/seed

ENV __AFL_PERSISTENT=1 __AFL_SHM_FUZZ=1

# wavm crashes for the C++ SimpleTest.wasm :/
# CMD afl-fuzz -i /in/ -o /out/ wavm run /fuzzer-challenges/libfuzzer/SimpleTest.wasm
CMD afl-fuzz -i /in/ -o /out/ wavm run /fuzzer-challenges/test-u8.wasm
