FROM ubuntu:focal

RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive TZ=UTC \
       apt-get install -y --no-install-recommends \
       llvm-8 clang-8 lld binutils cmake make openssh-client python git gdb lzma \
  && rm -rf /var/lib/apt/lists/*
RUN ln -s ../../lib/llvm-8/bin/opt     /usr/local/bin
RUN ln -s ../../lib/llvm-8/bin/llc     /usr/local/bin
RUN ln -s ../../lib/llvm-8/bin/llvm-mc /usr/local/bin
RUN ln -s ../../lib/llvm-8/bin/clang /usr/local/bin
COPY reopt/bin/reopt /usr/local/bin
COPY reopt/bin/reopt-explore /usr/local/bin
COPY reopt-vcg/bin/reopt-vcg /usr/local/bin
COPY reopt-vcg/bin/cvc4 /usr/local/bin

COPY reopt.vsix /usr/local/share/reopt/reopt.vsix
WORKDIR /root
