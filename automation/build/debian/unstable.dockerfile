FROM debian:unstable
LABEL maintainer.name="The Xen Project" \
      maintainer.email="xen-devel@lists.xenproject.org"

ENV DEBIAN_FRONTEND=noninteractive
ENV USER root

RUN mkdir /build
WORKDIR /build

# build depends
RUN apt-get update && \
    apt-get --quiet --yes install \
        build-essential \
        zlib1g-dev \
        libncurses5-dev \
        libssl-dev \
        python-dev \
        python3-dev \
        xorg-dev \
        uuid-dev \
        libyajl-dev \
        libaio-dev \
        libglib2.0-dev \
        clang \
        libpixman-1-dev \
        pkg-config \
        flex \
        bison \
        gettext \
        acpica-tools \
        bin86 \
        bcc \
        liblzma-dev \
        libc6-dev-i386 \
        libnl-3-dev \
        ocaml-nox \
        libfindlib-ocaml-dev \
        markdown \
        transfig \
        pandoc \
        checkpolicy \
        wget \
        git \
        nasm \
        gnupg \
        apt-transport-https \
        golang \
        && \
        apt-get autoremove -y && \
        apt-get clean && \
        rm -rf /var/lib/apt/lists* /tmp/* /var/tmp/*

RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key|apt-key add -
COPY unstable-llvm-8.list /etc/apt/sources.list.d/

RUN apt-get update && \
    apt-get --quiet --yes install \
        clang-8 \
        lld-8 \
        && \
        apt-get autoremove -y && \
        apt-get clean && \
        rm -rf /var/lib/apt/lists* /tmp/* /var/tmp/*
