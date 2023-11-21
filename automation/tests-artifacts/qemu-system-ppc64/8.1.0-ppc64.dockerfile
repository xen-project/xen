FROM --platform=linux/amd64 debian:bullseye-slim
LABEL maintainer.name="The Xen Project" \
      maintainer.email="xen-devel@lists.xenproject.org"

ENV DEBIAN_FRONTEND=noninteractive
ENV QEMU_VERSION=8.1.0
ENV USER root

RUN mkdir /build
WORKDIR /build

# build depends
RUN apt-get update && \
    apt-get --quiet --yes install \
        build-essential \
        curl \
        python3 \
        python3-pip \
        python3-elementpath \
        ninja-build \
        pkg-config \
        libglib2.0-dev \
        libpixman-1-dev \
        && \
    \
    curl -fsSLO https://download.qemu.org/qemu-"$QEMU_VERSION".tar.xz && \
    tar xvJf qemu-"$QEMU_VERSION".tar.xz && \
    cd qemu-"$QEMU_VERSION" && \
    ./configure --target-list=ppc64-softmmu && \
    make -j$(nproc) && \
    cp ./build/qemu-system-ppc64 / && \
    cp ./build/qemu-bundle/usr/local/share/qemu/skiboot.lid / && \
    cd /build && \
    rm -rf qemu-"$QEMU_VERSION"* && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists* /tmp/* /var/tmp/*
