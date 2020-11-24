FROM arm64v8/debian:unstable
LABEL maintainer.name="The Xen Project" \
      maintainer.email="xen-devel@lists.xenproject.org"

ENV DEBIAN_FRONTEND=noninteractive
ENV LINUX_VERSION=5.9.9
ENV USER root

RUN mkdir /build
WORKDIR /build

# build depends
RUN apt-get update && \
    apt-get --quiet --yes install \
        build-essential \
        libssl-dev \
        bc \
        curl \
        flex \
        bison \
        && \
    \
    # Build the kernel
    curl -fsSLO https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-"$LINUX_VERSION".tar.xz && \
    tar xvJf linux-"$LINUX_VERSION".tar.xz && \
    cd linux-"$LINUX_VERSION" && \
    make defconfig && \
    make -j$(nproc) Image.gz && \
    cp arch/arm64/boot/Image / && \
    cd /build && \
    rm -rf linux-"$LINUX_VERSION"* && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists* /tmp/* /var/tmp/*
