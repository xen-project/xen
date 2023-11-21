FROM --platform=linux/arm64/v8 debian:bookworm
LABEL maintainer.name="The Xen Project" \
      maintainer.email="xen-devel@lists.xenproject.org"

ENV DEBIAN_FRONTEND=noninteractive
ENV USER root
ENV CROSS_COMPILE /usr/bin/arm-linux-gnueabihf-

RUN mkdir /build
WORKDIR /build

# build depends
RUN apt-get update && \
    apt-get --quiet --yes install \
        build-essential \
        flex \
        bison \
        git \
        gcc-arm-linux-gnueabihf \
        && \
        apt-get autoremove -y && \
        apt-get clean && \
        rm -rf /var/lib/apt/lists* /tmp/* /var/tmp/*
