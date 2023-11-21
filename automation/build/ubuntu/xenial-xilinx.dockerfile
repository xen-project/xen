FROM --platform=linux/amd64 ubuntu:16.04
LABEL maintainer.name="The Xen Project " \
      maintainer.email="xen-devel@lists.xenproject.org"

ENV DEBIAN_FRONTEND=noninteractive
ENV USER root

RUN mkdir /build
WORKDIR /build

# board bringup depends
RUN apt-get update && \
    apt-get --quiet --yes install \
        snmp \
        snmp-mibs-downloader \
        u-boot-tools \
        device-tree-compiler \
        cpio \
        git \
        gzip \
        file \
        && \
        apt-get autoremove -y && \
        apt-get clean && \
        rm -rf /var/lib/apt/lists* /tmp/* /var/tmp/*
