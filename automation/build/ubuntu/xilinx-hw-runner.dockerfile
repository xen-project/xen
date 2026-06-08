# syntax=docker/dockerfile:1
FROM --platform=linux/amd64 ubuntu:16.04
LABEL maintainer.name="The Xen Project"
LABEL maintainer.email="xen-devel@lists.xenproject.org"

ENV DEBIAN_FRONTEND=noninteractive

RUN <<EOF
#!/bin/bash
    set -e

    apt-get update

    DEPS=(
        ca-certificates
        cpio
        device-tree-compiler
        expect
        file
        git
        gzip
        snmp
        snmp-mibs-downloader
        u-boot-tools
    )

    apt-get -y --no-install-recommends install "${DEPS[@]}"
    rm -rf /var/lib/apt/lists/*
EOF

USER root
WORKDIR /build
