# syntax=docker/dockerfile:1
FROM --platform=linux/amd64 debian:bullseye-slim
LABEL maintainer.name="The Xen Project"
LABEL maintainer.email="xen-devel@lists.xenproject.org"

ENV DEBIAN_FRONTEND=noninteractive
ENV CROSS_COMPILE=riscv64-linux-gnu-
ENV XEN_TARGET_ARCH=riscv64

RUN <<EOF
#!/bin/bash
    set -e

    useradd --create-home user

    apt-get update

    DEPS=(
        # Xen
        bison
        build-essential
        checkpolicy
        flex
        gcc-riscv64-linux-gnu
        python3-minimal
    )

    apt-get -y --no-install-recommends install "${DEPS[@]}"
    rm -rf /var/lib/apt/lists/*
EOF

USER user
WORKDIR /build
