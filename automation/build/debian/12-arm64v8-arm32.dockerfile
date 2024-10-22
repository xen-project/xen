# syntax=docker/dockerfile:1
FROM --platform=linux/arm64/v8 debian:bookworm-slim
LABEL maintainer.name="The Xen Project"
LABEL maintainer.email="xen-devel@lists.xenproject.org"

ENV DEBIAN_FRONTEND=noninteractive
ENV CROSS_COMPILE=/usr/bin/arm-linux-gnueabihf-

RUN <<EOF
#!/bin/bash
    set -eu

    useradd --create-home user

    apt-get update

    DEPS=(
        # Xen
        bison
        build-essential
        checkpolicy
        flex
        gcc-arm-linux-gnueabihf
    )

    apt-get --yes --no-install-recommends install "${DEPS[@]}"

    rm -rf /var/lib/apt/lists*
EOF

USER user
WORKDIR /build
