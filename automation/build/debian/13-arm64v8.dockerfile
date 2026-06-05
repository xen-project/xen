# syntax=docker/dockerfile:1
FROM --platform=linux/arm64/v8 debian:trixie-slim
LABEL maintainer.name="The Xen Project"
LABEL maintainer.email="xen-devel@lists.xenproject.org"

ENV DEBIAN_FRONTEND=noninteractive

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

        # Tools (general)
        ca-certificates
        cpio
        git-core
        pkg-config
        wget
        # libxenguest dombuilder
        libbz2-dev
        liblz4-dev
        liblzma-dev
        liblzo2-dev
        libzstd-dev
        zlib1g-dev
        # libacpi
        acpica-tools
        # libxl
        libfdt-dev
        libjson-c-dev
        uuid-dev
        # xentop
        libncurses5-dev
        # Python bindings
        python3-dev
        python3-setuptools
        # Golang bindings
        golang-go
        # Ocaml bindings/oxenstored
        ocaml
        ocaml-findlib

        # for test phase, qemu-* jobs
        busybox-static
        curl
        device-tree-compiler
        expect
        file
        ipxe-qemu
        ovmf
        qemu-system-aarch64
        u-boot-qemu
        u-boot-tools
    )

    apt-get -y --no-install-recommends install "${DEPS[@]}"

    rm -rf /var/lib/apt/lists*
EOF

USER user
WORKDIR /build
