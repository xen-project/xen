# syntax=docker/dockerfile:1
FROM --platform=linux/amd64 debian:bookworm
LABEL maintainer.name="The Xen Project"
LABEL maintainer.email="xen-devel@lists.xenproject.org"

ENV DEBIAN_FRONTEND=noninteractive

RUN <<EOF
#!/bin/bash
    set -eu

    apt-get update

    DEPS=(
        # Xen
        bison
        build-essential
        checkpolicy
        clang
        flex

        # Tools (general)
        ca-certificates
        git-core
        pkg-config
        wget
        # libxenguest dombuilder
        libbz2-dev
        liblzma-dev
        liblzo2-dev
        libzstd-dev
        zlib1g-dev
        # libacpi
        acpica-tools
        # libxl
        uuid-dev
        libnl-3-dev
        libyajl-dev
        # RomBIOS
        bcc
        bin86
        # xentop
        libncurses5-dev
        # Python bindings
        python3-dev
        python3-setuptools
        # Golang bindings
        golang-go
        # Ocaml bindings/oxenstored
        ocaml-nox
        ocaml-findlib

        # for test phase, qemu-smoke-* jobs
        expect
        qemu-system-x86

        # for qemu-alpine-x86_64-gcc
        busybox-static
        cpio

        # For *-efi jobs
        ovmf
    )

    apt-get -y --no-install-recommends install "${DEPS[@]}"

    rm -rf /var/lib/apt/lists*
EOF

USER root
WORKDIR /build
