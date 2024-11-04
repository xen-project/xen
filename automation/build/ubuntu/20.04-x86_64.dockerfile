# syntax=docker/dockerfile:1
FROM --platform=linux/amd64 ubuntu:20.04
LABEL maintainer.name="The Xen Project"
LABEL maintainer.email="xen-devel@lists.xenproject.org"

ENV DEBIAN_FRONTEND=noninteractive

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
        clang
        flex
        python3-minimal

        # Tools (general)
        ca-certificates
        git-core
        gzip
        patch
        perl
        pkg-config
        wget
        # libxenguest dombuilder
        libbz2-dev
        libzstd-dev
        liblzo2-dev
        liblzma-dev
        zlib1g-dev
        # libacpi
        acpica-tools
        # libxl
        uuid-dev
        libyajl-dev
        # RomBIOS
        bcc
        bin86
        # xentop
        libncurses5-dev
        # Python bindings
        python3-dev
        python3-setuptools
        # Ocaml bindings/oxenstored
        ocaml-nox
        ocaml-findlib

        # Stubdom download/extract
        bzip2

        # Qemu build
        libglib2.0-dev
        libpixman-1-dev
        meson
        ninja-build
        python3-packaging
    )

    apt-get -y --no-install-recommends install "${DEPS[@]}"
    rm -rf /var/lib/apt/lists/*
EOF

USER user
WORKDIR /build
