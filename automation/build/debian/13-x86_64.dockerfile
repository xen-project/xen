# syntax=docker/dockerfile:1
FROM --platform=linux/amd64 debian:trixie-slim
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
        clang
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
        ocaml
        ocaml-findlib

        # for test phase, qemu-* jobs
        busybox-static
        expect
        openssl
        ovmf
        python3-virt-firmware
        qemu-system-x86
        sbsigntool

        # for build-each-commit-gcc
        ccache
    )

    apt-get -y --no-install-recommends install "${DEPS[@]}"

    # Strip the password off the snakeoil key to avoid sbsign wanting an
    # interactive prompt
    openssl rsa \
            -in  /usr/share/ovmf/PkKek-1-snakeoil.key \
            -out /usr/share/ovmf/PkKek-1-snakeoil-nopass.key \
            -passin pass:snakeoil
    chmod 644 /usr/share/ovmf/PkKek-1-snakeoil-nopass.key

    rm -rf /var/lib/apt/lists*
EOF

USER user
WORKDIR /build
