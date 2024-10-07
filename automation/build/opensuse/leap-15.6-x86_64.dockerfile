# syntax=docker/dockerfile:1
FROM --platform=linux/amd64 opensuse/leap:15.6
LABEL maintainer.name="The Xen Project"
LABEL maintainer.email="xen-devel@lists.xenproject.org"

ENV PYTHON=python3.11
ENV XEN_TARGET_ARCH=x86_64

RUN <<EOF
#!/bin/bash
    set -e

    useradd --create-home user

    zypper refresh
    zypper update -y --no-recommends

    DEPS=(
        # Xen
        bison
        checkpolicy
        clang
        diffutils
        findutils
        flex
        gawk
        gcc
        make
        python311

        # Tools (general)
        git-core
        gzip
        patch
        perl
        pkg-config
        wget
        # libxenguest dombuilder
        'pkgconfig(bzip2)'
        'pkgconfig(libzstd)'
        'pkgconfig(lzo2)'
        'pkgconfig(liblzma)'
        'pkgconfig(zlib)'
        # libacpi
        acpica
        # libxl
        'pkgconfig(uuid)'
        'pkgconfig(yajl)'
        # RomBIOS
        bin86
        dev86
        # Header Check
        gcc-c++
        # xentop
        'pkgconfig(ncurses)'
        # Python bindings
        python311-devel
        python311-setuptools
        # Ocaml bindings/oxenstored
        ocaml
        ocaml-findlib

        # Stubdom (download/extract)
        bzip2
        tar

        # Qemu build
        meson
        ninja
        'pkgconfig(glib-2.0)'
        'pkgconfig(pixman-1)'
        python311-packaging
    )

    zypper install -y --no-recommends "${DEPS[@]}"
    zypper clean -a
EOF

USER user
WORKDIR /build
