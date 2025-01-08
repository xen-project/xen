# syntax=docker/dockerfile:1
FROM --platform=linux/amd64 fedora:41
LABEL maintainer.name="The Xen Project"
LABEL maintainer.email="xen-devel@lists.xenproject.org"

RUN <<EOF
    set -e

    useradd --create-home user

    dnf -y update

    DEPS=(
        # Xen
        binutils
        gcc
        make
        python3
        # Kconfig
        bison
        flex
        # Flask
        checkpolicy

        # Tools (general)
        git-core
        gzip
        patch
        perl-interpreter
        perl-File-Find
        pkgconfig
        wget
        # libxenguest dombuilder
        bzip2-devel
        libzstd-devel
        lzo-devel
        xz-devel
        zlib-devel
        # libacpi
        acpica-tools
        # libxl
        libuuid-devel
        yajl-devel
        # xen-foreign
        diffutils
        # RomBIOS
        dev86
        # Header Check
        gcc-c++
        # xentop
        ncurses-devel
        # Python bindings
        python3-devel
        python3-setuptools
        # Ocaml bindings/oxenstored
        ocaml
        ocaml-findlib
        # Golang bindings
        golang

        # Stubdom download/extract
        bzip2

        # Qemu build
        glib2-devel
        pixman-devel
        ninja-build
    )

    dnf -y --setopt=install_weak_deps=False install "${DEPS[@]}"

    dnf clean all
    rm -rf /var/cache/dnf
EOF

USER user
WORKDIR /build
