# syntax=docker/dockerfile:1
FROM --platform=linux/amd64 archlinux:base-devel
LABEL maintainer.name="The Xen Project"
LABEL maintainer.email="xen-devel@lists.xenproject.org"

RUN <<EOF
#!/bin/bash
    set -eu

    useradd --create-home user

    pacman-key --init

    DEPS=(
        # Tools (general)
        git
        wget
        # libxenguest dombuilder
        lzo
        # libacpi
        iasl
        # Python bindings
        python-setuptools
        # Golang bindings
        go
    )

    pacman -S --refresh --sysupgrade --noconfirm --noprogressbar --needed "${DEPS[@]}"
    yes | pacman -S --clean --clean
EOF

USER user
WORKDIR /build
