# syntax=docker/dockerfile:1
FROM --platform=linux/arm64/v8 alpine:3.24
LABEL maintainer.name="The Xen Project"
LABEL maintainer.email="xen-devel@lists.xenproject.org"

RUN apk --no-cache add bash

RUN <<EOF
#!/bin/bash
    set -eu

    adduser -D user

    DEPS=(
        # Xen
        bison
        flex
        g++
        gcc
        make

        # Tools (general)
        argp-standalone
        autoconf
        git
        linux-headers
        patch
        # libxenguest dombuilder
        bzip2-dev
        xz-dev
        zlib-dev
        zstd-dev
        # libacpi
        iasl
        # libxl
        dtc-dev
        json-c-dev
        util-linux-dev
        # xentop
        ncurses-dev
        # Python bindings
        python3-dev
        py3-setuptools
        # Ocaml bindings/oxenstored
        ocaml
        ocaml-findlib
    )

    apk add --no-cache "${DEPS[@]}"
EOF

USER user
WORKDIR /build
