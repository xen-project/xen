# syntax=docker/dockerfile:1
FROM --platform=linux/i386 debian:bookworm
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
        git-core
        pkg-config
        wget
        # libacpi
        acpica-tools
        # libxl
        uuid-dev
        libyajl-dev
        # xentop
        libncurses5-dev
        # Python bindings
        python3-dev
        python3-setuptools
        # Ocaml bindings/oxenstored
        ocaml-nox
        ocaml-findlib
    )

    apt-get -y --no-install-recommends install "${DEPS[@]}"

    rm -rf /var/lib/apt/lists*
EOF

USER user
WORKDIR /build
ENTRYPOINT ["linux32"]
