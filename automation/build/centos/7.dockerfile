# syntax=docker/dockerfile:1
FROM --platform=linux/amd64 centos:7
LABEL maintainer.name="The Xen Project" \
      maintainer.email="xen-devel@lists.xenproject.org"

RUN mkdir /build
WORKDIR /build

RUN <<EOF
    set -e

    # Fix up Yum config now that mirror.centos.org doesn't exist
    sed -e 's/mirror.centos.org/vault.centos.org/g' \
        -e 's/^#.*baseurl=https\?/baseurl=https/g' \
        -e 's/^mirrorlist=https\?/#mirrorlist=https/g' \
        -i /etc/yum.repos.d/*.repo

    # Add the EPEL repo to get dev86
    yum -y install epel-release

    # Update everything (Base container is out of date)
    yum -y update

    DEPS=(
        # Xen
        binutils
        gcc
        make
        python
        # Kconfig
        bison
        flex
        # Flask
        checkpolicy

        # Tools (general)
        git
        gzip
        patch
        perl
        pkgconfig
        wget
        # libxenguest dombuilder
        bzip2-devel
        lz4-devel
        lzo-devel
        xz-devel
        zlib-devel
        zstd-devel
        # libacpi
        acpica-tools
        # libxl
        libuuid-devel
        yajl-devel
        # RomBIOS
        dev86
        # Header Check
        gcc-c++
        # xentop
        ncurses-devel
        # Python bindings
        python-devel

        # Stubdom download/extract
        bzip2
    )

    yum -y install "${DEPS[@]}"

    yum clean all
    rm -rf /var/cache/yum
EOF
