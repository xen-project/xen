FROM --platform=linux/amd64 fedora:29
LABEL maintainer.name="The Xen Project" \
      maintainer.email="xen-devel@lists.xenproject.org"

# install Xen depends
RUN dnf -y install \
        clang \
        gcc \
        gcc-c++ \
        ncurses-devel \
        zlib-devel \
        openssl-devel \
        python-devel \
        python3-devel \
        libuuid-devel \
        pkgconfig \
        flex \
        bison \
        libaio-devel \
        glib2-devel \
        yajl-devel \
        pixman-devel \
        glibc-devel \
        # glibc-devel.i686 for Xen < 4.15
        glibc-devel.i686 \
        make \
        binutils \
        git \
        wget \
        acpica-tools \
        python-markdown \
        patch \
        checkpolicy \
        dev86 \
        xz-devel \
        bzip2 \
        nasm \
        ocaml \
        ocaml-findlib \
        golang \
        # QEMU
        ninja-build \
    && dnf clean all && \
    rm -rf /var/cache/dnf

RUN useradd --create-home user
USER user
WORKDIR /build
