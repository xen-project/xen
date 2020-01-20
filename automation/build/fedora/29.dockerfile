FROM fedora:29
LABEL maintainer.name="The Xen Project" \
      maintainer.email="xen-devel@lists.xenproject.org"

RUN mkdir /build
WORKDIR /build

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
        gettext \
        flex \
        bison \
        libaio-devel \
        glib2-devel \
        yajl-devel \
        pixman-devel \
        glibc-devel \
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
    && dnf clean all && \
    rm -rf /var/cache/dnf
