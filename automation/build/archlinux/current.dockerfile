FROM --platform=linux/amd64 archlinux:base-devel
LABEL maintainer.name="The Xen Project" \
      maintainer.email="xen-devel@lists.xenproject.org"

RUN pacman-key --init

RUN pacman -S --refresh --sysupgrade --noconfirm --noprogressbar --needed \
        bin86 \
        bridge-utils \
        bzip2 \
        dev86 \
        discount \
        dtc \
        e2fsprogs \
        ghostscript \
        git \
        gnutls \
        go \
        iasl \
        inetutils \
        iproute \
        # lib32-glibc for Xen < 4.15
        lib32-glibc \
        libaio \
        libcacard \
        libgl \
        libjpeg-turbo \
        libnl \
        libpng \
        libseccomp \
        net-tools \
        nss \
        perl \
        pixman \
        pkgconfig \
        python \
        python-setuptools \
        sdl \
        sdl2 \
        spice \
        spice-protocol \
        systemd \
        transfig \
        usbredir \
        wget \
        xz \
        yajl \
        zlib \
    && yes | pacman -S --clean --clean

ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/bin/site_perl:/usr/bin/vendor_perl:/usr/bin/core_perl

RUN useradd --create-home user
USER user
WORKDIR /build
