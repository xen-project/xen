FROM archlinux/base
LABEL maintainer.name="The Xen Project" \
      maintainer.email="xen-devel@lists.xenproject.org"

# Enable multilib repo, for dev86 package
RUN echo $'[multilib]\nInclude = /etc/pacman.d/mirrorlist' >> /etc/pacman.conf

RUN pacman -S --refresh --sysupgrade --noconfirm --noprogressbar --needed \
        base-devel \
        bin86 \
        bridge-utils \
        bzip2 \
        dev86 \
        dtc \
        e2fsprogs \
        ghostscript \
        git \
        gnutls \
        iasl \
        inetutils \
        iproute \
        lib32-glibc \
        libaio \
        libcacard \
        libgl \
        libjpeg-turbo \
        libnl \
        libpng \
        libseccomp \
        markdown \
        net-tools \
        nss \
        perl \
        pixman \
        pkgconfig \
        python \
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
        zlib

ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/bin/site_perl:/usr/bin/vendor_perl:/usr/bin/core_perl

RUN useradd --create-home user
USER user
WORKDIR /build
