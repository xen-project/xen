FROM debian/eol:jessie
LABEL maintainer.name="The Xen Project" \
      maintainer.email="xen-devel@lists.xenproject.org"

ENV DEBIAN_FRONTEND=noninteractive
ENV USER root

RUN mkdir /build
WORKDIR /build

# replace repos in archive as release is EOL
RUN cat <<"END" > /etc/apt/sources.list
deb http://archive.debian.org/debian/ jessie main contrib non-free
deb http://archive.debian.org/debian/ jessie-backports main contrib non-free
deb http://archive.debian.org/debian-security/ jessie/updates main contrib non-free
END

# build depends
RUN apt-get update && \
    apt-get --quiet --yes install \
        build-essential \
        zlib1g-dev \
        libncurses5-dev \
        libssl-dev \
        python-dev \
        xorg-dev \
        uuid-dev \
        libyajl-dev \
        libaio-dev \
        libglib2.0-dev \
        clang \
        libpixman-1-dev \
        pkg-config \
        flex \
        bison \
        acpica-tools \
        bin86 \
        bcc \
        liblzma-dev \
        # libc6-dev-i386 for Xen < 4.15
        libc6-dev-i386 \
        libnl-3-dev \
        ocaml-nox \
        libfindlib-ocaml-dev \
        markdown \
        transfig \
        pandoc \
        checkpolicy \
        wget \
        git \
        nasm \
        && \
        apt-get autoremove -y && \
        apt-get clean && \
        rm -rf /var/lib/apt/lists* /tmp/* /var/tmp/*
