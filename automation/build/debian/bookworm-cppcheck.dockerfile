FROM --platform=linux/arm64/v8 debian:bookworm AS builder

ENV DEBIAN_FRONTEND=noninteractive
ENV CPPCHECK_VERSION=2.7
ENV USER root

# dependencies for cppcheck build
RUN apt-get update && \
    apt-get --quiet --yes install \
        curl \
        build-essential \
        python-is-python3 \
        libpcre3-dev

RUN mkdir /build
WORKDIR /build

# cppcheck release build (see cppcheck readme.md)
RUN curl -fsSLO https://github.com/danmar/cppcheck/archive/"$CPPCHECK_VERSION".tar.gz && \
    tar xvzf "$CPPCHECK_VERSION".tar.gz && \
    cd cppcheck-"$CPPCHECK_VERSION" && \
    make install -j$(nproc) \
        MATCHCOMPILER=yes \
        FILESDIR=/usr/share/cppcheck \
        HAVE_RULES=yes CXXFLAGS="-O2 -DNDEBUG -Wall -Wno-sign-compare -Wno-unused-function"

FROM --platform=linux/arm64/v8 debian:bookworm
COPY --from=builder /usr/bin/cppcheck /usr/bin/cppcheck
COPY --from=builder /usr/share/cppcheck /usr/share/cppcheck

LABEL maintainer.name="The Xen Project" \
      maintainer.email="xen-devel@lists.xenproject.org"

ENV DEBIAN_FRONTEND=noninteractive
ENV USER root

RUN mkdir /build
WORKDIR /build

# dependencies for cppcheck analysis including Xen-only build/cross-build
RUN apt-get update && \
    apt-get --quiet --yes install \
        build-essential \
        python-is-python3 \
        libpcre3-dev \
        flex \
        bison \
        gcc-arm-linux-gnueabihf \
        gcc-x86-64-linux-gnu \
        && \
        apt-get autoremove -y && \
        apt-get clean && \
        rm -rf /var/lib/apt/lists* /tmp/* /var/tmp/*
