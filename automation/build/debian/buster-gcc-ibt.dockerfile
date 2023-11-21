FROM --platform=linux/amd64 debian:buster-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive
ENV USER root

RUN apt-get update && \
    apt-get --quiet --yes --no-install-recommends install \
        bison \
        build-essential \
        ca-certificates \
        flex \
        g++-multilib \
        libc6-dev-i386 \
        libgmp-dev \
        libisl-dev \
        libmpc-dev \
        libmpfr-dev \
        patch \
        wget

RUN mkdir /build
WORKDIR /build

RUN wget -q https://ftp.gnu.org/gnu/gcc/gcc-11.3.0/gcc-11.3.0.tar.xz -O - | tar xJ --strip=1
RUN wget -q https://xenbits.xen.org/people/andrewcoop/gcc-11.2-Add-fcf-check-attribute-yes-no.patch -O - | patch -p1
RUN ./configure \
        --prefix=/opt/gcc-11-ibt \
        --enable-languages=c \
        --disable-nls \
        --disable-threads \
        --disable-bootstrap \
        --disable-shared \
        --disable-libmudflap \
        --disable-libssp \
        --disable-libgomp \
        --disable-decimal-float \
        --disable-libquadmath \
        --disable-libatomic \
        --disable-libcc1 \
        --disable-libmpx
RUN make -j`nproc` && make -j`nproc` install


FROM --platform=linux/amd64 debian:buster-slim
COPY --from=builder /opt/gcc-11-ibt /opt/gcc-11-ibt

LABEL maintainer.name="The Xen Project" \
      maintainer.email="xen-devel@lists.xenproject.org"

ENV DEBIAN_FRONTEND=noninteractive
ENV USER root
ENV PATH="/opt/gcc-11-ibt/bin:${PATH}"

RUN mkdir /build
WORKDIR /build

RUN apt-get update && \
    apt-get --quiet --yes --no-install-recommends install \
        bison \
        build-essential \
        checkpolicy \
        flex \
        gawk \
        make \
        python3-minimal \
        && \
        apt-get autoremove -y && \
        apt-get clean && \
        rm -rf /var/lib/apt/lists* /tmp/* /var/tmp/*
