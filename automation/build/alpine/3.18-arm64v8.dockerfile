FROM --platform=linux/arm64/v8 alpine:3.18
LABEL maintainer.name="The Xen Project" \
      maintainer.email="xen-devel@lists.xenproject.org"

ENV USER root

RUN mkdir /build
WORKDIR /build

# build depends
RUN apk --no-cache add \
  \
  # xen build deps
  argp-standalone \
  autoconf \
  bash \
  bison \
  curl \
  dev86 \
  dtc-dev \
  flex \
  gcc \
  git \
  iasl \
  libaio-dev \
  libfdt \
  linux-headers \
  make \
  musl-dev  \
  ncurses-dev \
  ocaml \
  ocaml-findlib \
  patch  \
  python3-dev \
  py3-setuptools \
  texinfo \
  util-linux-dev \
  xz-dev \
  yajl-dev \
  zlib-dev \
  \
  # qemu build deps
  glib-dev \
  libattr \
  libcap-ng-dev \
  pixman-dev \
  # qubes test deps
  openssh-client \
  fakeroot \
