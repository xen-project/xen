FROM alpine:3.12
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
  clang \
  curl \
  dev86 \
  flex \
  g++ \
  gcc \
  git \
  grep \
  iasl \
  libaio-dev \
  libc6-compat \
  linux-headers \
  make \
  musl-dev  \
  ncurses-dev \
  ocaml \
  ocaml-findlib \
  patch  \
  python3-dev \
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
  ninja \
  pixman-dev \
