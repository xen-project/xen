FROM --platform=linux/amd64 centos:7
LABEL maintainer.name="The Xen Project" \
      maintainer.email="xen-devel@lists.xenproject.org"

RUN mkdir /build
WORKDIR /build

# work around https://github.com/moby/moby/issues/10180
# and add EPEL for dev86
RUN rpm --rebuilddb && \
    yum -y install \
        yum-plugin-ovl \
        epel-release \
    && yum clean all && \
    rm -rf /var/cache/yum

# install Xen depends
RUN yum -y update \
    && yum -y install \
        gcc \
        gcc-c++ \
        ncurses-devel \
        zlib-devel \
        openssl-devel \
        python-devel \
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
    && yum clean all && \
    rm -rf /var/cache/yum
