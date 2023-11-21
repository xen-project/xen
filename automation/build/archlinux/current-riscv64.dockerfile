FROM --platform=linux/amd64 archlinux
LABEL maintainer.name="The Xen Project" \
      maintainer.email="xen-devel@lists.xenproject.org"

# Packages needed for the build
RUN pacman --noconfirm --needed -Syu \
    base-devel \
    git \
    inetutils \
    riscv64-linux-gnu-binutils \
    riscv64-linux-gnu-gcc \
    riscv64-linux-gnu-glibc \
    # For test phase
    qemu-system-riscv

# Add compiler path
ENV CROSS_COMPILE=riscv64-linux-gnu-

RUN useradd --create-home user
USER user
WORKDIR /build
