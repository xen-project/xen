FROM --platform=linux/arm64/v8 alpine:3.18
LABEL maintainer.name="The Xen Project" \
      maintainer.email="xen-devel@lists.xenproject.org"

ENV USER root

RUN mkdir /build
WORKDIR /build

RUN \
  # apk
  apk update && \
  \
  # xen runtime deps
  apk add musl && \
  apk add openrc && \
  apk add busybox && \
  apk add sudo && \
  apk add dbus && \
  apk add bash && \
  apk add python3 && \
  apk add zlib && \
  apk add ncurses && \
  apk add texinfo && \
  apk add yajl && \
  apk add libaio && \
  apk add xz-dev && \
  apk add util-linux && \
  apk add argp-standalone && \
  apk add libfdt && \
  apk add glib && \
  apk add pixman && \
  apk add curl && \
  apk add udev && \
  \
  # Xen
  cd / && \
  # Minimal ramdisk environment in case of cpio output
  rc-update add udev && \
  rc-update add udev-trigger && \
  rc-update add udev-settle && \
  rc-update add networking sysinit && \
  rc-update add loopback sysinit && \
  rc-update add bootmisc boot && \
  rc-update add devfs sysinit && \
  rc-update add dmesg sysinit && \
  rc-update add hostname boot && \
  rc-update add hwclock boot && \
  rc-update add hwdrivers sysinit && \
  rc-update add killprocs shutdown && \
  rc-update add modloop sysinit && \
  rc-update add modules boot && \
  rc-update add mount-ro shutdown && \
  rc-update add savecache shutdown && \
  rc-update add sysctl boot && \
  rc-update add local default && \
  cp -a /sbin/init /init && \
  echo "ttyS0" >> /etc/securetty && \
  echo "hvc0" >> /etc/securetty && \
  echo "ttyS0::respawn:/sbin/getty -L ttyS0 115200 vt100" >> /etc/inittab && \
  echo "hvc0::respawn:/sbin/getty -L hvc0 115200 vt100" >> /etc/inittab && \
  passwd -d "root" root && \
  \
  # Create rootfs
  cd / && \
  tar cvzf /initrd.tar.gz bin dev etc home init lib mnt opt root sbin usr var
