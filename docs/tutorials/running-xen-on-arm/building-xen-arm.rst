*******************
Building Xen on Arm 
*******************

There are two major components which need to be built for a Xen system. The Xen hypervisor binary itself and the Xen toolstack.

===================
Cross Compiling Xen
===================

Cross compiling the Xen hypervisor is simple. Linaro supply cross compilers for both arm32 (`arm-linux-gnueabihf-`) and arm64 (`aarch64-linux-gnu-`) via `linaro-toolchain-binaries <https://launchpad.net/linaro-toolchain-binaries>`__. Alternatively, for 32-bit at least, you can download the arm-unknown-linux-gnueabi compiler from `kernel.org <http://www.kernel.org/pub/tools/crosstool/files/bin/x86_64/>`__.

Once you have a suitable cross compiler you can compile Xen with:

.. code-block::

    $ make dist-xen XEN_TARGET_ARCH=arm32 CROSS_COMPILE=arm-unknown-linux-gnueabihf-

or,

.. code-block::

    $ make dist-xen XEN_TARGET_ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-

This assumes that the command prefix for you cross compiler is `arm-unknown-linux-gnueabihf-` or `aarch64-linux-gnu-` and that the appropriate `arm-unknown-linux-gnueabihf-gcc` or `aarch64-linux-gnu-gcc` and friends are in your `$PATH`.

======================
Building the Toolstack
======================

For a complete cross-compilation of the hypervisor and the toolstack, it is recommended to use Yocto, see Xen_on_ARM_and_Yocto. Alternatively, it is possible to use QEMU user to run an ARM64 chroot on a x86 host, i.e. an ARM64 Debian or Ubuntu container on a regular x86 laptop.

.. code-block::

    $ apt-get install qemu-user-static

It installs `/usr/bin/qemu-aarch64-static`.

Next setup an ARM64 chroot environment on your x86 machine. Follow your distro recommandations. For instance, the following distros offer pre-packaged tarballs ready to be unpackged:

- Ubuntu: `http://cdimage.ubuntu.com/ubuntu-base/releases/20.04/release/ubuntu-base-20.04-base-arm64.tar.gz <http://cdimage.ubuntu.com/ubuntu-base/releases/20.04/release/ubuntu-base-20.04-base-arm64.tar.gz>`__
- Alpine Linux: `http://dl-cdn.alpinelinux.org/alpine/v3.11/releases/aarch64/alpine-minirootfs-3.11.6-aarch64.tar.gz <http://dl-cdn.alpinelinux.org/alpine/v3.11/releases/aarch64/alpine-minirootfs-3.11.6-aarch64.tar.gz>`__

Assuming that the ARM64 chroot is under `/chroot/distro_arm64`, then you can:

.. code-block::

    $ cp /usr/bin/qemu-aarch64-static /chroot/distro_arm64/usr/bin/qemu-aarch64-static
    $ chroot /chroot/distro_arm64

Now you have a full Arm64 environment running on a regular x86 machine. You can automate all the last steps with the following Docker command (the example is running Debian):

.. code-block::

    $ docker run -it -v /usr/bin/qemu-aarch64-static:/usr/bin/qemu-aarch64-static arm64v8/debian /bin/bash

Inside your ARM64 environment you can follow the regular native compilation steps:

.. code-block::

    $ cd xen.git
      # install build dependencies with apt-get/apk/yum etc.
    $ ./configure
    $ make -j4

===============
Native Building
===============

In order to build the tools a native build environment is required. For 32-bit the developers mainly use the armhf port of Debian, which is present in Wheezy running on an IMX53 based development board, although any ARMv7 development board would do. Note that the build hardware does not need to support the virtualisation extensions, since you don't have to run Xen on the same system as where you build it.

See `Xen on Raspberry Pi <https://xenproject.org/2020/09/29/xen-on-raspberry-pi-4-adventures/>`__.