************
Installation
************

=============
Prerequisites
=============



=============================================
Installing the Xen Project Software on Distro
=============================================

The Debian Xen Project packages consist primarily of a Xen Project-enabled Linux kernel, the hypervisor itself, a modified version of QEMU that support the hypervisor’s HVM mode and a set of userland tools.

All of this can be installed via an Apt meta-package called xen-linux-system. A meta-package is basically a way of installing a group of packages automatically. Apt will of course resolve all dependencies and bring in all the extra libraries we need.

Let's install the xen-linux-system meta-package:

.. code-block::
        
        apt-get install xen-system-amd64

Now we have a Xen Project hypervisor, a Xen Project kernel and the userland tools installed. When you next boot the system, the boot menu should include entries for starting Debian with the Xen hypervisor. One of them should be highlighted, to start Xen by default. Do that now, logging in as root again.

Next, let's check to see if virtualization is enabled in the BIOS. There are a few ways to do that.

The most comprehensive is to review the Xen section of dmesg created during the boot process. This will be your first use of xl, the very versatile Xen tool, which we will come back to shortly to create and manage domUs:

.. code-block::
        
        xl dmesg

Included in the output will be references to the CPU flags set in the BIOS to enable virtualization: 'vmx' for Intel, 'svm' for AMD. It will also detail other hardware virtualization extensions: VT-d features, Hardware Assisted Paging (HAP), I/O Virtualization and so on.

Another way is to check the flags set in the CPU on boot:

.. code-block::
        
        egrep '(vmx|svm|hypervisor)' /proc/cpuinfo

egrep will return any line containing one or more of those same text fragments (vmx/svm or more recently, just 'hypervisor'). If nothing comes back and you think it should, you may wish to look through the flags yourself:

.. code-block::
        
        cat /proc/cpuinfo
        
If the virtualization extensions don't appear, take a closer look at the BIOS settings. A few round-trips through the BIOS are often required to get all the bits working right.

======================================
Installing the Xen Project from Source
======================================

Prerequisites
~~~~~~~~~~~~~

A number of prerequisites are required for building a Xen source release. Ensure that you have all the following installed, either by visiting the project webpage or installing a pre-built package provided by your OS distributor:

    * GNU Make v3.80 or later
    * C compiler and linker:
      - For x86:
        - GCC 4.1.2_20070115 or later
        - GNU Binutils 2.16.91.0.5 or later
        or
        - Clang/LLVM 3.5 or later
      - For ARM:
        - GCC 4.8 or later
        - GNU Binutils 2.24 or later
    * Development install of zlib (e.g., zlib-dev)
    * Development install of Python 2.6 or later (e.g., python-dev)
    * Development install of curses (e.g., libncurses-dev)
    * Development install of openssl (e.g., openssl-dev)
    * Development install of x11 (e.g. xorg-x11-dev)
    * Development install of uuid (e.g. uuid-dev)
    * Development install of yajl (e.g. libyajl-dev)
    * Development install of libaio (e.g. libaio-dev) version 0.3.107 or greater.
    * Development install of GLib v2.0 (e.g. libglib2.0-dev)
    * Development install of Pixman (e.g. libpixman-1-dev)
    * pkg-config
    * bridge-utils package (/sbin/brctl)
    * iproute package (/sbin/ip)
    * GNU bison and GNU flex
    * GNU gettext
    * ACPI ASL compiler (iasl)

In addition to the above, there are a number of optional build prerequisites. Omitting these will cause the related features to be disabled at compile time:

    * Development install of Ocaml (e.g. ocaml-nox and ocaml-findlib). Required to build ocaml components which includes the alternative ocaml xenstored.
    * cmake (if building vtpm stub domains)
    * pandoc, transfig, pod2{man,html,text} for rendering various pieces of documentation into alternative formats
    * figlet (for generating the traditional Xen start of day banner)
    * systemd daemon development files
    * Development install of libnl3 (e.g., libnl-3-200, libnl-3-dev, etc). Required if network buffering is desired when using Remus with libxl.  See docs/README.remus for detailed information.
    * 16-bit x86 assembler, loader and compiler for qemu-traditional / rombios (dev86 rpm or bin86 & bcc debs)
    * Development install of liblzma for rombios
    * Development install of libbz2, liblzma, liblzo2, and libzstd for DomU kernel decompression.

.. note:: You need to acquire a suitable kernel for use in domain 0. If possible, use a kernel provided by your OS distributor. If no suitable kernel is available from your OS distributor then refer to `Xen Dom0 Kernels <https://wiki.xen.org/wiki/XenDom0Kernels>`__ for suggestions for suitable kernels to use. If you are looking to compile a Dom0 kernel from source, see `XenParavirtOps <https://wiki.xen.org/wiki XenParavirtOps>`__.

Building and Installing Xen
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. important:: Unless noted otherwise, all the following steps should be
performed with root privileges.

1. Download and untar the source tarball file. This will be a
   file named xen-unstable-src.tgz, or xen-$version-src.tgz.
   You can also pull the current version from the git or mercurial
   repositories at `https://xenbits.xen.org/ <https://xenbits.xen.org/>`__.

    .. code-block::
    
        # tar xzf xen-unstable-src.tgz

   Assuming you are using the unstable tree, this will untar into xen-unstable. The rest of the instructions
   use the unstable tree as an example, substitute the version for unstable.

2. cd to xen-unstable (or, whatever you have renamed it to).

3. For the very first build, or if you want to destroy build trees, perform the following steps:

    .. code-block::

        # ./configure
        # make world
        # make install

   See the documentation in the INSTALL file for more information.

   This will create and install onto the local machine. It will build
   the xen binary (xen.gz), the tools and the documentation.

   You can override the destination for make install by setting DESTDIR
   to some value.

4. To rebuild an existing tree without modifying the config:
   
    .. code-block::

                # make dist

   This will build and install xen, tools, and docs into the local dist/
   directory.

   You can override the destination for make install by setting DISTDIR
   to some value.

   make install and make dist differ in that make install does the
   right things for your local machine (installing the appropriate
   version of udev scripts, for example), but make dist includes all
   versions of those scripts, so that you can copy the dist directory
   to another machine and install from that distribution.

xenstore: xenstored and oxenstored
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Xen uses a configuration database called xenstore [0] to maintain configuration and status information shared between domains. A daemon is implemented as part of xenstore to act as an interface for access to the database for dom0 and guests. Two xenstored daemons are supported, one written in C which we refer
to as the xenstored (sometimes referred to as cxenstored), and another written in Ocaml called oxenstored. Details for xenstore and the different implementations can be found on the wiki's xenstore reference guide [1] and the xenstored [2] page. You can choose which xenstore you want to enable as default on a system through configure:

        ./configure --with-xenstored=xenstored
        ./configure --with-xenstored=oxenstored

By default oxenstored will be used if the ocaml development tools are found.
If you enable oxenstored the xenstored will still be built and installed,
the xenstored used can be changed through the configuration file:

/etc/sysconfig/xencommons
or
/etc/default/xencommons

You can change the preferred xenstored you want to use in the configuration
but since we cannot stop the daemon a reboot will be required to make the
change take effect.

[0] https://wiki.xen.org/wiki/XenStore
[1] https://wiki.xen.org/wiki/XenStoreReference
[2] https://wiki.xen.org/wiki/Xenstored

Python Runtime Libraries
~~~~~~~~~~~~~~~~~~~~~~~~

Various tools, such as pygrub, have the following runtime dependencies:

    * Python 2.6 or later.
          URL:    http://www.python.org/
          Debian: python

Note that the build system expects `python` to be available. If your system only has `python2` or `python3` but not `python` (as in Linux From Scratch), you will need to create a symlink for it, or specify PYTHON= when invoking make, like (note the position of PYTHON= matters):

    # make PYTHON=/usr/bin/python3

Intel(R) Trusted Execution Technology Support
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Intel's technology for safer computing, Intel(R) Trusted Execution Technology (Intel(R) TXT), defines platform-level enhancements that provide the building blocks for creating trusted platforms.  For more information, see `http://www.intel.com/technology/security/ <http://www.intel.com/technology/security/>`__.

Intel(R) TXT support is provided by the Trusted Boot (tboot) module in conjunction with minimal logic in the Xen hypervisor.

Tboot is an open source, pre- kernel/VMM module that uses Intel(R) TXT to perform a measured and verified launch of an OS kernel/VMM.

The Trusted Boot module is available from `http://sourceforge.net/projects/tboot <http://sourceforge.net/projects/tboot>`__. This project hosts the code in a mercurial repo at `http://tboot.sourceforge.net/hg/tboot.hg <http://tboot.sourceforge.net/hg/tboot.hg>`__ and contains tarballs of the source.  Instructions in the tboot README describe how to modify `grub.conf` to use tboot to launch Xen.

===============================================
Installing the Xen Project Software using Yocto
===============================================

Follow these instructions to cross-compile a hypervisor and minimal Dom0 filesystem image containing the Xen tools for the ARM64 QEMU emulator. The instructions are similar for other ARM64 platforms.

Obtaining the Source Code
~~~~~~~~~~~~~~~~~~~~~~~~~

We will use the Yocto stable release, "Dunfell":

.. code-block::

        $ git clone -b dunfell http://git.yoctoproject.org/git/poky
        $ cd poky
        $ git clone -b dunfell http://git.openembedded.org/meta-openembeddded
        $ git clone -b dunfell http://git.yoctoproject.org/git/meta-virtualization

Preparing the Build Tree
~~~~~~~~~~~~~~~~~~~~~~~~

Initialize your shell to be ready to build - this will generate basic configuration files when you do this the first time:

.. code-block::

        $ source ./oe-init-build-env

Edit `conf/bblayers.conf`, to add the source code layers needed. /scratch/repos/poky is the directory where you cloned the poky source code to - you will need to adjust the example paths here to match your directory layout:

.. code-block::

        BBLAYERS ?= " \
        /scratch/repos/poky/meta \
        /scratch/repos/poky/meta-poky \
        /scratch/repos/poky/meta-yocto-bsp \
        /scratch/repos/poky/meta-openembedded/meta-oe \
        /scratch/repos/poky/meta-openembedded/meta-filesystems \
        /scratch/repos/poky/meta-openembedded/meta-python \
        /scratch/repos/poky/meta-openembedded/meta-networking \
        /scratch/repos/poky/meta-virtualization \
        "

The `conf/local.conf` file contains instructions for the variables that it sets. You should review and make sure to set:

.. code-block::

        DL_DIR           -- set this to a local download directory for retrieved tarballs or other source code files
        SSTATE_DIR       -- set to a local directory for build cache files to speed up subsequent builds
        PACKAGE_CLASSES  -- package_ipk can be a good choice for package format

Then add the following to the same file, or make sure that the values here match if the variables are already present in the file:

.. code-block::

        MACHINE = "qemuarm64"
        DISTRO = "poky"
        IMAGE_FSTYPES += "cpio.gz"
        QEMU_TARGETS = "i386 aarch64"
        DISTRO_FEATURES += " virtualization xen"
        BUILD_REPRODUCIBLE_BINARIES = "1"

This configuration will enable OpenEmbedded's support for reproducible builds. It also reduces the number of emulation platforms for QEMU to significantly reduce build time.

If you would like to build QEMU to provide PV backends, such as disk and 9pfs, then you need to add:

.. code-block::

        PACKAGECONFIG_pn-qemu += " virtfs xen fdt"

Sdl is enabled by default in the Xen build of QEMU but it is not actually necessary and can be disabled with:

.. code-block::

        PACKAGECONFIG_remove_pn-qemu += " sdl"

Building
~~~~~~~~~

.. code-block::

        $ bitbake xen-image-minimal

When the build is completed, the output image file will be in build/tmp/deploy/images.

Targeting Hardware Platforms
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you are targetting a specific ARM hardware platform, you will likely need to add the "BSP layer", which contains the MACHINE definition for the hardware, and any closely related software such as bootloader configuration. The MACHINE variable needs to be set to match the hardware definition. You may also add additional layers containing related support software, if any.

TODO: instructions in this section are still pending validation for Dunfell

eg. For the Raspberry Pi 4:

In your poky directory, add the BSP layer:

.. code-block::

        $ git clone -b dunfell https://git.yoctoproject.org/git/meta-raspberrypi

In `local.conf`, set:

.. code-block::
        
        MACHINE = "raspberrypi4-64"

In bblayers.conf, add:

.. code-block::
        
        BBLAYERS_append = " /scratch/repos/poky/meta-raspberrypi"

Then, perform your build as before.

Building with a Local Copy of the Xen Source Code
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

TODO: instructions in this section are still pending validation for Dunfell

If you are building a local copy of a Xen source tree, you can add to `local.conf`:

.. code-block::

        INHERIT_pn-xen += "externalsrc"
        INHERIT_pn-xen-tools += "externalsrc"
        EXTERNALSRC_pn-xen = "/scratch/repos/xen"
        EXTERNALSRC_pn-xen-tools = "/scratch/repos/xen"
        EXTERNALSRC_BUILD_pn-xen = "/scratch/repos/xen"
        EXTERNALSRC_BUILD_pn-xen-tools = "/scratch/repos/xen"