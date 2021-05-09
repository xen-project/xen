**********************************************************
Xen Arm with Virtualization Extensions/qemu-system-aarch64
**********************************************************

=====================
QEMU AArch64 Emulator
=====================

QEMU is an Open Source GPLv2 software emulator. It can emulate a large range of machines of different architectures, including Cortex-A57s based platforms.

The following steps help you setup QEMU to emulate an ARM64 machine and run Xen inside it.

Building QEMU
~~~~~~~~~~~~~

QEMU v4.0.0 can run Xen out of the box. Build QEMU like this:

.. code-block::

        $ ./configure --target-list=aarch64-softmmu --prefix=/usr/local
        $ make
        $ sudo make install

Installing Xen
~~~~~~~~~~~~~~

QEMU works well with UEFI firmware for the emulated machine. To get the system working, download an Aarch64 UEFI ready distro image, like `xenial-server-cloudimg-arm64-uefi1.img`.

Then, clone Linux and build the kernel using the defconfig for arm64 (make defconfig && make Image.gz). For building Linux kernel for Arm64 / Arm user might need cross compilers. Below are details with respect to different distros :

- `OpenSUSE <https://opensuse.pkgs.org/tumbleweed/opensuse-oss/cross-aarch64-gcc7-7.3.1+r258313-1.2.x86_64.rpm.html>`__
- `UBUNTU <https://packages.ubuntu.com/en/trusty/gcc-aarch64-linux-gnu>`__
- `Other distros <https://pkgs.org/>`__

Steps can be found at `http://events17.linuxfoundation.org/sites/events/files/slides/Shuah_Khan_cross_compile_linux.pdf <http://events17.linuxfoundation.org/sites/events/files/slides/Shuah_Khan_cross_compile_linux.pdf>`__.

Run QEMU the first time, booting Linux directly (replace the MAC_ADDRESS and the paths). The following command uses user-networking and forwards port 2222 from the host to port 22 inside the virtual machine:

.. code-block::

    $ qemu-system-aarch64 \
    -machine virt,gic_version=3 -machine virtualization=true \
    -cpu cortex-a57 -machine type=virt -nographic \
    -smp 4 -m 4000 \
    -kernel /path/to/linux.git/arch/arm64/boot/Image.gz --append "console=ttyAMA0 root=/dev/vda1 init=/bin/sh" \
    -netdev user,id=hostnet0,hostfwd=tcp::2222-:22 -device virtio-net-device,netdev=hostnet0,mac=MAC_ADDRESS \
    -drive if=none,file=/path/to/xenial-server-cloudimg-arm64-uefi1.img,id=hd0 -device virtio-blk-device,drive=hd0

This command will give a shell prompt, where user might have to mount the root file system using below command :

.. code-block::

     $ mount -o remount,rw /dev/vda1 /

Once mounted, user would like to set the 'root' password using 'passwd' command and then relaunch the virtual machine using above qemu command, but now remove 'init=/bin/sh'.

Once login with 'root' user, you may need to set the ssh authorized_keys of host machine, to access the virtual machine via remote.

Follow `Building Xen on Arm <tutorials\building-xen-arm.rst>`__ to build Xen on Arm. Then, copy the Xen on ARM efi binary and the Linux kernel to the image:

.. code-block::

    $ scp -P2222 /path/to/linux.git/arch/arm64/boot/Image.gz root@127.0.0.1:/boot/efi/kernel
    $ scp -P2222 /path/to/xen.git/xen/xen.efi root@127.0.0.1:/boot/efi

Let's write a config file for it:

.. code-block:

    $ vi /boot/efi/xen.cfg

Let's use the following config:

.. code-block::

    options=console=dtuart noreboot dom0_mem=512M
    kernel=kernel root=/dev/vda1 init=/bin/sh rw console=hvc0
    dtb=virt-gicv3.dtb

Now we need the device tree binary, "virt-gicv3.dtb". QEMU can generate one for you with the following command:

.. code-block::

        $ qemu-system-aarch64 \
        -machine virt,gic_version=3 \
        -machine virtualization=true \
        -cpu cortex-a57 -machine type=virt \
        -smp 4 -m 4096 -display none \
        -machine dumpdtb=virt-gicv3.dtb
        $ scp -P2222 virt-gicv3.dtb root@127.0.0.1:/boot/efi

We have written everything we need to the disk image. Let's poweroff the virtual machine and proceed to download the UEFI firmware binary from Linaro: [1].

Running QEMU
~~~~~~~~~~~~

The following command create a new emulated AArch64 machine with 4 Cortex A57s, 4G of RAM, booting from EFI. The command below uses user networking in QEMU, other network configuration (bridging) are possible. Please change MAC_ADDRESS for the emulated machine and path to the guest image.

.. code-block::

        $ qemu-system-aarch64 \
        -machine virt,gic_version=3 \
        -machine virtualization=true \
        -cpu cortex-a57 -machine type=virt \
        -smp 4 -m 4096 -display none \
        -serial mon:stdio \
        -bios /path/to/QEMU_EFI.bin \
        -netdev user,id=hostnet0,hostfwd=tcp::2222-:22 -device virtio-net-device,netdev=hostnet0,mac=MAC_ADDRESS \
        -drive if=none,file=/path/to/xenial-server-cloudimg-arm64-uefi1.img,id=hd0 -device virtio-blk-device,drive=hd0 -boot order=d

The boot order option will enable to get to UEFI prompt. Typing "FS0:" and then "xen" will boot hypervisor.

The Xen tools can be built further using below links :

- `Appendix: chrooting into target file systems <https://wiki.debian.org/Arm64Qemu https://wiki.debian.org/QemuUserEmulation>`__

=========
Resources
=========

[1] `https://web.eecs.umich.edu/~jcma/blog/cjrl7dk7d000brlqjrv1rt7ru/ <https://web.eecs.umich.edu/~jcma/blog/cjrl7dk7d000brlqjrv1rt7ru/>`__