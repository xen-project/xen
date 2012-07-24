Using Upstream QEMU with Xen
============================

If you want to build with the QEMU unstable tree, follow the [QEMU
Upstream](http://wiki.xen.org/wiki/QEMU_Upstream) wiki page.

Otherwise, QEMU/SeaBIOS is now integrated into the build system, so you just
have to specify the device model version in an `xl` config file:

    device_model_version = 'qemu-xen'

The version of QEMU used in the build system is the last release of QEMU.
