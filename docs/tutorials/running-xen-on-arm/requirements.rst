************
Requirements
************

====================
General Requirements
====================

- ARM Hardware or Software Model
    See the following sections for information on hardware and models which are supported.
- Firmware
    Xen requires certain functionality from the system firmware. The primary requirement is that the hypervisor must be launched in Non-Secure Hypervisor mode only. If the stock firmware on a platform does not obey this (most commonly by launching in Secure Supervisor mode) then a firmware update may be required. This support is present in U-Boot 2014.01.

    .. note::
    
        Booting secondary processors on an SMP system requires firmware support for the Power State Coordination Interfaces (PSCI). Initial U-Boot support for this interface is available in `https://git.kernel.org/cgit/linux/kernel/git/maz/u-boot.git/log/?h=wip/psci <https://git.kernel.org/cgit/linux/kernel/git/maz/u-boot.git/log/?h=wip/psci>`__.

- Device Tree
    A device tree in the flat device tree format (.dtb). The host platform must be described in a DTB binary passed to Xen at boot time. This will be used by Xen and Dom0. Normally the regular device tree used when booting natively on the platform should be used.

- Xen
    All current work is now merged into the current development branch git://xenbits.xen.org/xen.git. It is recommended to use the latest Xen master branch.

- Linux Kernel for dom0
    The patches necessary to boot Linux as dom0 under Xen were merged upstream in v3.7. In order to actually start guests a few additional patches were required however these patches have now been included in the v3.8 Linux release. The latest Linus' tree has everything needed to run on Xen on ARM as dom0 and domU. It is recommended to use the latest Linux release where possible.

- dom0 userspace
    The developers are using the armhf port of Debian Wheezy.
    
- domU kernel
    The patches necessary to boot Linux as a guest under Xen were merged upstream in v3.7.

=================================
Requirements for Booting Natively
=================================

Before starting to load Xen it is highly recommended to get the kernel you intend to use as dom0 booting natively (i.e., without Xen underneath). This will let you iron out any driver issues and figure out the necessary kernel command line etc before adding Xen into the mix.

============================
Requirements for Booting Xen
============================

- ImageBuilder
    Many of the details necessary to boot Xen from U-Boot can be generated automatically by ImageBuilder's `uboot-script-gen`, see `ImageBuilder <..reference\imagebuilder.rst>`__.

- Boot Protocol
    Boot requirements are described in `Booting Xen from U-Boot <../tutorials/booting-xen-u-boot.rst>`__ in the Xen tree, which references the Linux arm and arm64 booting documentation.

- Device Trees
    Xen needs the device trees to be in the flat device tree format (the device tree blob or DTB).

    .. note:: It is no longer necessary to build a specific DTB for use with Xen. The Device Tree files shipped with Linux or from the Split Device Tree Repository can be used.

- Boot Modules
    At boot time Xen must be provided with a dom0 kernel blob and an optional dom0 initramfs blob. The bootloader must load these into memory and describe their location in the Device Tree Blob using the bindings specified in `Booting Xen from U-Boot <../tutorials/booting-xen-u-boot.rst>`__.

    These nodes can either be added by hand (by editing and recompiling the .dts file) or by using the `fdt` command in U-Boot to add them dynamically at boot time:

    .. code-block::

        fdt addr ${fdt_addr}
        fdt resize
        
        fdt set /chosen \#address-cells <1>
        fdt set /chosen \#size-cells <1>
        
        fdt mknod /chosen module@0
        fdt set /chosen/module@0 compatible "xen,linux-zimage" "xen,multiboot-module"
        fdt set /chosen/module@0 reg <${kernel_addr_r} 0x${filesize} >
        fdt set /chosen/module@0 bootargs "<DOMAIN 0 COMMAND LINE>"

- Command Lines
    `Booting Xen from U-Boot <../tutorials/booting-xen-u-boot.rst>`__ describes where Xen looks for both its own command line and the command line to pass to domain 0.

Getting Xen Output
~~~~~~~~~~~~~~~~~~

To get output log on the UART, Xen needs to know which UART to use. This should be passed in the hypervisor command line using the "dtuart" parameter. e.g.:

.. code-block:: 
    console=dtuart dtuart=myserial

where, myserial is either an alias to the UART in the device tree (aliases are found in the aliases device tree node) or a full DTB path to the device. As Xen already uses it the UART will be disabled from the point of view of domain 0.

For instance, this is a dummy device tree (won't work) to use the uart0 in Xen:

.. code-block::

    {
        choosen {
        bootargs = "console=dtuart dtuart=myserial";
        }
        aliases {
            myserial = &myserial_0;
        }
        myserial_0: uart0 {
        ... configuration of your UART ...
        }
    }

Here dtuart is configured using the myserial alias. Alternatively /uart0 (the full path to the device) could have been used.

.. note:: If you don't see output from Xen, you can enable early printk. This option will turn on platform specific UART and output information before the console is initialized.

===========
Dom0 Kernel
===========

In general the same kernel configuration as used to boot natively, plus turning on the Xen specific options should work. A good starting point is often the "multi_v7_defconfig" + Xen options.

If ARM_APPENDED_DTB is enabled then any appended DTB will be used instead of one supplied by Xen and the kernel will crash unless the memory in the DTB matches that location/size supplied by Xen. It is strongly recommended not to append a DTB to your dom0 kernel (or to disable APPENDED_DTB).

===================
DomU kernel and DTS
===================

Unprivileged guests can be created using xl. A simple VM config file would look like this:

.. code-block::

    kernel = "/root/image"
    memory = 128
    name = "guest"
    vcpus = 1
    disk = [ 'phy:/dev/loop0,xvda,w' ]
    extra = "earlyprintk=xenboot console=hvc0 root=/dev/xvda debug rw init=/bin/sh"

where, "/root/image" is a Linux zImage.

====================
Common DomU Pitfalls
====================

- Enabling CONFIG_DEBUG_LL in the guest kernel configuration.
    Although this option can work for dom0 if configured appropriately for the host it does not work for domU (which cannot see the host UART). The symptoms of this are that the guest console will be silent because the kernel has taken a fault accessing the early UART. This can be confirmed by using the xenctx tool (found in $PREFIX/lib/xen/bin/). The tool takes a numeric domid (not a name, use xl list or xl domid $name) and dumps the VCPU state. A PC of 0x0000000c will usually indicate that an early trap has occurred.