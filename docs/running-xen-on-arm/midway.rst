*********************************************
Xen Arm with Virtualization Extensions/Midway
*********************************************

Midway is the codename for the `Calxeda ECX-2000 <http://www.calxeda.com/wp-content/uploads/2013/10/Calxeda-ECX2000-PB-Oct20132.pdf>`__ based server system, featuring four A-15 cores in a micro-server oriented design.

==================
Supported Versions
==================

Though the Xen 4.3 release has some ARM support, it will not run on Midway. Beside the missing platform support there were several deficiencies in the code which prevent the 4.3 base (even with fixes) to run on this machine.

Xen 4.4 supports Midway. There is Midway platform code in Xen, which will be automatically detected and used. To use the earlyprintk feature for early debug output, build Xen with "CONFIG_EARLY_PRINTK=midway".

On the Linux kernel side you need a version which has all the fixes necessary to fully support Midway in LPAE mode. Kernel 3.12 works pretty well. However you should use the latest available version if possible to get the full support, including SWIOTLB. Configure a multi-platform kernel with support for the Calxeda SoCs, LPAE and at least the xgmac network driver as well as the Highbank SATA driver.

===========
Booting Xen
===========

The Calxeda primary firmware switches all cores into HYP mode already and installs a PSCI handler in secure state. Then it launches u-boot, which runs completely in HYP mode. So booting Xen works out of the box. The device tree is included in the firmware flash, this will be adjusted by primary firmware to match the runtime configuration (namely the memory size and parameters). There is no need to explicitly load a device tree, and you should avoid doing that.

To load the Xen binaries, you should load the Xen hypervisor at the address usually used for the (bare-metal) Linux kernel:

.. code-block::

    ==> tftp $kernel_addr_r xen-4.4

Now tell u-boot where the device tree has been loaded and add the Xen command line:

.. code-block::

    ==> fdt addr $fdt_addr; fdt resize
    ==> fdt set /chosen xen,xen-bootargs "console=dtuart dtuart=/soc/serial@fff36000"

Add any additionally needed Xen command line parameters here (like dom0_mem), if required.

The Dom0 zImage kernel should be loaded at any address supported by Xen, the recommendation is to use 0x1000000 (16MB):

.. code-block::

    ==> setenv dom0_addr 0x1000000
    ==> tftp $dom0_addr vmlinuz-3.13-rc3-xen

To tell Xen about the location of the Dom0 kernel, we will have to add a subnode to the /chosen node in the in-memory device tree:

.. code-block::

    ==> fdt mknod /chosen module
    ==> fdt set /chosen/module compatible "xen,linux-zimage" "xen,multiboot-module"
    ==> fdt set /chosen/module reg <0x0 $dom0_addr 0x0 0x$filesize>
    ==> fdt set /chosen/module bootargs "console=hvc0 root=/dev/sda2"

.. note:: $filesize reflects the file size of the last loaded file in u-boot, so subsequent ext2load/fatload/tftp commands will overwrite this value. So make sure to execute these lines right after the Dom0 kernel load.

Now you can launch Xen:

.. code-block::

    ==> bootz $kernel_addr_r - $fdt_addr

========================
Using Network in a Guest
========================

The Calxeda firmware needs to know the mac address of the guest, if it plans to use network. Before creating a guest, the following command should be called:

.. code-block::

    bridge fdb add xx:xx:xx:xx:xx:xx dev eth0

This can be automated by dropping the following into `/etc/xen/scripts/vif-post.d/cxfabric.hook` (the .hook suffix is important and the file must be executable):

.. code-block::

    # (De)register the new device with the CX Fabric. Ignore errors from bridge fdb
    # since the MAC might already be present etc.
    cxfabric() {
        local command=$1
        local mac=$(xenstore_read "$XENBUS_PATH/mac")
        case $command in
        online|add)
            log debug "Adding $mac to CXFabric fdb"
            do_without_error bridge fdb add $mac dev eth0
            ;;
        offline)
            log debug "Removing $mac from CXFabric fdb"
            do_without_error bridge fdb del $mac dev eth0
            ;;
        esac
    }
    cxfabric $command

.. note:: The binary bridge is provided by the iproute2 package. On Debian, the package only exists on Jessie and onwards.