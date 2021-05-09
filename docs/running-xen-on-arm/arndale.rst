**********************************************
Xen Arm with Virtualization Extensions/Arndale
**********************************************

The Arndale board is now supported in Xen upstream.

===================
Preparing the Board
===================

The bootloader provided with the Arndale does not let Xen boot in hypervisor mode, so we will use the u-boot provided by Linaro.

===========================
Building Xen and Linux Dom0
===========================

First, build Linux for dom0 to have a device tree to provide to Xen. You can get a tree from Linaro which contains a working configuration for the Arndale.

.. code-block::

    git clone -b linux-linaro git://git.linaro.org/kernel/linux-linaro-tracking.git linux
    cd linux
    ARCH=arm scripts/kconfig/merge_config.sh linaro/configs/linaro-base.conf linaro/configs/distribution.conf\
            linaro/configs/kvm-host.conf linaro/configs/xen.conf linaro/configs/arndale.conf linaro/configs/lt-arndale.conf
    make ARCH=arm zImage
    make ARCH=arm dtbs

The device tree used by the Arndale board is located in `arch/arm/boot/dts/exynos5250-arndale.dtb`.

Then, build Xen on ARM.

For the moment, xen doesn't build uImage for U-Boot. You can create the image with:

.. code-block::

    mkimage -A arm -T kernel -a 0x80200000 -e 0x80200000 -C none -d "$xen_src/xen/xen" xen-uImage 

where, $xen_src is the root directory of your xen git. Note that before commit 47d1a51 (xen: arm: make zImage the default target which we install) it was necessary to use `$xen_src/xen/xen.bin` instead.

====================
Booting Xen and Dom0
====================

To boot Xen and Dom0, you can use:

- PXE: it's easier for development but you need a computer which act as a server;
- copy binary on the SD card: when you don't have network on your board.

Once you have chosen the boot method, you can start to follow steps in the next sections. When you have finished to configure your board, you can:

- Save the U-Boot configuration with saveenv command. The next time you want to reboot your board, you won't have to reconfigure U-Boot.
- Boot with boot command.

===============
Booting via PXE
===============

The following script allow U-boot to download everything via tftp and boot xen.

1. Setup the PXE Server
2. Copy xen-uImage, the zImage (rename in linux-zImage), exynos5250-arndale.dtb in /tftpboot/
3. Copy the script in /tftpboot

    .. code-block::

        wget http://xenbits.xen.org/people/julieng/load-xen-tftp.scr.txt
        mkimage -T script -C none -d load-xen-tftp.scr.txt /tftpboot/load-xen-tftp.img

4. At U-Boot prompt, on your board, you need to set the following variable:

    .. code-block::

        setenv ipaddr 10.y.y.y
        setenv serverip 10.x.x.x
        setenv usbethaddr 00:zz:zz:zz:zz:zz
        setenv ethaddr 00:zz:zz:zz:zz:zz
        setenv xen_addr_r 0x50000000
        setenv kernel_addr_r 0x60000000
        setenv dtb_addr_r 0x42000000
        setenv script_addr_r 0x40080000
        setenv xen_path /xen-uImage
        setenv kernel_path /linux-zImage
        setenv dtb_path /exynos5250-arndale.dtb
        setenv bootcmd 'tftpboot $script_addr_r /load-xen-tftp.img; source $script_addr_r'
        setenv xen_bootargs 'sync_console console=dtuart dtuart=/serial@12C20000'
        setenv dom0_bootargs 'console=hvc0 ignore_loglevel psci=enable clk_ignore_unused root=/dev/mmcblk1p3'

    with:

    10.y.y.y the ip addr of the board
    10.x.x.x the ip of a tftp server (or PXE server).
    00:zz:zz:zz:zz:zz the MAC address of the board. 
    
    You can generate it with the following shell command:

    .. code-block::

        bash -c 'printf "00:16:3e:%02x:%02x:%02x\n" $(( $RANDOM % 256 )) $(( $RANDOM % 256 )) $(( $RANDOM % 256 ))'

    or, using the `www.hellion.org.uk/cgi-bin/randmac.pl <www.hellion.org.uk/cgi-bin/randmac.pl>`__ website.

===============================
Booting Directly on the SD Card
===============================

1. Copy xen-uImage and the zImage the root directory of you SD card.
2. At U-Boot prompt, on your board, you need to set the following variable:

    .. code-block::

        setenv kernel_addr_r 0x60000000
        setenv xen_addr_r 0x50000000
        setenv bootcmd_load_linux_mmc 'ext2load mmc 1:0 $kernel_addr_r /zImage'
        setenv boot_xen_mmc 'run bootcmd_load_linux_mmc; ext2load mmc 1:0 $xen_addr_r /xen-uImage; bootm $xen_addr_r -'
        setenv bootcmd 'run boot_xen_mmc'

3. Assuming the SD card has only one partition with ext2 filesystem, execute the boot command with the following command:

    .. code-block::

        boot

======================================================================
Alternate SD approach based on Linaro pre-built image for Arndale 5250
======================================================================

1. On your host development machine, install [Linaro prebuilt] to a uSD card (assuming it mounts at /dev/sdb, see linaro instructions for more detail):

.. code-block::

    $ wget https://releases.linaro.org/14.03/ubuntu/arndale/arndale-saucy_server_20140323-616.img.gz
    $ gunzip < arndale-saucy_server_20140323-616.img.gz | sudo dd bs=64k of=/dev/sdb

2. Copy your compiled xen-uImage, linux-zImage, and exynos5250-arndale.dtb all to the boot partition on the uSD card. Copy the contents of xen/dist/install to the rootfs partition. Unmount the uSD from your host development machine, insert it in the Arndale.

3. Start minicom on host development machine, connected to the Arndale via a serial cable:

    .. code-block::
 
           $ sudo minicom

4. Power on Arndale, press reset, watch the minicom console, and hit “enter” to interrupt U-Boot to get the u-Boot prompt. Enter the following into the minicom console. The saveenv stores the environment variables, so you won't have to repeat those the next time around.

    .. code-block::

        setenv xen_addr_r 0x50000000
        setenv kernel_addr_r 0x60000000
        setenv dtb_addr_r 0x42000000
        setenv xen_bootargs 'sync_console console=dtuart dtuart=/serial@12C20000 dom0_mem=512M'
        setenv dom0_bootargs 'console=hvc0 ignore_loglevel psci=enable clk_ignore_unused root=/dev/mmcblk1p3'
        saveenv
        fatload mmc 0:2 $kernel_addr_r linux-zImage
        fatload mmc 0:2 $xen_addr_r xen-uImage
        fatload mmc 0:2 $dtb_addr_r exynos5250-arndale.dtb
        fdt addr $dtb_addr_r
        fdt resize
        fdt set /chosen xen,xen-bootargs \"$xen_bootargs\"
        fdt set /chosen xen,dom0-bootargs \"$dom0_bootargs\"
        fdt mknode /chosen modules
        fdt set /chosen/modules '#address-cells' <1>
        fdt set /chosen/modules '#size-cells' <1>   
        fdt mknode /chosen/modules module@0                                                                        
        fdt set /chosen/modules/module@0 compatible xen,linux-zimage xen,multiboot-module                          
        fdt set /chosen/modules/module@0 reg <$kernel_addr_r 0x00a00000>                                             
        bootm $xen_addr_r - $dtb_addr_r

=========        
Resources
=========

Information about the Arndale board development: `www.arndaleboard.org/wiki/index.php/WiKi <www.arndaleboard.org/wiki/index.php/WiKi>`__.
Linaro page about the Arndale board: `wiki.linaro.org/Boards/Arndale/Setup/PXEBoot <wiki.linaro.org/Boards/Arndale/Setup/PXEBoot>`__
Alternate SD approach based on Linaro pre-built image (more detailed): `Booting Linux in Xen's Dom0 on Arndale Exynos 5250 <http://www.episodic.cc/2014/06/booting-linux-in-xens-dom0-on-arndale.html>`__