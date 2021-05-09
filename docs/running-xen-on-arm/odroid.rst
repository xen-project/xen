***********************************************
Xen Arm with Virtualization Extensions/OdroidXU
***********************************************

===================
Preparing the Board
===================

The bootloader provided with the OdroidXU does not let Xen boot in hypervisor mode. In the Odroid forums for the XU, one is likely to see many U-Boot blobs (bl1/bl2/tzsw/u-boot) which could possibly be used to let Xen boot in hypervisor mode. To avoid multiple sources, currently a single source is provided which can be accessed from `https://github.com/suriyanr/linux-xen/tree/odroid-3.13.y/sd_fuse <https://github.com/suriyanr/linux-xen/tree/odroid-3.13.y/sd_fuse>`__.

The `sd_fusing.sh` script found therein can be used to fuse the SD card or eMMC card with the required BL1/BL2/TZSW and U-Boot.

.. code-block::

  sd_fusing.sh /dev/mmcblk0

Ensure `/dev/mmcblk0` is the correct device which represents the SD card or eMMC card that you will be using. This will let XEN boot in hypervisor mode as well as set CNTFRQ through the trustzone. This is required for domUs to get the correct timer frequency. (dom0's optionally can pick it up from the device tree)

============
Building Xen
============

Follow Build Xen on Arm to build Xen. For more verbose debug messages from XEN, it is worthwhile to compile Xen as below:

.. code-block::

    make dist-xen XEN_TARGET_ARCH=arm32 debug=y CONFIG_EARLY_PRINTK=exynos5250

.. note:: 

    Currently, Xen cannot build an uImage for U-Boot. You can create the image with:

    .. code-block::

        mkimage -A arm -T kernel -a 0x80200000 -e 0x80200000 -C none -d "$xen_src/xen/xen" xen4.5-uImage

    where, `$xen_src` is the root directory of your xen git.

==============================================================
Building a Device Tree for Xen, Linux Dom0 Kernel, and Modules
============================================================== 

We will build Linux for dom0 to have a device tree to provide to Xen. You can get a tree from [1] which contains a working configuration for the Odroid XU.

.. code-block::

    git clone -b odroid-3.13.y https://github.com/suriyanr/linux-xen.git --depth=1
    cd linux-xen
    make ARCH=arm CROSS_COMPILE=$CROSS_COMPILE odroidxu_xen_defconfig
    make ARCH=arm CROSS_COMPILE=$CROSS_COMPILE zImage
    make ARCH=arm CROSS_COMPILE=$CROSS_COMPILE dtbs
    # Note that CROSS_COMPILE has to be set appropriately or can be left unset if building natively.
 
The device tree used by the OdroidXU is located in arch/arm/boot/dts/exynos5410-odroidxu.dtb

.. code-block::

    # Now build the dom0 modules
    make ARCH=arm CROSS_COMPILE=$CROSS_COMPILE modules
    # And install them 
    make ARCH=arm CROSS_COMPILE=$CROSS_COMPILE INSTALL_MOD_PATH=/media/suriyan/rootfs modules_install

Note that /media/suriyan/rootfs is where the rootfs of the Odroid XU is mounted in the build box. Your path might vary or you will have to mount it appropriately.

=========================
Booting from SD/eMMC Card
=========================

Start with a distribution that you like, say xubuntu 14.04lts from `http://odroid.in/ubuntu_14.04lts/ubuntu-14.04lts-xubuntu-odroid-xu-20140714.img.xz <http://odroid.in/ubuntu_14.04lts/ubuntu-14.04lts-xubuntu-odroid-xu-20140714.img.xz>`__, or ArchLinuxArm, if you prefer from `http://archlinuxarm.org/platforms/armv7/samsung/odroid-xu <http://archlinuxarm.org/platforms/armv7/samsung/odroid-xu>`__.

Once you have imaged the SD card or eMMC card with your preferred distribution, overwrite the BL1/BL2/TZSW/U-Boot as mentioned in ref:: Preparing the Board.

Both the distributions mentioned above have a VFAT partition as the first partition. We shall use this partition to populate the XEN specific images - xen4.5-uImage, zImage, exynos5410-odroidxu.dtb - under a directory called `xen`. This is so we avoid overwriting the files that come with the default distribution in case we want to revert back the XEN changes.

.. code-block::

    suriyan@Stealth:/media/suriyan/BOOT$ ls -l xen
    ...
    -rw-r--r-- 1 suriyan suriyan   40467 Dec  8 14:04 exynos5410-odroidxu.dtb
    -rw-r--r-- 1 suriyan suriyan  689052 Dec  8 15:15 xen4.5-uImage
    -rw-r--r-- 1 suriyan suriyan 4709392 Dec  8 14:04 zImage

.. note:: The file sizes that you have might be different. The purpose here is to show the directory and the names of the files therein.

Rename the original boot.ini file in the VFAT partition to `boot.ini.org`. Copy the `boot.ini` found in `https://github.com/suriyanr/linux-xen/blob/odroid-3.13.y/sd_fuse/boot.ini <https://github.com/suriyanr/linux-xen/blob/odroid-3.13.y/sd_fuse/boot.ini>`__ in its place.

.. note:: 

  This `boot.ini` assumes that the rootfs resides in `/dev/mmcblk0p2`. If you have planned it elsewhere, change this value in the line which looks like the below appropriately.

  .. code-block::

        setenv dom0_bootargs vmalloc=256M console=hvc0 psci=enable earlyprintk debug clk_ignore_unused root=/dev/mmcblk0p2 rootwait rw drm_kms_helper.edid_firmware=edid/1920x1080.fw video=HDMI-A-1:1920x1080MR-32@60

Now we can plug the SD/eMMC card to the OdroidXU and boot it up.

Console Login Prompt
~~~~~~~~~~~~~~~~~~~~

hvc0 is used as the console by Xen. You will notice that `console=hvc0` is passed as the kernel boot parameter (will be the same for domU kernel as well).

To get a login prompt for dom0/domU one has to spawn a tty on hvc0. The below steps work for 14.04* Ubuntu.

.. code-block::

    cp /etc/init/tty1.conf /etc/init/hvc0.conf
    Replace tty1 with hvc0 in file /etc/init/hvc0.conf

============================
Building a Linux DomU Kernel
============================

Mainline Linux will be used for this purpose. The options to enable for building the domU kernel is as below:

.. code-block::

    make ARCH=arm CROSS_COMPILE=$CROSS_COMPILE exynos_defconfig
    make ARCH=arm menuconfig
  
When presented with the menu, make sure the below are enabled:

 1. Kernel Features -> Xen guest support on ARM
 2. Device Drivers -> Block devices -> Xen virtual block device support.
 3. Device Drivers -> Network device support -> Xen network device frontend
 4. Device Drivers -> Xen driver support -> Select all.
 5. System Type -> ARM system type -> Allow multiple platforms to be selected.
 6. System Type -> Multiple platform selection -> ARMv7 based platforms
 7. System Type -> Dummy Virtual Machine.
 8. Device Drivers -> Input Device support -> Miscellaneous devices -> Xen virtual keyboard and mouse support.

Build the linux kernel:

.. code-block::

    make ARCH=arm CROSS_COMPILE=$CROSS_COMPILE zImage

This zImage can then be used as a Linux domU kernel.

=========
Resources
=========

[2] Information about the `OdroidXU board <http://odroid.com/dokuwiki/doku.php?id=en:odroid-xu>`__
[3] `Odroid XU forum <http://forum.odroid.com/viewforum.php?f=59>`__