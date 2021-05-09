*************************************************
Xen ARM with Virtualization Extensions/FastModels
*************************************************

=======================
Fixed Virtual Platforms
=======================

The primary models in use today by the Xen developers are the Fixed Virtual Platforms (FVP) modules which are available from Arm&trade;, e.g., RTSM_VE_Cortex-A15x2 and RTSM_VE_AEMv8Ax2.

In addition for ARMv8, Arm also makes a `Foundation Model <#Foundation_Model>`__ freely available.

If you do not have access to the FVPs or Foundation model (e.g., you are interested in ARMv7), then you may be able to download an evaluation version of the FastModels and build an equivalent model yourself using sgcanvas, see `Building a Model with sgcanvas <.\tutorials\running-xen-on-arm\sgcanvas.rst>`__.

============
Known Issues
============

Xen boot can be slow on the models because it scrubs the memory. If it is too slow, you can add `no-bootscrub` on the Xen command line.

===========
Device Tree
===========

The device tree for the ARMv8 foundation model is upstream in Linux.

Pawel Moll maintains a set of device tree files which describe the fast model platforms. See `arm-dts.git <http://www.linux-arm.org/git?p=arm-dts.git;a=summary>`__.

This tree contains no build system, therefore the device tree compiler (dtc) should be invoked by hand:

.. code-block::

        $ git clone git://linux-arm.org/arm-dts.git arm-dts.git
        $ cd arm-dts.git/fast_models
        $ dtc -I dts -O dtb -o rtsm_ve-cortex_a15x2.dtb rtsm_ve-cortex_a15x2.dts
        $ dtc -I dts -O dtb -o rtsm_ve-aemv8a.dtb rtsm_ve-aemv8a.dts 

You should use the dts file which describes as many CPUs as the model you intend to use (e.g., the x1, x2 or x4 suffix). In the case of the AEM DTS, you should edit it to contain the appropriate number of CPU nodes.

=======================
Firmware and Boot-wrapper
=======================

It is common to run the models without real firmware. In this case a boot-wrapper is required in order to provide a suitable boot time environment for Xen (e.g., booting in NS-HYP mode, providing the boot modules, etc.). Bootwrappers are available for both arm32 and arm64; however, their functionality differs significantly.

arm32
~~~~~

The arm32 boot-wrapper is the more functional version and can make use of semihosting to load the hypervisor, kernel and DTB from the host filesystem at runtime. A version of the boot-wrapper with support for Xen is available in the xen-arm32 branch of `http://xenbits.xen.org/gitweb/?p=people/ianc/boot-wrapper.git;a=summary <http://xenbits.xen.org/gitweb/?p=people/ianc/boot-wrapper.git;a=summary>`__.

Build the Boot-wrapper
----------------------

.. code-block::

    $ git clone -b xen-arm32 git://xenbits.xen.org/people/ianc/boot-wrapper.git boot-wrapper.git
    $ cd boot-wrapper.git
    $ make CROSS_COMPILE=arm-linux-gnueabihf- semi

This produces a `linux-system-semi.axf` binary. This should be passed to the model as the application to run and a `cluster.cpu0.semihosting-cmd_line` option should be passed (with -C) containing the set of modules and their command lines. For example:

.. code-block::

    RTSM_VE_Cortex-A15x2 -C cluster.cpu0.semihosting-cmd_line="
        --kernel xen.git/xen/xen \
        --module linux.git/arch/arm/boot/zImage <DOMAIN 0 COMMAND LINE>
        --dtb rtsm_ve-cortex_a15x2.dtb -- <XEN COMMAND LINE>"
    <MODEL OPTIONS> boot-wrapper.git/linux-system-semi.axf

The Command line options are as follows:

--kernel <path-to-kernel>
   Provides the "kernel", Xen in this case.
--module <path-to-module> <optional-command-line>
   Supplies a boot module. In this case the first module supplied is treated as the domain 0 kernel (in zImage format). The kernel command line should be specified here too.
--dtb <path-to-dtb>
   Supplies the Device Tree Blob.

The final -- token delimits the end of the options after which the kernel (Xen in this case) command line should be supplied.

.. note:: The entirety of the `cluster.cpu0.semihosting-cmd_line` options should be quoted from the shell.

arm64
~~~~~

The arm64 version of boot-wrapper is not as fully featured as the arm32 version and does not support semihosting. The required binaries and command lines are built directly into the boot-wrapper which must be rebuilt whenever any component changes.

The upstream boot-wrapper-aarch64 has Xen support. It can be built as shown below:

.. code-block::

        $ git clone git://git.kernel.org/pub/scm/linux/kernel/git/mark/boot-wrapper-aarch64.git
        $ cd boot-wrapper-aarch64
        $ autoreconf -i
        $ ./configure --host=aarch64-linux-gnu \
        $     --with-kernel-dir=$KERNEL \
        $     --with-dtb=$KERNEL/arch/arm64/boot/dts/arm/foundation-v8.dtb \
        $     --with-cmdline="console=hvc0 earlycon=pl011,0x1c090000 root=/dev/vda rw" \
        $     --enable-psci \
        $     --with-xen-cmdline="dtuart=serial0 console=dtuart no-bootscrub dom0_mem=512M" \
        $     --with-xen=$XEN \
        $     --with-cpu-ids=0,1,2,3
        $ make

Where, `$KERNEL` points to the Linux kernel directory, and `$XEN` points to the Xen binary. You need to have the cross-compile toolchain installed on your `$PATH`.

The resulting `xen-system.axf` binary should be passed to the model as the application to run. For example:

.. code-block::

        $ ./Foundation_Platform --image=/path/to/xen-system.axf --block-device=<rootfs> --cores=4
        
If any of Xen, the FDT or the kernel Image change then only the final make step needs to be repeated.

================
Foundation Model
================

The ARMv8 Foundation Model is a free as in beer AArch64 emulation platform. The use is very similar to the arm64 instructions for the fastmodel using the relevant bootwrapper however the invocation of the model is slightly different:

.. code-block::

    ./Foundation_v8pkg/models/Linux64_GCC-4.1/Foundation_v8 \
        --image boot-wrapper-aarch64/xen-system.axf \
        --block-device rootfs.img

The block device is exposed by the emulated hardware via virtio, therefore the root device will be `/dev/vda`. Make sure to have at least the following options enabled in your kernel config:

.. code-block::

        CONFIG_VIRTIO=y
        CONFIG_VIRTIO_MMIO=y
        CONFIG_VIRTIO_BLK=y

===============
FVP AEMv8 Model
===============

The FVP AEMv8 Model is a licensed AArch64 emulation platform. It has additional features compared to ARMv8 foundation model.

.. code-block::

        model_shell <FVP_AEMv8_install_directory>/models/Linux64_GCC-4.1/RTSM_VE_AEMv8A.so \
            -C motherboard.mmc.p_mmc_file=<aarch64_rootfs_image> \
            boot-wrapper-aarch64/xen-system.axf 


.. note::

    1. The DTS for FVP AEMv8 model is already available in mainline Linux kernel.
    2. For trying XEN on older FVP AEMv8 model we might need to disable VIRTIO BLOCK device from FVP AEMv8 model DTS.

