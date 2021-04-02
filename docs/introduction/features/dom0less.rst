========
Dom0less
========

"Dom0less" is a set of Xen features that enable the deployment of a Xen
system without an control domain (often referred to as "dom0"). Each
feature can be used independently from the others, unless otherwise
stated.

*****************************************
Booting Multiple Domains from Device Tree
*****************************************

This feature enables Xen to create a set of DomUs at boot time.
Information about the DomUs to be created by Xen is passed to the
hypervisor via Device Tree. Specifically, the existing Device Tree based
Multiboot specification has been extended to allow for multiple domains
to be passed to Xen. See docs/misc/arm/device-tree/booting.txt for more
information about the Multiboot specification and how to use it.

Currently, a control domain ("dom0") is still required, but in the
future it will become unnecessary when all domains are created
directly from Xen. Instead of waiting for the control domain to be fully
booted and the Xen tools to become available, domains created by Xen
this way are started right away in parallel. Hence, their boot time is
typically much shorter.

Configuration
~~~~~~~~~~~~~

Loading Binaries into Memory
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

U-Boot needs to load not just Xen, the device tree binary, the dom0 kernel and
ramdisk. It also needs to load the kernel and ramdisk of any additional domains
to boot. For example if this is the bootcmd for Xen and Dom0:

.. code-block::

    tftpb 0x1280000 xen.dtb
    tftpb 0x0x80000 xen-Image
    tftpb 0x1400000 xen.ub
    tftpb 0x9000000 xen-rootfs.cpio.gz.u-boot

    bootm 0x1400000 0x9000000 0x1280000

If we want to add one DomU with Image-DomU as the DomU kernel
and ramdisk-DomU as DomU ramdisk:

.. code-block::

    tftpb 0x1280000 xen.dtb
    tftpb 0x80000 xen-Image
    tftpb 0x1400000 xen.ub
    tftpb 0x9000000 xen-rootfs.cpio.gz.u-boot

    tftpb 0x2000000 Image-DomU
    tftpb 0x3000000 ramdisk-DomU

    bootm 0x1400000 0x9000000 0x1280000


Device Tree Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^

In addition to loading the necessary binaries, we also need to advertise
the presence of the additional VM and its configuration. It is done via
device tree adding a node under /chosen as follows:

.. code-block::

    domU1 {
        #address-cells = <1>;
        #size-cells = <1>;
        compatible = "xen,domain";
        memory = <0 0x20000>;
        cpus = <1>;
        vpl011;

        module@2000000 {
            compatible = "multiboot,kernel", "multiboot,module";
            reg = <0x2000000 0xffffff>;
            bootargs = "console=ttyAMA0";
        };

        module@30000000 {
            compatible = "multiboot,ramdisk", "multiboot,module";
            reg = <0x3000000 0xffffff>;
        };
    };

Where memory is the memory of the VM in KBs, cpus is the number of
cpus. module@2000000 and module@3000000 advertise where the kernel and
ramdisk are in memory.

Note: the size specified should exactly match the size of the Kernel/initramfs.
Otherwise, they may be unusable in Xen (for instance if they are compressed).

See docs/misc/arm/device-tree/booting.txt for more information.

Limitations
~~~~~~~~~~~

Domains started by Xen at boot time currently have the following
limitations:

- They cannot be properly shutdown or rebooted using xl. If one of them
  crashes, the whole platform should be rebooted.

- Some xl operations might not work as expected. xl is meant to be used
  with domains that have been created by it. Using xl with domains
  started by Xen at boot might not work as expected.

- The GIC version is the native version. In absence of other
  information, the GIC version exposed to the domains started by Xen at
  boot is the same as the native GIC version.

- No PV drivers. There is no support for PV devices at the moment. All
  devices need to be statically assigned to guests.

- Pinning vCPUs of domains started by Xen at boot can be
  done from the control domain, using `xl vcpu-pin` as usual. It is not
  currently possible to configure vCPU pinning without a control domain.
  However, the NULL scheduler can be selected by passing `sched=null` to
  the Xen command line. The NULL scheduler automatically assigns and
  pins vCPUs to pCPUs, but the vCPU-pCPU assignments cannot be
  configured.

Notes
~~~~~

- `xl console` command will not attach to the domain's console in case
  of dom0less. DomU are domains created by Xen (similar to Dom0) and
  therefore they are all managed by Xen and some of the commands may not work.

  A user is allowed to configure the key sequence to switch input.
  Pressing the Xen "conswitch" (Ctrl-A by default) three times
  switches input in case of dom0less mode.

- Domains created by Xen will have no name at boot. Domain-0 has a name
  thanks to the helper xen-init-dom0 called at boot by the initscript.
  If you want to setup DomU name, then you will have to create the xenstore
  node associated. By default DomU names are shown as '(null)' in the
  xl domains list.
