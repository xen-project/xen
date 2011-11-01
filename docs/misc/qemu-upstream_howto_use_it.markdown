Help to use QEMU (upstream version) with Xen
============================================

Note
----

All these steps will become unnecessary after the patches to integrate
SeaBIOS/QEMU build will be applied.


How to build it
---------------

### SeaBIOS

The new device-model needs a different BIOS, SeaBIOS. Clone the repository from:

  - git://git.qemu.org/seabios.git
  - http://git.qemu.org/git/seabios.git

Put the `.config` file in the appendix at the root of seabios.git and build SeaBIOS.

In xen-unstable source tree, add the file `.config` with
`SEABIOS_DIR = /path/to/seabios.git`.
To build hvmloader with SeaBIOS, you propably need to `make -C tools/firmware
clean` first and then `make tools`, to use the new SEABIOS_DIR parameter.


### QEMU

Get QEMU upstream source from:

  - git://xenbits.xensource.com/qemu-upstream-unstable.git
  - http://xenbits.xensource.com/git-http/qemu-upstream-unstable.git

To configure build QEMU upstream with Xen

    ./configure --enable-xen --target-list=i386-softmmu --extra-cflags="-I$path_to_xen_source/tools/include -I$path_to_xen_source/tools/libxc -I$path_to_xen_source/tools/xenstore" --extra-ldflags="-L$path_to_xen_source/tools/libxc -L$path_to_xen_source/tools/xenstore"

You can also use other several options such as `--disable-kvm`.


How to use QEMU upstream
------------------------

Only xl support QEMU upstream.

To actually use it, add or change this in your VM configuration file:

    device_model_version = 'qemu-xen'
    device_model_override = '/path/to/qemu/i386-softmmu/qemu'

NB: On qemu-upstream repository, the default binary name has been renamed to
`qemu-system-i386`.


Appendix
------

### `.config` file for SeaBIOS

    #
    # General Features
    #
    # CONFIG_COREBOOT is not set
    CONFIG_XEN=y
    CONFIG_THREADS=y
    CONFIG_THREAD_OPTIONROMS=y
    CONFIG_RELOCATE_INIT=y
    CONFIG_BOOTMENU=y
    CONFIG_BOOTMENU_WAIT=1000
    # CONFIG_BOOTSPLASH is not set
    CONFIG_BOOTORDER=y
    #
    # Hardware support
    #
    CONFIG_ATA=y
    CONFIG_ATA_DMA=y
    CONFIG_ATA_PIO32=y
    CONFIG_AHCI=y
    CONFIG_VIRTIO_BLK=y
    CONFIG_FLOPPY=y
    CONFIG_PS2PORT=y
    CONFIG_USB=y
    CONFIG_USB_UHCI=y
    CONFIG_USB_OHCI=y
    CONFIG_USB_EHCI=y
    CONFIG_USB_MSC=y
    CONFIG_USB_HUB=y
    CONFIG_USB_KEYBOARD=y
    CONFIG_USB_MOUSE=y
    CONFIG_SERIAL=y
    CONFIG_LPT=y
    # CONFIG_EXTRA_PCI_ROOTS is not set
    # CONFIG_USE_SMM is not set
    CONFIG_MTRR_INIT=y
    #
    # BIOS interfaces
    #
    CONFIG_DRIVES=y
    # CONFIG_CDROM_BOOT is not set
    CONFIG_PCIBIOS=y
    CONFIG_APMBIOS=y
    CONFIG_PNPBIOS=y
    CONFIG_OPTIONROMS=y
    # CONFIG_OPTIONROMS_DEPLOYED is not set
    CONFIG_OPTIONROMS_CHECKSUM=y
    CONFIG_PMM=y
    CONFIG_BOOT=y
    CONFIG_KEYBOARD=y
    CONFIG_KBD_CALL_INT15_4F=y
    CONFIG_MOUSE=y
    CONFIG_S3_RESUME=y
    # CONFIG_S3_RESUME_VGA_INIT is not set
    # CONFIG_DISABLE_A20 is not set
    #
    # BIOS Tables
    #
    CONFIG_PIRTABLE=y
    CONFIG_MPTABLE=y
    CONFIG_SMBIOS=y
    CONFIG_ACPI=y
    #
    # Debugging
    #
    CONFIG_DEBUG_LEVEL=3
    CONFIG_DEBUG_SERIAL=y
    CONFIG_DEBUG_SERIAL_PORT=0x3f8
    # CONFIG_SCREEN_AND_DEBUG is not set
