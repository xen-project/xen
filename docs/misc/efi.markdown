For x86, building xen.efi requires gcc 4.5.x or above (4.6.x or newer
recommended, as 4.5.x was probably never really tested for this purpose) and
binutils 2.22 or newer.  Additionally, the binutils build must be configured to
include support for the x86_64-pep emulation (i.e.
`--enable-targets=x86_64-pep` or an option of equivalent effect should be
passed to the configure script).

For arm64, the PE/COFF header is open-coded in assembly, so no toolchain
support for PE/COFF is required.  Also, the PE/COFF header co-exists with the
normal Image format, so a single binary may be booted as an Image file or as an
EFI application.  When booted as an EFI application, Xen requires a
configuration file as described below unless a bootloader, such as GRUB, has
loaded the modules and describes them in the device tree provided to Xen.  If a
bootloader provides a device tree containing modules then any configuration
files are ignored, and the bootloader is responsible for populating all
relevant device tree nodes.

Once built, `make install-xen` will place the resulting binary directly into
the EFI boot partition, provided `EFI_VENDOR` is set in the environment (and
`EFI_MOUNTPOINT` is overridden as needed, should the default of `/boot/efi` not
match your system). The xen.efi binary will also be installed in
`/usr/lib64/efi/`, unless `EFI_DIR` is set in the environment to override this
default.

The binary itself will require a configuration file (names with the `.efi`
extension of the binary's name replaced by `.cfg`, and - until an existing
file is found - trailing name components dropped at `.`, `-`, and `_`
separators will be tried) to be present in the same directory as the binary.
(To illustrate the name handling, a binary named `xen-4.2-unstable.efi` would
try `xen-4.2-unstable.cfg`, `xen-4.2.cfg`, `xen-4.cfg`, and `xen.cfg` in
order.) One can override this with a command line option (`-cfg=<filename>`).
This configuration file and EFI commandline are only used for booting directly
from EFI firmware, or when using an EFI loader that does not support
the multiboot2 protocol.  When booting using GRUB or another multiboot aware
loader the EFI commandline is ignored and all information is passed from
the loader to Xen using the multiboot protocol.

The configuration file consists of one or more sections headed by a section
name enclosed in square brackets, with individual values specified in each
section. A section named `[global]` is treated specially to allow certain
settings to apply to all other sections (or to provide defaults for certain
settings in case individual sections don't specify them). This file (for now)
needs to be of ASCII type and not e.g. UTF-8 or UTF-16. A typical file would
thus look like this (`#` serving as comment character):

    **************************example begin******************************

    [global]
    default=sle11sp2
    
    [sle11sp2]
    options=console=vga,com1 com1=57600 loglvl=all noreboot
    kernel=vmlinuz-3.0.31-0.4-xen ignore_loglevel #earlyprintk=xen
    ramdisk=initrd-3.0.31-0.4-xen

    **************************example end********************************

The individual values used here are:

###`default=<name>`

Specifies the section to use for booting, if none was specified on the command
line; only meaningful in the `[global]` section. This isn't required; if
absent, section headers will be ignored and for each value looked for the
first instance within the file will be used.

###`options=<text>`

Specifies the options passed to the hypervisor, see [Xen Hypervisor Command
Line Options](xen-command-line.html).

###`kernel=<filename>[ <options>]`

Specifies the Dom0 kernel binary and the options to pass to it.

###`ramdisk=<filename>`

Specifies a Linux-style initial RAM disk image to load.

Other values to specify are:

###`video=gfx-<xres>[x<yres>[x<depth>]]`

Specifies a video mode to select if available. In case of problems, the
`-basevideo` command line option can be used to skip altering video modes.

###`xsm=<filename>`

Specifies an XSM module to load.

###`ucode=<filename>`

Specifies a CPU microcode blob to load. (x86 only)

###`dtb=<filename>`

Specifies a device tree file to load.  The platform firmware may provide a
DTB in an EFI configuration table, so this field is optional in that
case. A dtb specified in the configuration file will override a device tree
provided in the EFI configuration table. (ARM only)

###`chain=<filename>`

Specifies an alternate configuration file to use in case the specified section
(and in particular its `kernel=` setting) can't be found in the default (or
specified) configuration file. This is only meaningful in the [global] section
and really not meant to be used together with the `-cfg=` command line option.

Filenames must be specified relative to the location of the EFI binary.

Extra options to be passed to Xen can also be specified on the command line,
following a `--` separator option.
