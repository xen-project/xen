Building xen.efi requires gcc 4.5.x or above (4.6.x or newer recommended, as
4.5.x was probably never really tested for this purpose) and binutils 2.22 or
newer. Additionally, the binutils build must be configured to include support
for the x86_64-pep emulation (i.e. `--enable-targets=x86_64-pep` or an option
of equivalent effect should be passed to the configure script).

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

The configuration file consists of one or more sections headed by a section
name enclosed in square brackets, with individual values specified in each
section. A section named `[global]` is treated specially to allow certain
settings to apply to all other sections (or to provide defaults for certain
settings in case individual sections don't specify them). A typical file would
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

Specifies a CPU microcode blob to load.

###`chain=<filename>`

Specifies an alternate configuration file to use in case the specified section
(and in particular its `kernel=` setting) can't be found in the default (or
specified) configuration file. This is only meaningful in the [global] section
and really not meant to be used together with the `-cfg=` command line option.

Filenames must be specified relative to the location of the EFI binary.

Extra options to be passed to Xen can also be specified on the command line,
following a `--` separator option.
