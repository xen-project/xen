.. SPDX-License-Identifier: CC-BY-4.0

How Xen Boots
=============

This is an at-a-glance reference of Xen's booting capabilities and
expectations.


Build
-----

A build of xen produces ``xen.gz`` and optionally ``xen.efi`` as final
artefacts.

 * For BIOS, Xen supports the Multiboot 1 and 2 protocols.

 * For EFI, Xen supports Multiboot 2 with EFI extensions, and native EFI64.

 * For virtualisation, Xen supports starting directly with the PVH boot
   protocol.


Objects
~~~~~~~

To begin with, most object files are compiled and linked.  This includes the
Multiboot 1 and 2 headers and entrypoints, including the Multiboot 2 tags for
EFI extensions.  When ``CONFIG_PVH_GUEST`` is selected at build time, this
includes the PVH entrypoint and associated ELF notes.

Depending on whether the compiler supports ``__attribute__((__ms_abi__))`` or
not, either an EFI stub is included which nops/fails applicable setup and
runtime calls, or full EFI support is included.


Protocols and entrypoints
~~~~~~~~~~~~~~~~~~~~~~~~~

All headers and tags are built in ``xen/arch/x86/boot/head.S``

The Multiboot 1 headers request aligned modules and memory information.  Entry
is via the start of the binary image, which is the ``start`` symbol.  This
entrypoint must be started in 32bit mode.

The Multiboot 2 headers are more flexible, and in addition request that the
image be loaded as high as possible below the 4G boundary, with 2M alignment.
Entry is still via the ``start`` symbol as with MB1, and still in 32bit mode.

Headers for the EFI MB2 extensions are also present.  These request that
``ExitBootServices()`` not be called, and register ``__efi_mb2_start`` as an
alternative entrypoint, entered in 64bit mode.

If ``CONFIG_PVH_GUEST`` was selected at build time, an Elf note is included
which indicates the ability to use the PVH boot protocol, and registers
``__pvh_start`` as the entrypoint, entered in 32bit mode.


xen.gz
~~~~~~

The objects are linked together to form ``xen-syms`` which is an ELF64
executable with full debugging symbols.  ``xen.gz`` is formed by stripping
``xen-syms``, then repackaging the result as an ELF32 object with a single
load section at 2MB, and ``gzip``-ing the result.  Despite the ELF32 having a
fixed load address, its contents are relocatable.

Any bootloader which unzips the binary and follows the ELF headers will place
it at the 2M boundary and jump to ``start`` which is the identified entry
point.  However, Xen depends on being entered with the MB1 or MB2 protocols,
and will terminate otherwise.

The MB2+EFI entrypoint depends on being entered with the MB2 protocol, and
will terminate if the entry protocol is wrong, or if EFI details aren't
provided, or if EFI Boot Services are not available.


xen.efi
~~~~~~~

When a PEI-capable toolchain is found, the objects are linked together and a
PE32+ binary is created.  It can be run directly from the EFI shell, and has
``efi_start`` as its entry symbol.

.. note::

   xen.efi does contain all MB1/MB2/PVH tags included in the rest of the
   build.  However, entry via anything other than the EFI64 protocol is
   unsupported, and won't work.


Boot
----

Xen, once loaded into memory, identifies its position in order to relocate
system structures.  For 32bit entrypoints, this necessarily requires a call
instruction, and therefore a stack, but none of the ABIs provide one.

Overall, given that on a BIOS-based system, the IVT and BDA occupy the first
5/16ths of the first page of RAM, with the rest free to use, Xen assumes the
top of the page is safe to use.
