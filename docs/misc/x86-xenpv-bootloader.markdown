# Xen x86 PV Bootloader Protocol

## Introduction

One method for booting an x86 Xen PV guest is to use a PV bootloader,
that is, a bootloader which is itself a PV kernel but which behaves as
a bootloader (examples include the pvgrub-legacy and grub2 targeting
Xen).

In many cases the user wishes to manage this PV bootloader from within
the guest, and therefore wishes to chainload something from the guest
filesystem, most likely via a stage 1 PV bootloader provided by dom0.

The purpose of this document is to define the paths within the guest
filesystem where a stage 1 bootloader should look for the in-guest PV
bootloader to load and the protocol/format expected from the
to-be-chainloaded bootloader.

## Protocol

The bootloader binary should be an ELF file of the appropriate type
(32- or 64-bit). It should contain the standard Xen ELF notes allowing
it to be loaded by the Xen toolstack domain builder (TBD: Reference).

## Path

The second stage bootloader should be installed into the guest
filesystem as:

 * `/boot/xen/pvboot-<ARCH>.elf`

Where `<ARCH>` is the first element of the GNU triplet e.g. one of:

 * i386 (nb only i386, not i686 etc), corresponding to the Xen
   x86\_32(p) arch;
 * x86\_64, corresponding to the Xen x86\_64 arch;

It is allowable for `/boot` to be a separate filesystem from `/` and
therefore stage 1 bootloaders should search
`/boot/xen/pvboot-<ARCH>.elf` and `/xen/pvboot-<ARCH>.elf` (in that
order). The `xen` directory should be on the same filesystem as /boot
and therefore it is not necessary to search for /pvboot-<ARCH>.elf.

It is not in general possible under Xen for a bootloader to boot a
kernel of a different width from itself, and this extends to
chainloading from a stage one. Therefore it is permissible to have
both `/boot/xen/pvboot-i386.elf` and `/boot/xen/pvboot-x86\_64.elf`
present in a guest to be used by the appropriate stage 1 (e.g. for
systems with 32-bit userspace and an optional 64-bit kernel).
