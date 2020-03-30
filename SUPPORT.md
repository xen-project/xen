% Support statement for this release

This document describes the support status
and in particular the security support status of the Xen branch
within which you find it.

See the bottom of the file
for the definitions of the support status levels etc.

# Release Support

    Xen-Version: 4.14-unstable
    Initial-Release: n/a
    Supported-Until: TBD
    Security-Support-Until: Unreleased - not yet security-supported

Release Notes
: <a href="https://wiki.xenproject.org/wiki/Xen_Project_X.YY_Release_Notes">RN</a>

# Feature Support

## Kconfig

EXPERT and DEBUG Kconfig options are not security supported. Other
Kconfig options are supported, if the related features are marked as
supported in this document.

## Host Architecture

### x86-64

    Status: Supported

### ARM v7 + Virtualization Extensions

    Status: Supported

### ARM v8

    Status: Supported

## Host hardware support

### Physical CPU Hotplug

    Status, x86: Supported

### Physical Memory Hotplug

    Status, x86: Supported

### Host ACPI (via Domain 0)

    Status, x86 PV: Supported
    Status, ARM: Experimental

### x86/Intel Platform QoS Technologies

    Status: Tech Preview

### IOMMU

    Status, AMD IOMMU: Supported
    Status, Intel VT-d: Supported
    Status, ARM SMMUv1: Supported
    Status, ARM SMMUv2: Supported
    Status, Renesas IPMMU-VMSA: Tech Preview

### ARM/GICv3 ITS

Extension to the GICv3 interrupt controller to support MSI.

    Status: Experimental

## Guest Type

### x86/PV

Traditional Xen PV guest

No hardware requirements

    Status: Supported

### x86/HVM

Fully virtualised guest using hardware virtualisation extensions

Requires hardware virtualisation support (Intel VMX / AMD SVM)

    Status, domU: Supported

### x86/PVH

PVH is a next-generation paravirtualized mode
designed to take advantage of hardware virtualization support when possible.
During development this was sometimes called HVMLite or PVHv2.

Requires hardware virtualisation support (Intel VMX / AMD SVM).

Dom0 support requires an IOMMU (Intel VT-d / AMD IOMMU).

    Status, domU: Supported
    Status, dom0: Experimental

### ARM

ARM only has one guest type at the moment

    Status: Supported

## Toolstack

### xl

    Status: Supported

### Direct-boot kernel image format

Format which the toolstack accepts for direct-boot kernels

    Supported, x86: bzImage, ELF
    Supported, ARM32: zImage
    Supported, ARM64: Image

### Dom0 init support for xl

    Status, SysV: Supported
    Status, systemd: Supported
    Status, BSD-style: Supported

### JSON output support for xl

Output of information in machine-parseable JSON format

    Status: Experimental

### Open vSwitch integration for xl

    Status, Linux: Supported

### Virtual cpu hotplug

    Status: Supported

### QEMU backend hotplugging for xl

    Status: Supported

## Toolstack/3rd party

### libvirt driver for xl

    Status: Supported, Security support external

## Debugging, analysis, and crash post-mortem

### Host serial console

    Status, NS16550: Supported
    Status, EHCI: Supported
    Status, Cadence UART (ARM): Supported
    Status, PL011 UART (ARM): Supported
    Status, Exynos 4210 UART (ARM): Supported
    Status, OMAP UART (ARM): Supported
    Status, SCI(F) UART: Supported

### Hypervisor 'debug keys'

These are functions triggered either from the host serial console,
or via the xl 'debug-keys' command,
which cause Xen to dump various hypervisor state to the console.

    Status: Supported, not security supported

### Hypervisor synchronous console output (sync_console)

Xen command-line flag to force synchronous console output.

    Status: Supported, not security supported

Useful for debugging, but not suitable for production environments
due to incurred overhead.

### gdbsx

    Status, x86: Supported, not security supported

Debugger to debug ELF guests

### Soft-reset for PV guests

Soft-reset allows a new kernel to start 'from scratch' with a fresh VM state,
but with all the memory from the previous state of the VM intact.
This is primarily designed to allow "crash kernels",
which can do core dumps of memory to help with debugging in the event of a crash.

    Status: Supported

### xentrace

Tool to capture Xen trace buffer data

    Status, x86: Supported

### gcov

Export hypervisor coverage data suitable for analysis by gcov or lcov.

    Status: Supported, Not security supported

## Memory Management

### Dynamic memory control

Allows a guest to add or remove memory after boot-time.
This is typically done by a guest kernel agent known as a "balloon driver".

    Status: Supported

### Populate-on-demand memory

This is a mechanism that allows normal operating systems with only a balloon driver
to boot with memory < maxmem.

    Status, x86 HVM: Supported

### Memory Sharing

Allow sharing of identical pages between guests

    Status, x86 HVM: Expermental

### Memory Paging

Allow pages belonging to guests to be paged to disk

    Status, x86 HVM: Experimenal

### Alternative p2m

Alternative p2m (altp2m) allows external monitoring of guest memory
by maintaining multiple physical to machine (p2m) memory mappings.

    Status, x86 HVM: Tech Preview
    Status, ARM: Tech Preview

## Resource Management

### CPU Pools

Groups physical cpus into distinct groups called "cpupools",
with each pool having the capability
of using different schedulers and scheduling properties.

    Status: Supported

### Core Scheduling

Allows to group virtual cpus into virtual cores which are scheduled on the
physical cores. This results in never running different guests at the same
time on the same physical core.

    Status, x86: Experimental

### Credit Scheduler

A weighted proportional fair share virtual CPU scheduler.
This is the default scheduler.

    Status: Supported

### Credit2 Scheduler

A general purpose scheduler for Xen,
designed with particular focus on fairness, responsiveness, and scalability

    Status: Supported

### RTDS based Scheduler

A soft real-time CPU scheduler
built to provide guaranteed CPU capacity to guest VMs on SMP hosts

    Status: Experimental

### ARINC653 Scheduler

A periodically repeating fixed timeslice scheduler.

    Status: Supported

Currently only single-vcpu domains are supported.

### Null Scheduler

A very simple, very static scheduling policy
that always schedules the same vCPU(s) on the same pCPU(s).
It is designed for maximum determinism and minimum overhead
on embedded platforms.

    Status: Experimental

### NUMA scheduler affinity

Enables NUMA aware scheduling in Xen

    Status, x86: Supported

## Scalability

### Super page support

NB that this refers to the ability of guests
to have higher-level page table entries point directly to memory,
improving TLB performance.
On ARM, and on x86 in HAP mode,
the guest has whatever support is enabled by the hardware.

This feature is independent
of the ARM "page granularity" feature (see below).

    Status, x86 HVM/PVH, HAP: Supported
    Status, x86 HVM/PVH, Shadow, 2MiB: Supported
    Status, ARM: Supported

On x86 in shadow mode, only 2MiB (L2) superpages are available;
furthermore, they do not have the performance characteristics
of hardware superpages.

### x86/PVHVM

This is a useful label for a set of hypervisor features
which add paravirtualized functionality to HVM guests
for improved performance and scalability.
This includes exposing event channels to HVM guests.

    Status: Supported

## High Availability and Fault Tolerance

### Remus Fault Tolerance

    Status: Experimental

### COLO Manager

    Status: Experimental

### x86/vMCE

Forward Machine Check Exceptions to appropriate guests

    Status: Supported

## Virtual driver support, guest side

### Blkfront

Guest-side driver capable of speaking the Xen PV block protocol

    Status, Linux: Supported
    Status, FreeBSD: Supported, Security support external
    Status, NetBSD: Supported, Security support external
    Status, OpenBSD: Supported, Security support external
    Status, Windows: Supported

### Netfront

Guest-side driver capable of speaking the Xen PV networking protocol

    Status, Linux: Supported
    Status, FreeBSD: Supported, Security support external
    Status, NetBSD: Supported, Security support external
    Status, OpenBSD: Supported, Security support external
    Status, Windows: Supported

### PV Framebuffer (frontend)

Guest-side driver capable of speaking the Xen PV Framebuffer protocol

    Status, Linux (xen-fbfront): Supported

### PV display (frontend)

Guest-side driver capable of speaking the Xen PV display protocol

    Status, Linux: Supported

### PV Console (frontend)

Guest-side driver capable of speaking the Xen PV console protocol

    Status, Linux (hvc_xen): Supported
    Status, FreeBSD: Supported, Security support external
    Status, NetBSD: Supported, Security support external
    Status, Windows: Supported

### PV keyboard (frontend)

Guest-side driver capable of speaking the Xen PV keyboard protocol.
Note that the "keyboard protocol" includes mouse / pointer /
multi-touch support as well.

    Status, Linux (xen-kbdfront): Supported

### PV USB (frontend)

    Status, Linux: Supported

### PV SCSI protocol (frontend)

    Status, Linux: Supported, with caveats

NB that while the PV SCSI frontend is in Linux and tested regularly,
there is currently no xl support.

### PV TPM (frontend)

Guest-side driver capable of speaking the Xen PV TPM protocol

    Status, Linux (xen-tpmfront): Tech Preview

### PV 9pfs frontend

Guest-side driver capable of speaking the Xen 9pfs protocol

    Status, Linux: Tech Preview

### PVCalls (frontend)

Guest-side driver capable of making pv system calls

    Status, Linux: Tech Preview

### PV sound (frontend)

Guest-side driver capable of speaking the Xen PV sound protocol

    Status, Linux: Supported

## Virtual device support, host side

For host-side virtual device support,
"Supported" and "Tech preview" include xl/libxl support
unless otherwise noted.

### Blkback

Host-side implementations of the Xen PV block protocol.

    Status, Linux (xen-blkback): Supported
    Status, QEMU (xen_disk), raw format: Supported
    Status, QEMU (xen_disk), qcow format: Supported
    Status, QEMU (xen_disk), qcow2 format: Supported
    Status, QEMU (xen_disk), vhd format: Supported
    Status, FreeBSD (blkback): Supported, Security support external
    Status, NetBSD (xbdback): Supported, security support external
    Status, Blktap2, raw format: Deprecated
    Status, Blktap2, vhd format: Deprecated

Backends only support raw format unless otherwise specified.

### Netback

Host-side implementations of Xen PV network protocol

    Status, Linux (xen-netback): Supported
    Status, FreeBSD (netback): Supported, Security support external
    Status, NetBSD (xennetback): Supported, Security support external

### PV Framebuffer (backend)

Host-side implementation of the Xen PV framebuffer protocol

    Status, QEMU: Supported

### PV Console (xenconsoled)

Host-side implementation of the Xen PV console protocol

    Status: Supported

### PV keyboard (backend)

Host-side implementation of the Xen PV keyboard protocol.
Note that the "keyboard protocol" includes mouse / pointer support as well.

    Status, QEMU: Supported

### PV USB (backend)

Host-side implementation of the Xen PV USB protocol

    Status, QEMU: Supported

### PV SCSI protocol (backend)

    Status, Linux: Experimental

NB that while the PV SCSI backend is in Linux and tested regularly,
there is currently no xl support.

### PV TPM (backend)

    Status: Tech Preview

### PV 9pfs (backend)

    Status, QEMU: Tech Preview

### PVCalls (backend)

    Status, Linux: Experimental

PVCalls backend has been checked into Linux,
but has no xl support.

### Online resize of virtual disks

    Status: Supported

## Security

### Driver Domains

"Driver domains" means allowing non-Domain 0 domains
with access to physical devices to act as back-ends.

    Status: Supported, with caveats

See the appropriate "Device Passthrough" section
for more information about security support.

### Device Model Stub Domains

    Status: Supported, with caveats

Vulnerabilities of a device model stub domain
to a hostile driver domain (either compromised or untrusted)
are excluded from security support.

### Device Model Deprivileging

    Status, Linux dom0: Tech Preview, with limited support

This means adding extra restrictions to a device model in order to
prevent a compromised device model from attacking the rest of the
domain it's running in (normally dom0).

"Tech preview with limited support" means we will not issue XSAs for
the _additional_ functionality provided by the feature; but we will
issue XSAs in the event that enabling this feature opens up a security
hole that would not be present without the feature disabled.

For example, while this is classified as tech preview, a bug in libxl
which failed to change the user ID of QEMU would not receive an XSA,
since without this feature the user ID wouldn't be changed. But a
change which made it possible for a compromised guest to read
arbitrary files on the host filesystem without compromising QEMU would
be issued an XSA, since that does weaken security.

### KCONFIG Expert

    Status: Experimental

### Live Patching

    Status, x86: Supported
    Status, ARM: Experimental

Compile time disabled for ARM by default.

### Virtual Machine Introspection

    Status, x86: Supported, not security supported

### XSM & FLASK

    Status: Experimental

Compile time disabled by default.

Also note that using XSM
to delegate various domain control hypercalls
to particular other domains, rather than only permitting use by dom0,
is also specifically excluded from security support for many hypercalls.
Please see XSA-77 for more details.

### FLASK default policy

    Status: Experimental

The default policy includes FLASK labels and roles for a "typical" Xen-based system
with dom0, driver domains, stub domains, domUs, and so on.

## Virtual Hardware, Hypervisor

### x86/Nested PV

This means running a Xen hypervisor inside an HVM domain on a Xen system,
with support for PV L2 guests only
(i.e., hardware virtualization extensions not provided
to the guest).

    Status, x86 Xen HVM: Tech Preview

This works, but has performance limitations
because the L1 dom0 can only access emulated L1 devices.

Xen may also run inside other hypervisors (KVM, Hyper-V, VMWare),
but nobody has reported on performance.

### x86/Nested HVM

This means providing hardware virtulization support to guest VMs
allowing, for instance, a nested Xen to support both PV and HVM guests.
It also implies support for other hypervisors,
such as KVM, Hyper-V, Bromium, and so on as guests.

    Status, x86 HVM: Experimental

### vPMU

Virtual Performance Management Unit for HVM guests

    Status, x86: Supported, Not security supported

Disabled by default (enable with hypervisor command line option).
This feature is not security supported: see https://xenbits.xen.org/xsa/advisory-163.html

### Argo: Inter-domain message delivery by hypercall

    Status: Experimental

### x86/PCI Device Passthrough

    Status, x86 PV: Supported, with caveats
    Status, x86 HVM: Supported, with caveats

Only systems using IOMMUs are supported.

Not compatible with migration, populate-on-demand, altp2m,
introspection, memory sharing, or memory paging.

Because of hardware limitations
(affecting any operating system or hypervisor),
it is generally not safe to use this feature
to expose a physical device to completely untrusted guests.
However, this feature can still confer significant security benefit
when used to remove drivers and backends from domain 0
(i.e., Driver Domains).

### x86/Multiple IOREQ servers

An IOREQ server provides emulated devices to HVM and PVH guests.
QEMU is normally the only IOREQ server,
but Xen has support for multiple IOREQ servers.
This allows for custom or proprietary device emulators
to be used in addition to QEMU.

	Status: Experimental

### ARM/Non-PCI device passthrough

    Status: Supported, not security supported

Note that this still requires an IOMMU
that covers the DMA of the device to be passed through.

### ARM: 16K and 64K page granularity in guests

    Status: Supported, with caveats

No support for QEMU backends in a 16K or 64K domain.

### ARM: Guest Device Tree support

    Status: Supported

### ARM: Guest ACPI support

    Status: Supported

### Arm: OP-TEE Mediator

    Status: Tech Preview

## Virtual Hardware, QEMU

This section describes supported devices available in HVM mode using a
qemu devicemodel (the default).

    Status: Support scope restricted 

Note that other devices are available but not security supported.

### x86/Emulated platform devices (QEMU):

    Status, piix3: Supported

### x86/Emulated network (QEMU):

    Status, e1000: Supported
    Status, rtl8193: Supported
    Status, virtio-net: Supported

### x86/Emulated storage (QEMU):

    Status, piix3 ide: Supported
    Status, ahci: Supported

See the section **Blkback** for image formats supported by QEMU.

### x86/Emulated graphics (QEMU):

    Status, cirrus-vga: Supported
    Status, stdvga: Supported

### x86/Emulated audio (QEMU):

    Status, sb16: Supported
    Status, es1370: Supported
    Status, ac97: Supported

### x86/Emulated input (QEMU):

    Status, usbmouse: Supported
    Status, usbtablet: Supported
    Status, ps/2 keyboard: Supported
    Status, ps/2 mouse: Supported

### x86/Emulated serial card (QEMU):

    Status, UART 16550A: Supported

### x86/Host USB passthrough (QEMU):

    Status: Supported, not security supported

## Virtual Firmware

### x86/HVM iPXE

Booting a guest via PXE.

    Status: Supported, with caveats

PXE inherently places full trust of the guest in the network,
and so should only be used
when the guest network is under the same administrative control
as the guest itself.

### x86/HVM BIOS

Booting a guest via guest BIOS firmware

    Status, SeaBIOS (qemu-xen): Supported
    Status, ROMBIOS (qemu-xen-traditional): Supported

### x86/HVM OVMF

OVMF firmware implements the UEFI boot protocol.

    Status, qemu-xen: Supported

# Format and definitions

This file contains prose, and machine-readable fragments.
The data in a machine-readable fragment relate to
the section and subsection in which it is found.

The file is in markdown format.
The machine-readable fragments are markdown literals
containing RFC-822-like (deb822-like) data.

In each case, descriptions which expand on the name of a feature as
provided in the section heading, precede the Status indications.
Any paragraphs which follow the Status indication are caveats or
qualifications of the information provided in Status fields.

## Keys found in the Feature Support subsections

### Status

This gives the overall status of the feature,
including security support status, functional completeness, etc.
Refer to the detailed definitions below.

If support differs based on implementation
(for instance, x86 / ARM, Linux / QEMU / FreeBSD),
one line for each set of implementations will be listed.

## Definition of Status labels

Each Status value corresponds to levels of security support,
testing, stability, etc., as follows:

### Experimental

    Functional completeness: No
    Functional stability: Here be dragons
    Interface stability: Not stable
    Security supported: No

### Tech Preview

    Functional completeness: Yes
    Functional stability: Quirky
    Interface stability: Provisionally stable
    Security supported: No

#### Supported

    Functional completeness: Yes
    Functional stability: Normal
    Interface stability: Yes
    Security supported: Yes

#### Deprecated

    Functional completeness: Yes
    Functional stability: Quirky
    Interface stability: No (as in, may disappear the next release)
    Security supported: Yes

All of these may appear in modified form.
There are several interfaces, for instance,
which are officially declared as not stable;
in such a case this feature may be described as "Stable / Interface not stable".

## Definition of the status label interpretation tags

### Functionally complete

Does it behave like a fully functional feature?
Does it work on all expected platforms,
or does it only work for a very specific sub-case?
Does it have a sensible UI,
or do you have to have a deep understanding of the internals
to get it to work properly?

### Functional stability

What is the risk of it exhibiting bugs?

General answers to the above:

  * **Here be dragons**

    Pretty likely to still crash / fail to work.
    Not recommended unless you like life on the bleeding edge.

  * **Quirky**

    Mostly works but may have odd behavior here and there.
    Recommended for playing around or for non-production use cases.

  * **Normal**

    Ready for production use

### Interface stability

If I build a system based on the current interfaces,
will they still work when I upgrade to the next version?

  * **Not stable**

    Interface is still in the early stages and
    still fairly likely to be broken in future updates.

  * **Provisionally stable**

    We're not yet promising backwards compatibility,
    but we think this is probably the final form of the interface.
    It may still require some tweaks.

  * **Stable**

    We will try very hard to avoid breaking backwards  compatibility,
    and to fix any regressions that are reported.

### Security supported

Will XSAs be issued if security-related bugs are discovered
in the functionality?

If "no",
anyone who finds a security-related bug in the feature
will be advised to
post it publicly to the Xen Project mailing lists
(or contact another security response team,
if a relevant one exists).

Bugs found after the end of **Security-Support-Until**
in the Release Support section will receive an XSA
if they also affect newer, security-supported, versions of Xen.
However, the Xen Project will not provide official fixes
for non-security-supported versions.

Three common 'diversions' from the 'Supported' category
are given the following labels:

  * **Supported, Not security supported**

    Functionally complete, normal stability,
    interface stable, but no security support

  * **Supported, Security support external**

    This feature is security supported
    by a different organization (not the XenProject).
    See **External security support** below.

  * **Supported, with caveats**

    This feature is security supported only under certain conditions,
    or support is given only for certain aspects of the feature,
    or the feature should be used with care
    because it is easy to use insecurely without knowing it.
    Additional details will be given in the description.

### Interaction with other features

Not all features interact well with all other features.
Some features are only for HVM guests; some don't work with migration, &c.

### External security support

The XenProject security team
provides security support for XenProject projects.

We also provide security support for Xen-related code in Linux,
which is an external project but doesn't have its own security process.

External projects that provide their own security support for Xen-related features are listed below.

  * QEMU https://wiki.qemu.org/index.php/SecurityProcess

  * Libvirt https://libvirt.org/securityprocess.html

  * FreeBSD https://www.freebsd.org/security/

  * NetBSD http://www.netbsd.org/support/security/

  * OpenBSD https://www.openbsd.org/security.html
