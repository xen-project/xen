# Changelog

Notable changes to Xen will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

## [unstable UNRELEASED](https://xenbits.xen.org/gitweb/?p=xen.git;a=shortlog;h=staging) - TBD

### Changed
 - Repurpose command line gnttab_max_{maptrack_,}frames options so they don't
   cap toolstack provided values.
 - Ignore VCPUOP_set_singleshot_timer's VCPU_SSHOTTMR_future flag. The only
   known user doesn't use it properly, leading to in-guest breakage.

### Added
 - On x86, support for features new in Intel Sapphire Rapids CPUs:
   - PKS (Protection Key Supervisor) available to HVM/PVH guests.
   - VM-Notify used by Xen to mitigate certain micro-architectural pipeline
     livelocks, instead of crashing the entire server.
   - Bus-lock detection, used by Xen to mitigate (by rate-limiting) the system
     wide impact of a guest misusing atomic instructions.
 - xl/libxl can customize SMBIOS strings for HVM guests.
 - Add support for AVX512-FP16 on x86.

## [4.17.0](https://xenbits.xen.org/gitweb/?p=xen.git;a=shortlog;h=RELEASE-4.17.0) - 2022-12-12

### Changed
 - On x86 "vga=current" can now be used together with GrUB2's gfxpayload setting. Note that
   this requires use of "multiboot2" (and "module2") as the GrUB commands loading Xen.
 - The "gnttab" option now has a new command line sub-option for disabling the
   GNTTABOP_transfer functionality.
 - The x86 MCE command line option info is now updated.

### Added / support upgraded
 - Out-of-tree builds for the hypervisor now supported.
 - __ro_after_init support, for marking data as immutable after boot.
 - The project has officially adopted 4 directives and 24 rules of MISRA-C,
   added MISRA-C checker build integration, and defined how to document
   deviations.
 - IOMMU superpage support on x86, affecting PV guests as well as HVM/PVH ones
   when they don't share page tables with the CPU (HAP / EPT / NPT).
 - Support for VIRT_SSBD and MSR_SPEC_CTRL for HVM guests on AMD.
 - Improved TSC, CPU, and APIC clock frequency calibration on x86.
 - Support for Xen using x86 Control Flow Enforcement technology for its own
   protection. Both Shadow Stacks (ROP protection) and Indirect Branch
   Tracking (COP/JOP protection).
 - Add mwait-idle support for SPR and ADL on x86.
 - Extend security support for hosts to 12 TiB of memory on x86.
 - Add command line option to set cpuid parameters for dom0 at boot time on x86.
 - Improved static configuration options on Arm.
 - cpupools can be specified at boot using device tree on Arm.
 - It is possible to use PV drivers with dom0less guests, allowing statically
   booted dom0less guests with PV devices.
 - On Arm, p2m structures are now allocated out of a pool of memory set aside at
   domain creation.
 - Improved mitigations against Spectre-BHB on Arm.
 - Support VirtIO-MMIO devices device-tree binding creation in toolstack on Arm.
 - Allow setting the number of CPUs to activate at runtime from command line
   option on Arm.
 - Grant-table support on Arm was improved and hardened by implementing
   "simplified M2P-like approach for the xenheap pages"
 - Add Renesas R-Car Gen4 IPMMU-VMSA support on Arm.
 - Add i.MX lpuart and i.MX8QM support on Arm.
 - Improved toolstack build system.
 - Add Xue - console over USB 3 Debug Capability.
 - gitlab-ci automation: Fixes and improvements together with new tests.

### Removed / support downgraded
 - dropped support for the (x86-only) "vesa-mtrr" and "vesa-remap" command line options

## [4.16.0](https://xenbits.xen.org/gitweb/?p=xen.git;a=shortlog;h=RELEASE-4.16.0) - 2021-12-02

### Removed
 - XENSTORED_ROOTDIR environment variable from configuartion files and
   initscripts, due to being unused.

### Changed
 - Quarantining of passed-through PCI devices no longer defaults to directing I/O to a scratch
   page, matching original post-XSA-302 behavior (albeit the change was also backported, first
   appearing in 4.12.2 and 4.11.4). Prior (4.13...4.15-like) behavior can be arranged for
   either by enabling the IOMMU_QUARANTINE_SCRATCH_PAGE setting at build (configuration) time
   or by passing "iommu=quarantine=scratch-page" on the hypervisor command line.
 - pv-grub stubdoms will no longer be built per default. In order to be able to use pv-grub
   configure needs to be called with "--enable-pv-grub" as parameter.
 - qemu-traditional based device models (both, qemu-traditional and ioemu-stubdom) will
   no longer be built per default. In order to be able to use those, configure needs to
   be called with "--enable-qemu-traditional" as parameter.
 - Fixes for credit2 scheduler stability in corner case conditions.
 - Ongoing improvements in the hypervisor build system.
 - vtpmmgr miscellaneous fixes in preparation for TPM 2.0 support.
 - 32bit PV guests only supported in shim mode.
 - Improved PVH dom0 debug key handling.
 - Fix booting on some Intel systems without a PIT (i8254).
 - Cleanup of the xenstore library interface.
 - Fix truncation of return value from xencall2 by introducing a new helper
   that returns a long instead.
 - Fix system register accesses on Arm to use the proper 32/64bit access size.
 - Various fixes for Arm OP-TEE mediator.
 - Switch to domheap for Xen page tables.

### Added
 - 32bit Arm builds to the gitlab-ci automated tests.
 - x86 full system tests to the gitlab-ci automated tests.
 - Arm limited vPMU support for guests.
 - Static physical memory allocation for dom0less on arm64.
 - dom0less EFI support on arm64.
 - GICD_ICPENDR register handling in vGIC emulation to support Zephyr OS.
 - CPU feature leveling on arm64 platform with heterogeneous cores.
 - Report unpopulated memory regions safe to use for external mappings, Arm and
   device tree only.
 - Support of generic DT IOMMU bindings for Arm SMMU v2.
 - Limit grant table version on a per-domain basis.

## [4.15.0](https://xenbits.xen.org/gitweb/?p=xen.git;a=shortlog;h=RELEASE-4.15.0) - 2021-04-08

### Added / support upgraded
 - ARM IOREQ servers (device emulation etc.) (Tech Preview)
 - Renesas IPMMU-VMSA (Supported, not security supported; was Tech Preview)
 - ARM SMMUv3 (Tech Preview)
 - Switched MSR accesses to deny by default policy.
 - Intel Processor Trace support (Tech Preview)
 - Named PCI devices for xl/libxl
 - Improved documentation for xl PCI configuration format
 - Support for zstd-compressed dom0 (x86) and domU kernels
 - EFI: Enable booting unified hypervisor/kernel/initrd/DT images
 - Reduce ACPI verbosity by default
 - Add ucode=allow-same option to test late microcode loading path
 - Library improvements from NetBSD ports upstreamed
 - CI loop: Add Alpine Linux, Ubuntu Focal targets; drop CentOS 6
 - CI loop: Add qemu-based dom0 / domU test for ARM
 - CI loop: Add dom0less aarch64 smoke test
 - x86: Allow domains to use AVX-VNNI instructions
 - Factored out HVM-specific shadow code, improving code clarity and reducing the size of PV-only hypervisor builds
 - Added XEN_SCRIPT_DIR configuration option to specify location for Xen scripts, rather than hard-coding /etc/xen/scripts
 - xennet: Documented a way for the backend (or toolstack) to specify MTU to the frontend
 - xenstore can now be live-updated on a running system. (Tech preview)
 - Some additional affordances in various xl subcommands.
 - Added workarounds for the following ARM errata: Cortex A53 #843419, Cortex A55 #1530923, Cortex A72 #853709, Cortex A73 #858921, Cortex A76 #1286807, Neoverse-N1 #1165522
 - On detecting a host crash, some debug key handlers can automatically triggered to aid in debugging
 - Increase the maximum number of guests which can share a single IRQ from 7 to 16, and make this configurable with irq-max-guests

### Removed / support downgraded

 - qemu-xen-traditional as host process device model, now "No security
   support, not recommended".  (Use as stub domain device model is still
   supported - see SUPPORT.md.)

## [4.14.0](https://xenbits.xen.org/gitweb/?p=xen.git;a=shortlog;h=RELEASE-4.14.0) - 2020-07-23

### Added
 - This file and MAINTAINERS entry.
 - Use x2APIC mode whenever available, regardless of interrupt remapping
   support.
 - Performance improvements to guest assisted TLB flushes, either when using
   the Xen hypercall interface or the viridian one.
 - Assorted pvshim performance and scalability improvements plus some bug
   fixes.
 - Hypervisor framework to ease porting Xen to run on hypervisors.
 - Initial support to run on Hyper-V.
 - Initial hypervisor file system (hypfs) support.
 - libxl support for running qemu-xen device model in a linux stubdomain.
 - New 'domid_policy', allowing domain-ids to be randomly chosen.
 - Option to preserve domain-id across migrate or save+restore.
 - Support in kdd for initial KD protocol handshake for Win 7, 8 and 10 (64 bit).
 - Tech preview support for Control-flow Execution Technology, with Xen using
   Supervisor Shadow Stacks for its own protection.

### Changed
 - The CPUID data seen by a guest on boot is now moved in the migration
   stream.  A guest migrating between non-identical hardware will now no
   longer observe details such as Family/Model/Stepping, Cache, etc changing.
   An administrator still needs to take care to ensure the features visible to
   the guest at boot are compatible with anywhere it might migrate.

## [4.13.0](https://xenbits.xen.org/gitweb/?p=xen.git;a=shortlog;h=RELEASE-4.13.0) - 2019-12-17

> Pointer to release from which CHANGELOG tracking starts
