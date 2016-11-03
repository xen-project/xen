**NOTE**: this document will be merged into `pvh.markdown` once PVH is replaced
with the HVMlite implementation.

# x86/HVM direct boot ABI #

Since the Xen entry point into the kernel can be different from the
native entry point, a `ELFNOTE` is used in order to tell the domain
builder how to load and jump into the kernel entry point:

    ELFNOTE(Xen, XEN_ELFNOTE_PHYS32_ENTRY,          .long,  xen_start32)

The presence of the `XEN_ELFNOTE_PHYS32_ENTRY` note indicates that the
kernel supports the boot ABI described in this document.

The domain builder must load the kernel into the guest memory space and
jump into the entry point defined at `XEN_ELFNOTE_PHYS32_ENTRY` with the
following machine state:

 * `ebx`: contains the physical memory address where the loader has placed
   the boot start info structure.

 * `cr0`: bit 0 (PE) must be set. All the other writeable bits are cleared.

 * `cr4`: all bits are cleared.

 * `cs`: must be a 32-bit read/execute code segment with a base of ‘0’
   and a limit of ‘0xFFFFFFFF’. The selector value is unspecified.

 * `ds`, `es`: must be a 32-bit read/write data segment with a base of
   ‘0’ and a limit of ‘0xFFFFFFFF’. The selector values are all unspecified.

 * `tr`: must be a 32-bit TSS (active) with a base of '0' and a limit of '0x67'.

 * `eflags`: bit 17 (VM) must be cleared. Bit 9 (IF) must be cleared.
   Bit 8 (TF) must be cleared. Other bits are all unspecified.

All other processor registers and flag bits are unspecified. The OS is in
charge of setting up it's own stack, GDT and IDT.

The format of the boot start info structure (pointed to by %ebx) can be found
in xen/include/public/arch-x86/hvm/start_info.h

Other relevant information needed in order to boot a guest kernel
(console page address, xenstore event channel...) can be obtained
using HVMPARAMS, just like it's done on HVM guests.

The setup of the hypercall page is also performed in the same way
as HVM guests, using the hypervisor cpuid leaves and msr ranges.

## AP startup ##

AP startup can be performed using hypercalls or the local APIC if present.
The following VCPU hypercalls can be used in order to bring up secondary vCPUs:

 * `VCPUOP_initialise` is used to set the initial state of the vCPU. The
   argument passed to the hypercall must be of the type vcpu_hvm_context.
   See `public/hvm/hvm_vcpu.h` for the layout of the structure. Note that
   this hypercall allows starting the vCPU in several modes (16/32/64bits),
   regardless of the mode the BSP is currently running on.

 * `VCPUOP_up` is used to launch the vCPU once the initial state has been
   set using `VCPUOP_initialise`.

 * `VCPUOP_down` is used to bring down a vCPU.

 * `VCPUOP_is_up` is used to scan the number of available vCPUs.

## Hardware description ##

PVHv2 guests that have access to hardware (either emulated or real) will also
have ACPI tables with the description of the hardware that's available to the
guest. This applies to both privileged and unprivileged guests. A pointer to
the position of the RSDP in memory (if present) can be fetched from the start
info structure that's passed at boot time (field rsdp_paddr).

Description of paravirtualized devices will come from XenStore, just as it's
done for HVM guests.
