# PVH Specification #

## Rationale ##

PVH is a new kind of guest that has been introduced on Xen 4.4 as a DomU, and
on Xen 4.5 as a Dom0. The aim of PVH is to make use of the hardware
virtualization extensions present in modern x86 CPUs in order to
improve performance.

PVH is considered a mix between PV and HVM, and can be seen as a PV guest
that runs inside of an HVM container, or as a PVHVM guest without any emulated
devices. The design goal of PVH is to provide the best performance possible and
to reduce the amount of modifications needed for a guest OS to run in this mode
(compared to pure PV).

This document tries to describe the interfaces used by PVH guests, focusing
on how an OS should make use of them in order to support PVH.

## Early boot ##

PVH guests use the PV boot mechanism, that means that the kernel is loaded and
directly launched by Xen (by jumping into the entry point). In order to do this
Xen ELF Notes need to be added to the guest kernel, so that they contain the
information needed by Xen. Here is an example of the ELF Notes added to the
FreeBSD amd64 kernel in order to boot as PVH:

    ELFNOTE(Xen, XEN_ELFNOTE_GUEST_OS,       .asciz, "FreeBSD")
    ELFNOTE(Xen, XEN_ELFNOTE_GUEST_VERSION,  .asciz, __XSTRING(__FreeBSD_version))
    ELFNOTE(Xen, XEN_ELFNOTE_XEN_VERSION,    .asciz, "xen-3.0")
    ELFNOTE(Xen, XEN_ELFNOTE_VIRT_BASE,      .quad,  KERNBASE)
    ELFNOTE(Xen, XEN_ELFNOTE_PADDR_OFFSET,   .quad,  KERNBASE)
    ELFNOTE(Xen, XEN_ELFNOTE_ENTRY,          .quad,  xen_start)
    ELFNOTE(Xen, XEN_ELFNOTE_HYPERCALL_PAGE, .quad,  hypercall_page)
    ELFNOTE(Xen, XEN_ELFNOTE_HV_START_LOW,   .quad,  HYPERVISOR_VIRT_START)
    ELFNOTE(Xen, XEN_ELFNOTE_FEATURES,       .asciz, "writable_descriptor_tables|auto_translated_physmap|supervisor_mode_kernel|hvm_callback_vector")
    ELFNOTE(Xen, XEN_ELFNOTE_PAE_MODE,       .asciz, "yes")
    ELFNOTE(Xen, XEN_ELFNOTE_L1_MFN_VALID,   .long,  PG_V, PG_V)
    ELFNOTE(Xen, XEN_ELFNOTE_LOADER,         .asciz, "generic")
    ELFNOTE(Xen, XEN_ELFNOTE_SUSPEND_CANCEL, .long,  0)
    ELFNOTE(Xen, XEN_ELFNOTE_BSD_SYMTAB,     .asciz, "yes")

On the Linux side, the above can be found in `arch/x86/xen/xen-head.S`.

It is important to highlight the following notes:

  * `XEN_ELFNOTE_ENTRY`: contains the virtual memory address of the kernel entry
    point.
  * `XEN_ELFNOTE_HYPERCALL_PAGE`: contains the virtual memory address of the
    hypercal page inside of the guest kernel (this memory region will be filled
    by Xen prior to booting).
  * `XEN_ELFNOTE_FEATURES`: contains the list of features supported by the kernel.
    In the example above the kernel is only able to boot as a PVH guest, but
    those options can be mixed with the ones used by pure PV guests in order to
    have a kernel that supports both PV and PVH (like Linux). The list of
    options available can be found in the `features.h` public header. Note that
    in the example above `hvm_callback_vector` is in `XEN_ELFNOTE_FEATURES`.
    Older hypervisors will balk at this being part of it, so it can also be put
    in `XEN_ELFNOTE_SUPPORTED_FEATURES` which older hypervisors will ignore.

Xen will jump into the kernel entry point defined in `XEN_ELFNOTE_ENTRY` with
paging enabled (either long mode or protected mode with paging turned on
depending on the kernel bitness) and some basic page tables setup. An important
distinction for a 64bit PVH is that it is launched at privilege level 0 as
opposed to a 64bit PV guest which is launched at privilege level 3.

Also, the `rsi` (`esi` on 32bits) register is going to contain the virtual
memory address where Xen has placed the `start_info` structure. The `rsp` (`esp`
on 32bits) will point to the top of an initial single page stack, that can be
used by the guest kernel. The `start_info` structure contains all the info the
guest needs in order to initialize. More information about the contents can be
found in the `xen.h` public header.

### Initial amd64 control registers values ###

Initial values for the control registers are set up by Xen before booting the
guest kernel. The guest kernel can expect to find the following features
enabled by Xen.

`CR0` has the following bits set by Xen:

  * PE (bit 0): protected mode enable.
  * ET (bit 4): 387 or newer processor.
  * PG (bit 31): paging enabled.

`CR4` has the following bits set by Xen:

  * PAE (bit 5): PAE enabled.

And finally in `EFER` the following features are enabled:

  * LME (bit 8): Long mode enable.
  * LMA (bit 10): Long mode active.

At least the following flags in `EFER` are guaranteed to be disabled:

  * SCE (bit 0): System call extensions disabled.
  * NXE (bit 11): No-Execute disabled.

There's no guarantee about the state of the other bits in the `EFER` register.

All the segments selectors are set with a flat base at zero.

The `cs` segment selector attributes are set to 0x0a09b, which describes an
executable and readable code segment only accessible by the most privileged
level. The segment is also set as a 64-bit code segment (`L` flag set, `D` flag
unset).

The remaining segment selectors (`ds`, `ss`, `es`, `fs` and `gs`) are all set
to the same values. The attributes are set to 0x0c093, which implies a read and
write data segment only accessible by the most privileged level.

The `FS.base`, `GS.base` and `KERNEL_GS.base` MSRs are zeroed out.

The `IDT` and `GDT` are also zeroed, so the guest must be specially careful to
not trigger a fault until after they have been properly set. The way of setting
the IDT and the GDT is using the native instructions as would be done on bare
metal.

The `RFLAGS` register is guaranteed to be clear when jumping into the kernel
entry point, with the exception of the reserved bit 1 set.

## Memory ##

Since PVH guests rely on virtualization extensions provided by the CPU, they
have access to a hardware virtualized MMU, which means page-table related
operations should use the same instructions used on native.

There are however some differences with native. The usage of native MTRR
operations is forbidden, and `XENPF_*_memtype` hypercalls should be used
instead. This can be avoided by simply not using MTRR and setting all the
memory attributes using PAT, which doesn't require the usage of any hypercalls.

Since PVH doesn't use a BIOS in order to boot, the physical memory map has
to be retrieved using the `XENMEM_memory_map` hypercall, which will return
an e820 map. This memory map might contain holes that describe MMIO regions,
that will be already setup by Xen.

*TODO*: we need to figure out what to do with MMIO regions, right now Xen
sets all the holes in the native e820 to MMIO regions for Dom0 up to 4GB. We
need to decide what to do with MMIO regions above 4GB on Dom0, and what to do
for PVH DomUs with pci-passthrough.

In the case of a guest started with memory != maxmem, the e820 memory map
returned by Xen will contain the memory up to maxmem. The guest has to be very
careful to only use the lower memory pages up to the value contained in
`start_info->nr_pages` because any memory page above that value will not be
populated.

## Physical devices ##

When running as Dom0 the guest OS has the ability to interact with the physical
devices present in the system. A note should be made that PVH guests require
a working IOMMU in order to interact with physical devices.

The first step in order to manipulate the devices is to make Xen aware of
them. Due to the fact that all the hardware description on x86 comes from
ACPI, Dom0 is responsible for parsing the ACPI tables and notifying Xen about
the devices it finds. This is done with the `PHYSDEVOP_pci_device_add`
hypercall.

*TODO*: explain the way to register the different kinds of PCI devices, like
devices with virtual functions.

## Interrupts ##

All interrupts on PVH guests are routed over event channels, see
[Event Channel Internals][event_channels] for more detailed information about
event channels. In order to inject interrupts into the guest an IDT vector is
used. This is the same mechanism used on PVHVM guests, and allows having
per-cpu interrupts that can be used to deliver timers or IPIs.

In order to register the callback IDT vector the `HVMOP_set_param` hypercall
is used with the following values:

    domid = DOMID_SELF
    index = HVM_PARAM_CALLBACK_IRQ
    value = (0x2 << 56) | vector_value

The OS has to program the IDT for the `vector_value` using the baremetal
mechanism.

In order to know which event channel has fired, we need to look into the
information provided in the `shared_info` structure. The `evtchn_pending`
array is used as a bitmap in order to find out which event channel has
fired. Event channels can also be masked by setting it's port value in the
`shared_info->evtchn_mask` bitmap.

### Interrupts from physical devices ###

When running as Dom0 (or when using pci-passthrough) interrupts from physical
devices are routed over event channels. There are 3 different kind of
physical interrupts that can be routed over event channels by Xen: IO APIC,
MSI and MSI-X interrupts.

Since physical interrupts usually need EOI (End Of Interrupt), Xen allows the
registration of a memory region that will contain whether a physical interrupt
needs EOI from the guest or not. This is done with the
`PHYSDEVOP_pirq_eoi_gmfn_v2` hypercall that takes a parameter containing the
physical address of the memory page that will act as a bitmap. Then in order to
find out if an IRQ needs EOI or not, the OS can perform a simple bit test on the
memory page using the PIRQ value.

### IO APIC interrupt routing ###

IO APIC interrupts can be routed over event channels using `PHYSDEVOP`
hypercalls. First the IRQ is registered using the `PHYSDEVOP_map_pirq`
hypercall, as an example IRQ#9 is used here:

    domid = DOMID_SELF
    type = MAP_PIRQ_TYPE_GSI
    index = 9
    pirq = 9

The IRQ#9 is now registered as PIRQ#9. The triggering and polarity can also
be configured using the `PHYSDEVOP_setup_gsi` hypercall:

    gsi = 9 # This is the IRQ value.
    triggering = 0
    polarity = 0

In this example the IRQ would be configured to use edge triggering and high
polarity.

Finally the PIRQ can be bound to an event channel using the
`EVTCHNOP_bind_pirq`, that will return the event channel port the PIRQ has been
assigned. After this the event channel will be ready for delivery.

*NOTE*: when running as Dom0, the guest has to parse the interrupt overrides
found on the ACPI tables and notify Xen about them.

### MSI ###

In order to configure MSI interrupts for a device, Xen must be made aware of
it's presence first by using the `PHYSDEVOP_pci_device_add` as described above.
Then the `PHYSDEVOP_map_pirq` hypercall is used:

    domid = DOMID_SELF
    type = MAP_PIRQ_TYPE_MSI_SEG or MAP_PIRQ_TYPE_MULTI_MSI
    index = -1
    pirq = -1
    bus = pci_device_bus
    devfn = pci_device_function
    entry_nr = number of MSI interrupts

The type has to be set to `MAP_PIRQ_TYPE_MSI_SEG` if only one MSI interrupt
source is being configured. On devices that support MSI interrupt groups
`MAP_PIRQ_TYPE_MULTI_MSI` can be used to configure them by also placing the
number of MSI interrupts in the `entry_nr` field.

The values in the `bus` and `devfn` field should be the same as the ones used
when registering the device with `PHYSDEVOP_pci_device_add`.

### MSI-X ###

*TODO*: how to register/use them.

## Event timers and timecounters ##

Since some hardware is not available on PVH (like the local APIC), Xen provides
the OS with suitable replacements in order to get the same functionality. One
of them is the timer interface. Using a set of hypercalls, a guest OS can set
event timers that will deliver and event channel interrupt to the guest.

In order to use the timer provided by Xen the guest OS first needs to register
a VIRQ event channel to be used by the timer to deliver the interrupts. The
event channel is registered using the `EVTCHNOP_bind_virq` hypercall, that
only takes two parameters:

    virq = VIRQ_TIMER
    vcpu = vcpu_id

The port that's going to be used by Xen in order to deliver the interrupt is
returned in the `port` field. Once the interrupt is set, the timer can be
programmed using the `VCPUOP_set_singleshot_timer` hypercall.

    flags = VCPU_SSHOTTMR_future
    timeout_abs_ns = absolute value when the timer should fire

It is important to notice that the `VCPUOP_set_singleshot_timer` hypercall must
be executed from the same vCPU where the timer should fire, or else Xen will
refuse to set it. This is a single-shot timer, so it must be set by the OS
every time it fires if a periodic timer is desired.

Xen also shares a memory region with the guest OS that contains time related
values that are updated periodically. This values can be used to implement a
timecounter or to obtain the current time. This information is placed inside of
`shared_info->vcpu_info[vcpu_id].time`. The uptime (time since the guest has
been launched) can be calculated using the following expression and the values
stored in the `vcpu_time_info` struct:

    system_time + ((((tsc - tsc_timestamp) << tsc_shift) * tsc_to_system_mul) >> 32)

The timeout that is passed to `VCPUOP_set_singleshot_timer` has to be
calculated using the above value, plus the timeout the system wants to set.

If the OS also wants to obtain the current wallclock time, the value calculated
above has to be added to the values found in `shared_info->wc_sec` and
`shared_info->wc_nsec`.

## SMP discover and bring up ##

The process of bringing up secondary CPUs is obviously different from native,
since PVH doesn't have a local APIC. The first thing to do is to figure out
how many vCPUs the guest has. This is done using the `VCPUOP_is_up` hypercall,
using for example this simple loop:

    for (i = 0; i < MAXCPU; i++) {
        ret = HYPERVISOR_vcpu_op(VCPUOP_is_up, i, NULL);
        if (ret >= 0)
            /* vCPU#i is present */
    }

Note than when running as Dom0, the ACPI tables might report a different number
of available CPUs. This is because the value on the ACPI tables is the
number of physical CPUs the host has, and it might bear no resemblance with the
number of vCPUs Dom0 actually has so it should be ignored.

In order to bring up the secondary vCPUs they must be configured first. This is
achieved using the `VCPUOP_initialise` hypercall. A valid context has to be
passed to the vCPU in order to boot. The relevant fields for PVH guests are
the following:

  * `flags`: contains `VGCF_*` flags (see `arch-x86/xen.h` public header).
  * `user_regs`: struct that contains the register values that will be set on
    the vCPU before booting. All GPRs are available to be set, however, the
    most relevant ones are `rip` and `rsp` in order to set the start address
    and the stack. Please note, all selectors must be null.
  * `ctrlreg[3]`: contains the address of the page tables that will be used by
    the vCPU. Other control registers should be set to zero, or else the
    hypercall will fail with -EINVAL.

After the vCPU is initialized with the proper values, it can be started by
using the `VCPUOP_up` hypercall. The values of the other control registers of
the vCPU will be the same as the ones described in the `control registers`
section.

Examples about how to bring up secondary CPUs can be found on the FreeBSD
code base in `sys/x86/xen/pv.c` and on Linux `arch/x86/xen/smp.c`.

## Control operations (reboot/shutdown) ##

Reboot and shutdown operations on PVH guests are performed using hypercalls.
In order to issue a reboot, a guest must use the `SHUTDOWN_reboot` hypercall.
In order to perform a power off from a guest DomU, the `SHUTDOWN_poweroff`
hypercall should be used.

The way to perform a full system power off from Dom0 is different than what's
done in a DomU guest. In order to perform a power off from Dom0 the native
ACPI path should be followed, but the guest should not write the `SLP_EN`
bit to the Pm1Control register. Instead the `XENPF_enter_acpi_sleep` hypercall
should be used, filling the following data in the `xen_platform_op` struct:

    cmd = XENPF_enter_acpi_sleep
    interface_version = XENPF_INTERFACE_VERSION
    u.enter_acpi_sleep.pm1a_cnt_val = Pm1aControlValue
    u.enter_acpi_sleep.pm1b_cnt_val = Pm1bControlValue

This will allow Xen to do it's clean up and to power off the system. If the
host is using hardware reduced ACPI, the following field should also be set:

    u.enter_acpi_sleep.flags = XENPF_ACPI_SLEEP_EXTENDED (0x1)

## CPUID ##

The cpuid instruction that should be used is the normal `cpuid`, not the
emulated `cpuid` that PV guests usually require.

*TDOD*: describe which cpuid flags a guest should ignore and also which flags
describe features can be used. It would also be good to describe the set of
cpuid flags that will always be present when running as PVH.

## Final notes ##

All the other hardware functionality not described in this document should be
assumed to be performed in the same way as native.

[event_channels]: http://wiki.xen.org/wiki/Event_Channel_Internals
