
PVH : an x86 PV guest running in an HVM container.

See: http://blog.xen.org/index.php/2012/10/23/the-paravirtualization-spectrum-part-1-the-ends-of-the-spectrum/

At the moment HAP is required for PVH.

At present the only PVH guest is an x86 64bit PV linux. Patches are at:
   git://git.kernel.org/pub/scm/linux/kernel/git/konrad/xen.git

A PVH guest kernel must support following features, as defined for linux
in arch/x86/xen/xen-head.S:

   #define FEATURES_PVH "|writable_descriptor_tables" \
                        "|auto_translated_physmap"    \
                        "|supervisor_mode_kernel"     \
                        "|hvm_callback_vector"

In a nutshell:
* the guest uses auto translate:
 - p2m is managed by xen
 - pagetables are owned by the guest
 - mmu_update hypercall not available
* it uses event callback and not vlapic emulation,
* IDT is native, so set_trap_table hcall is also N/A for a PVH guest.

For a full list of hcalls supported for PVH, see pvh_hypercall64_table
in arch/x86/hvm/hvm.c in xen.  From the ABI prespective, it's mostly a
PV guest with auto translate, although it does use hvm_op for setting
callback vector, and has a special version of arch_set_guest_info for bringing
up secondary cpus.

The initial phase targets the booting of a 64bit UP/SMP linux guest in PVH
mode. This is done by adding: pvh=1 in the config file. xl, and not xm, is
supported. Phase I patches are broken into three parts:
   - xen changes for booting of 64bit PVH guest
   - tools changes for creating a PVH guest
   - boot of 64bit dom0 in PVH mode.

To boot 64bit dom0 in PVH mode, add dom0pvh to grub xen command line.

Following fixme's exist in the code:
  - arch/x86/time.c: support more tsc modes.

Following remain to be done for PVH:
   - Get rid of PVH mode, make it just HVM with some flags set
   - implement arch_get_info_guest() for pvh.
   - Investigate what else needs to be done for VMI support.
   - AMD port.
   - 32bit PVH guest support in both linux and xen. Xen changes are tagged
     "32bitfixme".
   - Add support for monitoring guest behavior. See hvm_memory_event* functions
     in hvm.c
   - vcpu hotplug support
   - Live migration of PVH guests.
   - Avail PVH dom0 of posted interrupts. (This will be a big win).


Note, any emails to me must be cc'd to xen devel mailing list. OTOH, please
cc me on PVH emails to the xen devel mailing list.

Mukesh Rathor
mukesh.rathor [at] oracle [dot] com
