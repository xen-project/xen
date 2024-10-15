/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/bug.h>
#include <xen/bootfdt.h>
#include <xen/compile.h>
#include <xen/device_tree.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/shutdown.h>

#include <public/version.h>

#include <asm/early_printk.h>
#include <asm/sbi.h>
#include <asm/smp.h>
#include <asm/traps.h>

void arch_get_xen_caps(xen_capabilities_info_t *info)
{
    BUG_ON("unimplemented");
}

/* Xen stack for bringing up the first CPU. */
unsigned char __initdata cpu0_boot_stack[STACK_SIZE]
    __aligned(STACK_SIZE);

void __init noreturn start_xen(unsigned long bootcpu_id,
                               paddr_t dtb_addr)
{
    const char *cmdline;

    remove_identity_mapping();

    set_processor_id(0);

    set_cpuid_to_hartid(0, bootcpu_id);

    trap_init();

    sbi_init();

    setup_fixmap_mappings();

    device_tree_flattened = early_fdt_map(dtb_addr);
    if ( !device_tree_flattened )
        panic("Invalid device tree blob at physical address %#lx. The DTB must be 8-byte aligned and must not exceed %lld bytes in size.\n\n"
              "Please check your bootloader.\n",
              dtb_addr, BOOT_FDT_VIRT_SIZE);

    /* Register Xen's load address as a boot module. */
    if ( !add_boot_module(BOOTMOD_XEN, virt_to_maddr(_start),
                          _end - _start, false) )
        panic("Failed to add BOOTMOD_XEN\n");

    if ( !boot_fdt_info(device_tree_flattened, dtb_addr) )
        BUG();

    cmdline = boot_fdt_cmdline(device_tree_flattened);
    printk("Command line: %s\n", cmdline);
    cmdline_parse(cmdline);

    printk("All set up\n");

    machine_halt();
}
