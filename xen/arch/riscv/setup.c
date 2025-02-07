/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/acpi.h>
#include <xen/bug.h>
#include <xen/bootfdt.h>
#include <xen/compile.h>
#include <xen/device_tree.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/shutdown.h>
#include <xen/vmap.h>
#include <xen/xvmalloc.h>

#include <public/version.h>

#include <asm/early_printk.h>
#include <asm/fixmap.h>
#include <asm/sbi.h>
#include <asm/setup.h>
#include <asm/smp.h>
#include <asm/traps.h>

/* Xen stack for bringing up the first CPU. */
unsigned char __initdata cpu0_boot_stack[STACK_SIZE]
    __aligned(STACK_SIZE);

/**
 * copy_from_paddr - copy data from a physical address
 * @dst: destination virtual address
 * @paddr: source physical address
 * @len: length to copy
 */
void __init copy_from_paddr(void *dst, paddr_t paddr, unsigned long len)
{
    const void *src = (void *)FIXMAP_ADDR(FIX_MISC);

    while ( len )
    {
        unsigned long s = paddr & (PAGE_SIZE - 1);
        unsigned long l = min(PAGE_SIZE - s, len);

        set_fixmap(FIX_MISC, maddr_to_mfn(paddr), PAGE_HYPERVISOR_RW);
        memcpy(dst, src + s, l);
        clear_fixmap(FIX_MISC);

        paddr += l;
        dst += l;
        len -= l;
    }
}

/* Relocate the FDT in Xen heap */
static void * __init relocate_fdt(paddr_t dtb_paddr, size_t dtb_size)
{
    void *fdt = xvmalloc_array(uint8_t, dtb_size);

    if ( !fdt )
        panic("Unable to allocate memory for relocating the Device-Tree.\n");

    copy_from_paddr(fdt, dtb_paddr, dtb_size);

    return fdt;
}

void __init noreturn start_xen(unsigned long bootcpu_id,
                               paddr_t dtb_addr)
{
    const char *cmdline;
    size_t fdt_size;

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

    fdt_size = boot_fdt_info(device_tree_flattened, dtb_addr);

    cmdline = boot_fdt_cmdline(device_tree_flattened);
    printk("Command line: %s\n", cmdline);
    cmdline_parse(cmdline);

    setup_mm();

    vm_init();

    end_boot_allocator();

    /*
     * The memory subsystem has been initialized, we can now switch from
     * early_boot -> boot.
     */
    system_state = SYS_STATE_boot;

    init_constructors();

    if ( acpi_disabled )
    {
        printk("Booting using Device Tree\n");
        device_tree_flattened = relocate_fdt(dtb_addr, fdt_size);
        dt_unflatten_host_device_tree();
    }
    else
    {
        device_tree_flattened = NULL;
        panic("Booting using ACPI isn't supported\n");
    }

    printk("All set up\n");

    machine_halt();
}
