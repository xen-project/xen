/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Derived from Xen 4.19's $xen/arch/arm/setup.c.
 *
 * bookkeeping routines.
 *
 * Tim Deegan <tim@xen.org>
 * Copyright (c) 2011 Citrix Systems.
 * Copyright (c) 2024 Raptor Engineering LLC
 */

#include <xen/acpi.h>
#include <xen/bootfdt.h>
#include <xen/bug.h>
#include <xen/device_tree.h>
#include <xen/init.h>
#include <xen/libfdt/libfdt-xen.h>
#include <xen/mm.h>

#include <asm/setup.h>

struct bootinfo __initdata bootinfo = BOOTINFO_INIT;

const char * __init boot_module_kind_as_string(bootmodule_kind kind)
{
    switch ( kind )
    {
    case BOOTMOD_XEN:     return "Xen";
    case BOOTMOD_FDT:     return "Device Tree";
    case BOOTMOD_KERNEL:  return "Kernel";
    case BOOTMOD_RAMDISK: return "Ramdisk";
    case BOOTMOD_XSM:     return "XSM";
    case BOOTMOD_GUEST_DTB:     return "DTB";
    case BOOTMOD_UNKNOWN: return "Unknown";
    default: BUG();
    }
}

static void __init dt_unreserved_regions(paddr_t s, paddr_t e,
                                         void (*cb)(paddr_t ps, paddr_t pe),
                                         unsigned int first)
{
    const struct membanks *reserved_mem = bootinfo_get_reserved_mem();
#ifdef CONFIG_STATIC_SHM
    const struct membanks *shmem = bootinfo_get_shmem();
    unsigned int offset;
#endif
    unsigned int i;

    /*
     * i is the current bootmodule we are evaluating across all possible
     * kinds.
     */
    for ( i = first; i < reserved_mem->nr_banks; i++ )
    {
        paddr_t r_s = reserved_mem->bank[i].start;
        paddr_t r_e = r_s + reserved_mem->bank[i].size;

        if ( s < r_e && r_s < e )
        {
            dt_unreserved_regions(r_e, e, cb, i + 1);
            dt_unreserved_regions(s, r_s, cb, i + 1);
            return;
        }
    }

#ifdef CONFIG_STATIC_SHM
    /*
     * When retrieving the corresponding shared memory addresses
     * below, we need to index the shmem->bank starting from 0, hence
     * we need to use i - reserved_mem->nr_banks.
    */
    offset = reserved_mem->nr_banks;
    for ( ; i - offset < shmem->nr_banks; i++ )
    {
        paddr_t r_s, r_e;

        r_s = shmem->bank[i - offset].start;

        /* Shared memory banks can contain INVALID_PADDR as start */
        if ( INVALID_PADDR == r_s )
            continue;

        r_e = r_s + shmem->bank[i - offset].size;

        if ( s < r_e && r_s < e )
        {
            dt_unreserved_regions(r_e, e, cb, i + 1);
            dt_unreserved_regions(s, r_s, cb, i + 1);
            return;
        }
    }
#endif

    cb(s, e);
}

/*
 * TODO: '*_end' could be 0 if the bank/region is at the end of the physical
 * address space. This is for now not handled as it requires more rework.
 */
static bool __init meminfo_overlap_check(const struct membanks *mem,
                                         paddr_t region_start,
                                         paddr_t region_size,
                                         bool allow_memreserve_overlap)
{
    paddr_t bank_start = INVALID_PADDR, bank_end = 0;
    paddr_t region_end = region_start + region_size;
    unsigned int i, bank_num = mem->nr_banks;

    for ( i = 0; i < bank_num; i++ )
    {
        bank_start = mem->bank[i].start;
        bank_end = bank_start + mem->bank[i].size;

        if ( INVALID_PADDR == bank_start || region_end <= bank_start ||
             region_start >= bank_end )
            continue;

        /*
         * If allow_memreserve_overlap is set, this check allows a region to be
         * included in a MEMBANK_FDT_RESVMEM bank, but struct membanks *mem of
         * type STATIC_SHARED_MEMORY don't set the bank[].type field because
         * that is declared in a union with a field that is instead used,
         * in any case this restriction is ok since STATIC_SHARED_MEMORY banks
         * are not meant to clash with FDT /memreserve/ ranges.
         */
        if ( allow_memreserve_overlap && mem->type != STATIC_SHARED_MEMORY &&
             region_start >= bank_start && region_end <= bank_end &&
             mem->bank[i].type == MEMBANK_FDT_RESVMEM )
            continue;

        printk("Region: [%#"PRIpaddr", %#"PRIpaddr") overlapping with bank[%u]: [%#"PRIpaddr", %#"PRIpaddr")\n",
                region_start, region_end, i, bank_start, bank_end);
        return true;
    }

    return false;
}

/*
 * TODO: '*_end' could be 0 if the module/region is at the end of the physical
 * address space. This is for now not handled as it requires more rework.
 */
static bool __init bootmodules_overlap_check(struct bootmodules *bootmodules,
                                             paddr_t region_start,
                                             paddr_t region_size)
{
    paddr_t mod_start = INVALID_PADDR, mod_end = 0;
    paddr_t region_end = region_start + region_size;
    unsigned int i, mod_num = bootmodules->nr_mods;

    for ( i = 0; i < mod_num; i++ )
    {
        mod_start = bootmodules->module[i].start;
        mod_end = mod_start + bootmodules->module[i].size;

        if ( region_end <= mod_start || region_start >= mod_end )
            continue;
        else
        {
            printk("Region: [%#"PRIpaddr", %#"PRIpaddr") overlapping with mod[%u]: [%#"PRIpaddr", %#"PRIpaddr")\n",
                   region_start, region_end, i, mod_start, mod_end);
            return true;
        }
    }

    return false;
}

void __init fw_unreserved_regions(paddr_t s, paddr_t e,
                                  void (*cb)(paddr_t ps, paddr_t pe),
                                  unsigned int first)
{
    if ( acpi_disabled )
        dt_unreserved_regions(s, e, cb, first);
    else
        cb(s, e);
}

/*
 * Given an input physical address range, check if this range is overlapping
 * with the existing reserved memory regions defined in bootinfo.
 * Return true if the input physical address range is overlapping with any
 * existing reserved memory regions, otherwise false.
 */
bool __init check_reserved_regions_overlap(paddr_t region_start,
                                           paddr_t region_size,
                                           bool allow_memreserve_overlap)
{
    const struct membanks *mem_banks[] = {
        bootinfo_get_reserved_mem(),
#ifdef CONFIG_ACPI
        bootinfo_get_acpi(),
#endif
#ifdef CONFIG_STATIC_SHM
        bootinfo_get_shmem(),
#endif
    };
    unsigned int i;

    /*
     * Check if input region is overlapping with reserved memory banks or
     * ACPI EfiACPIReclaimMemory (when ACPI feature is enabled) or static
     * shared memory banks (when static shared memory feature is enabled)
     */
    for ( i = 0; i < ARRAY_SIZE(mem_banks); i++ )
        if ( meminfo_overlap_check(mem_banks[i], region_start, region_size,
                                   allow_memreserve_overlap) )
            return true;

    /* Check if input region is overlapping with bootmodules */
    if ( bootmodules_overlap_check(&bootinfo.modules,
                                   region_start, region_size) )
        return true;

    return false;
}

struct bootmodule __init *add_boot_module(bootmodule_kind kind,
                                          paddr_t start, paddr_t size,
                                          bool domU)
{
    struct bootmodules *mods = &bootinfo.modules;
    struct bootmodule *mod;
    unsigned int i;

    if ( mods->nr_mods == MAX_MODULES )
    {
        printk("Ignoring %s boot module at %"PRIpaddr"-%"PRIpaddr" (too many)\n",
               boot_module_kind_as_string(kind), start, start + size);
        return NULL;
    }

    /*
     * u-boot adds boot module such as ramdisk to the /memreserve/, since these
     * ranges are saved in reserved_mem at this stage, allow an eventual exact
     * match with MEMBANK_FDT_RESVMEM banks.
     */
    if ( check_reserved_regions_overlap(start, size, true) )
        return NULL;

    for ( i = 0 ; i < mods->nr_mods ; i++ )
    {
        mod = &mods->module[i];
        if ( mod->kind == kind && mod->start == start )
        {
            if ( !domU )
                mod->domU = false;
            return mod;
        }
    }

    mod = &mods->module[mods->nr_mods++];
    mod->kind = kind;
    mod->start = start;
    mod->size = size;
    mod->domU = domU;

    return mod;
}

/*
 * boot_module_find_by_kind can only be used to return Xen modules (e.g
 * XSM, DTB) or Dom0 modules. This is not suitable for looking up guest
 * modules.
 */
struct bootmodule * __init boot_module_find_by_kind(bootmodule_kind kind)
{
    struct bootmodules *mods = &bootinfo.modules;
    struct bootmodule *mod;
    int i;
    for (i = 0 ; i < mods->nr_mods ; i++ )
    {
        mod = &mods->module[i];
        if ( mod->kind == kind && !mod->domU )
            return mod;
    }
    return NULL;
}

void __init add_boot_cmdline(const char *name, const char *cmdline,
                             bootmodule_kind kind, paddr_t start, bool domU)
{
    struct bootcmdlines *cmds = &bootinfo.cmdlines;
    struct bootcmdline *cmd;

    if ( cmds->nr_mods == MAX_MODULES )
    {
        printk("Ignoring %s cmdline (too many)\n", name);
        return;
    }

    cmd = &cmds->cmdline[cmds->nr_mods++];
    cmd->kind = kind;
    cmd->domU = domU;
    cmd->start = start;

    ASSERT(strlen(name) <= DT_MAX_NAME);
    safe_strcpy(cmd->dt_name, name);

    if ( strlen(cmdline) > BOOTMOD_MAX_CMDLINE )
        panic("module %s command line too long\n", name);
    safe_strcpy(cmd->cmdline, cmdline);
}

/*
 * boot_cmdline_find_by_kind can only be used to return Xen modules (e.g
 * XSM, DTB) or Dom0 modules. This is not suitable for looking up guest
 * modules.
 */
struct bootcmdline * __init boot_cmdline_find_by_kind(bootmodule_kind kind)
{
    struct bootcmdlines *cmds = &bootinfo.cmdlines;
    struct bootcmdline *cmd;
    int i;

    for ( i = 0 ; i < cmds->nr_mods ; i++ )
    {
        cmd = &cmds->cmdline[i];
        if ( cmd->kind == kind && !cmd->domU )
            return cmd;
    }
    return NULL;
}

struct bootcmdline * __init boot_cmdline_find_by_name(const char *name)
{
    struct bootcmdlines *mods = &bootinfo.cmdlines;
    struct bootcmdline *mod;
    unsigned int i;

    for (i = 0 ; i < mods->nr_mods ; i++ )
    {
        mod = &mods->cmdline[i];
        if ( strcmp(mod->dt_name, name) == 0 )
            return mod;
    }
    return NULL;
}

struct bootmodule * __init boot_module_find_by_addr_and_kind(bootmodule_kind kind,
                                                             paddr_t start)
{
    struct bootmodules *mods = &bootinfo.modules;
    struct bootmodule *mod;
    unsigned int i;

    for (i = 0 ; i < mods->nr_mods ; i++ )
    {
        mod = &mods->module[i];
        if ( mod->kind == kind && mod->start == start )
            return mod;
    }
    return NULL;
}

/*
 * Return the end of the non-module region starting at s. In other
 * words return s the start of the next modules after s.
 *
 * On input *end is the end of the region which should be considered
 * and it is updated to reflect the end of the module, clipped to the
 * end of the region if it would run over.
 */
static paddr_t __init next_module(paddr_t s, paddr_t *end)
{
    struct bootmodules *mi = &bootinfo.modules;
    paddr_t lowest = ~(paddr_t)0;
    int i;

    for ( i = 0; i < mi->nr_mods; i++ )
    {
        paddr_t mod_s = mi->module[i].start;
        paddr_t mod_e = mod_s + mi->module[i].size;

        if ( !mi->module[i].size )
            continue;

        if ( mod_s < s )
            continue;
        if ( mod_s > lowest )
            continue;
        if ( mod_s > *end )
            continue;
        lowest = mod_s;
        *end = min(*end, mod_e);
    }
    return lowest;
}

/*
 * Populate the boot allocator.
 * If a static heap was not provided by the admin, all the RAM but the
 * following regions will be added:
 *  - Modules (e.g., Xen, Kernel)
 *  - Reserved regions
 *  - Xenheap (CONFIG_SEPARATE_XENHEAP only)
 * If a static heap was provided by the admin, populate the boot
 * allocator with the corresponding regions only, but with Xenheap excluded
 * on CONFIG_SEPARATE_XENHEAP.
 */
void __init populate_boot_allocator(void)
{
    unsigned int i;
    const struct membanks *banks = bootinfo_get_mem();
    const struct membanks *reserved_mem = bootinfo_get_reserved_mem();
    paddr_t s, e;

    if ( using_static_heap )
    {
        for ( i = 0 ; i < reserved_mem->nr_banks; i++ )
        {
            if ( reserved_mem->bank[i].type != MEMBANK_STATIC_HEAP )
                continue;

            s = reserved_mem->bank[i].start;
            e = s + reserved_mem->bank[i].size;
#ifdef CONFIG_SEPARATE_XENHEAP
            /* Avoid the xenheap, note that the xenheap cannot across a bank */
            if ( s <= mfn_to_maddr(directmap_mfn_start) &&
                 e >= mfn_to_maddr(directmap_mfn_end) )
            {
                init_boot_pages(s, mfn_to_maddr(directmap_mfn_start));
                init_boot_pages(mfn_to_maddr(directmap_mfn_end), e);
            }
            else
#endif
                init_boot_pages(s, e);
        }

        return;
    }

    for ( i = 0; i < banks->nr_banks; i++ )
    {
        const struct membank *bank = &banks->bank[i];
        paddr_t bank_end = bank->start + bank->size;

        s = bank->start;
        while ( s < bank_end )
        {
            paddr_t n = bank_end;

            e = next_module(s, &n);

            if ( e == ~(paddr_t)0 )
                e = n = bank_end;

            /*
             * Module in a RAM bank other than the one which we are
             * not dealing with here.
             */
            if ( e > bank_end )
                e = bank_end;

#ifdef CONFIG_SEPARATE_XENHEAP
            /* Avoid the xenheap */
            if ( s < mfn_to_maddr(directmap_mfn_end) &&
                 mfn_to_maddr(directmap_mfn_start) < e )
            {
                e = mfn_to_maddr(directmap_mfn_start);
                n = mfn_to_maddr(directmap_mfn_end);
            }
#endif

            fw_unreserved_regions(s, e, init_boot_pages, 0);
            s = n;
        }
    }
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
