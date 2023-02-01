/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * xen/arch/arm/setup.c
 *
 * Early bringup code for an ARMv7-A with virt extensions.
 *
 * Tim Deegan <tim@xen.org>
 * Copyright (c) 2011 Citrix Systems.
 */

#include <xen/compile.h>
#include <xen/device_tree.h>
#include <xen/domain_page.h>
#include <xen/grant_table.h>
#include <xen/types.h>
#include <xen/string.h>
#include <xen/serial.h>
#include <xen/sched.h>
#include <xen/console.h>
#include <xen/err.h>
#include <xen/init.h>
#include <xen/irq.h>
#include <xen/mm.h>
#include <xen/param.h>
#include <xen/softirq.h>
#include <xen/keyhandler.h>
#include <xen/cpu.h>
#include <xen/pfn.h>
#include <xen/virtual_region.h>
#include <xen/vmap.h>
#include <xen/trace.h>
#include <xen/libfdt/libfdt.h>
#include <xen/acpi.h>
#include <xen/warning.h>
#include <asm/alternative.h>
#include <asm/page.h>
#include <asm/current.h>
#include <asm/setup.h>
#include <asm/gic.h>
#include <asm/cpuerrata.h>
#include <asm/cpufeature.h>
#include <asm/platform.h>
#include <asm/procinfo.h>
#include <asm/setup.h>
#include <xsm/xsm.h>
#include <asm/acpi.h>

struct bootinfo __initdata bootinfo;

/*
 * Sanitized version of cpuinfo containing only features available on all
 * cores (only on arm64 as there is no sanitization support on arm32).
 */
struct cpuinfo_arm __read_mostly system_cpuinfo;

#ifdef CONFIG_ACPI
bool __read_mostly acpi_disabled;
#endif

#ifdef CONFIG_ARM_32
static unsigned long opt_xenheap_megabytes __initdata;
integer_param("xenheap_megabytes", opt_xenheap_megabytes);
#endif

domid_t __read_mostly max_init_domid;

static __used void init_done(void)
{
    int rc;

    /* Must be done past setting system_state. */
    unregister_init_virtual_region();

    free_init_memory();

    /*
     * We have finished booting. Mark the section .data.ro_after_init
     * read-only.
     */
    rc = modify_xen_mappings((unsigned long)&__ro_after_init_start,
                             (unsigned long)&__ro_after_init_end,
                             PAGE_HYPERVISOR_RO);
    if ( rc )
        panic("Unable to mark the .data.ro_after_init section read-only (rc = %d)\n",
              rc);

    startup_cpu_idle_loop();
}

static void __init init_idle_domain(void)
{
    scheduler_init();
    set_current(idle_vcpu[0]);
    /* TODO: setup_idle_pagetable(); */
}

static const char * __initdata processor_implementers[] = {
    ['A'] = "ARM Limited",
    ['B'] = "Broadcom Corporation",
    ['C'] = "Cavium Inc.",
    ['D'] = "Digital Equipment Corp",
    ['M'] = "Motorola, Freescale Semiconductor Inc.",
    ['P'] = "Applied Micro",
    ['Q'] = "Qualcomm Inc.",
    ['V'] = "Marvell Semiconductor Inc.",
    ['i'] = "Intel Corporation",
};

static void __init processor_id(void)
{
    const char *implementer = "Unknown";
    struct cpuinfo_arm *c = &system_cpuinfo;

    identify_cpu(c);
    current_cpu_data = *c;

    if ( c->midr.implementer < ARRAY_SIZE(processor_implementers) &&
         processor_implementers[c->midr.implementer] )
        implementer = processor_implementers[c->midr.implementer];

    if ( c->midr.architecture != 0xf )
        printk("Huh, cpu architecture %x, expected 0xf (defined by cpuid)\n",
               c->midr.architecture);

    printk("Processor: %"PRIregister": \"%s\", variant: 0x%x, part 0x%03x,"
           "rev 0x%x\n", c->midr.bits, implementer,
           c->midr.variant, c->midr.part_number, c->midr.revision);

#if defined(CONFIG_ARM_64)
    printk("64-bit Execution:\n");
    printk("  Processor Features: %016"PRIx64" %016"PRIx64"\n",
           system_cpuinfo.pfr64.bits[0], system_cpuinfo.pfr64.bits[1]);
    printk("    Exception Levels: EL3:%s EL2:%s EL1:%s EL0:%s\n",
           cpu_has_el3_32 ? "64+32" : cpu_has_el3_64 ? "64" : "No",
           cpu_has_el2_32 ? "64+32" : cpu_has_el2_64 ? "64" : "No",
           cpu_has_el1_32 ? "64+32" : cpu_has_el1_64 ? "64" : "No",
           cpu_has_el0_32 ? "64+32" : cpu_has_el0_64 ? "64" : "No");
    printk("    Extensions:%s%s%s\n",
           cpu_has_fp ? " FloatingPoint" : "",
           cpu_has_simd ? " AdvancedSIMD" : "",
           cpu_has_gicv3 ? " GICv3-SysReg" : "");

    /* Warn user if we find unknown floating-point features */
    if ( cpu_has_fp && (boot_cpu_feature64(fp) >= 2) )
        printk(XENLOG_WARNING "WARNING: Unknown Floating-point ID:%d, "
               "this may result in corruption on the platform\n",
               boot_cpu_feature64(fp));

    /* Warn user if we find unknown AdvancedSIMD features */
    if ( cpu_has_simd && (boot_cpu_feature64(simd) >= 2) )
        printk(XENLOG_WARNING "WARNING: Unknown AdvancedSIMD ID:%d, "
               "this may result in corruption on the platform\n",
               boot_cpu_feature64(simd));

    printk("  Debug Features: %016"PRIx64" %016"PRIx64"\n",
           system_cpuinfo.dbg64.bits[0], system_cpuinfo.dbg64.bits[1]);
    printk("  Auxiliary Features: %016"PRIx64" %016"PRIx64"\n",
           system_cpuinfo.aux64.bits[0], system_cpuinfo.aux64.bits[1]);
    printk("  Memory Model Features: %016"PRIx64" %016"PRIx64"\n",
           system_cpuinfo.mm64.bits[0], system_cpuinfo.mm64.bits[1]);
    printk("  ISA Features:  %016"PRIx64" %016"PRIx64"\n",
           system_cpuinfo.isa64.bits[0], system_cpuinfo.isa64.bits[1]);
#endif

    /*
     * On AArch64 these refer to the capabilities when running in
     * AArch32 mode.
     */
    if ( cpu_has_aarch32 )
    {
        printk("32-bit Execution:\n");
        printk("  Processor Features: %"PRIregister":%"PRIregister"\n",
               system_cpuinfo.pfr32.bits[0], system_cpuinfo.pfr32.bits[1]);
        printk("    Instruction Sets:%s%s%s%s%s%s\n",
               cpu_has_aarch32 ? " AArch32" : "",
               cpu_has_arm ? " A32" : "",
               cpu_has_thumb ? " Thumb" : "",
               cpu_has_thumb2 ? " Thumb-2" : "",
               cpu_has_thumbee ? " ThumbEE" : "",
               cpu_has_jazelle ? " Jazelle" : "");
        printk("    Extensions:%s%s\n",
               cpu_has_gentimer ? " GenericTimer" : "",
               cpu_has_security ? " Security" : "");

        printk("  Debug Features: %"PRIregister"\n",
               system_cpuinfo.dbg32.bits[0]);
        printk("  Auxiliary Features: %"PRIregister"\n",
               system_cpuinfo.aux32.bits[0]);
        printk("  Memory Model Features: %"PRIregister" %"PRIregister"\n"
               "                         %"PRIregister" %"PRIregister"\n",
               system_cpuinfo.mm32.bits[0], system_cpuinfo.mm32.bits[1],
               system_cpuinfo.mm32.bits[2], system_cpuinfo.mm32.bits[3]);
        printk("  ISA Features: %"PRIregister" %"PRIregister" %"PRIregister"\n"
               "                %"PRIregister" %"PRIregister" %"PRIregister"\n",
               system_cpuinfo.isa32.bits[0], system_cpuinfo.isa32.bits[1],
               system_cpuinfo.isa32.bits[2], system_cpuinfo.isa32.bits[3],
               system_cpuinfo.isa32.bits[4], system_cpuinfo.isa32.bits[5]);
    }
    else
    {
        printk("32-bit Execution: Unsupported\n");
    }

    processor_setup();
}

static void __init dt_unreserved_regions(paddr_t s, paddr_t e,
                                         void (*cb)(paddr_t, paddr_t),
                                         unsigned int first)
{
    unsigned int i, nr;
    int rc;

    rc = fdt_num_mem_rsv(device_tree_flattened);
    if ( rc < 0 )
        panic("Unable to retrieve the number of reserved regions (rc=%d)\n",
              rc);

    nr = rc;

    for ( i = first; i < nr ; i++ )
    {
        paddr_t r_s, r_e;

        if ( fdt_get_mem_rsv(device_tree_flattened, i, &r_s, &r_e ) < 0 )
            /* If we can't read it, pretend it doesn't exist... */
            continue;

        r_e += r_s; /* fdt_get_mem_rsv returns length */

        if ( s < r_e && r_s < e )
        {
            dt_unreserved_regions(r_e, e, cb, i+1);
            dt_unreserved_regions(s, r_s, cb, i+1);
            return;
        }
    }

    /*
     * i is the current bootmodule we are evaluating across all possible
     * kinds.
     *
     * When retrieving the corresponding reserved-memory addresses
     * below, we need to index the bootinfo.reserved_mem bank starting
     * from 0, and only counting the reserved-memory modules. Hence,
     * we need to use i - nr.
     */
    for ( ; i - nr < bootinfo.reserved_mem.nr_banks; i++ )
    {
        paddr_t r_s = bootinfo.reserved_mem.bank[i - nr].start;
        paddr_t r_e = r_s + bootinfo.reserved_mem.bank[i - nr].size;

        if ( s < r_e && r_s < e )
        {
            dt_unreserved_regions(r_e, e, cb, i + 1);
            dt_unreserved_regions(s, r_s, cb, i + 1);
            return;
        }
    }

    cb(s, e);
}

/*
 * TODO: '*_end' could be 0 if the bank/region is at the end of the physical
 * address space. This is for now not handled as it requires more rework.
 */
static bool __init meminfo_overlap_check(struct meminfo *meminfo,
                                         paddr_t region_start,
                                         paddr_t region_size)
{
    paddr_t bank_start = INVALID_PADDR, bank_end = 0;
    paddr_t region_end = region_start + region_size;
    unsigned int i, bank_num = meminfo->nr_banks;

    for ( i = 0; i < bank_num; i++ )
    {
        bank_start = meminfo->bank[i].start;
        bank_end = bank_start + meminfo->bank[i].size;

        if ( region_end <= bank_start || region_start >= bank_end )
            continue;
        else
        {
            printk("Region: [%#"PRIpaddr", %#"PRIpaddr") overlapping with bank[%u]: [%#"PRIpaddr", %#"PRIpaddr")\n",
                   region_start, region_end, i, bank_start, bank_end);
            return true;
        }
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
                                  void (*cb)(paddr_t, paddr_t),
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
                                           paddr_t region_size)
{
    /* Check if input region is overlapping with bootinfo.reserved_mem banks */
    if ( meminfo_overlap_check(&bootinfo.reserved_mem,
                               region_start, region_size) )
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

    if ( check_reserved_regions_overlap(start, size) )
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

void __init discard_initial_modules(void)
{
    struct bootmodules *mi = &bootinfo.modules;
    int i;

    for ( i = 0; i < mi->nr_mods; i++ )
    {
        paddr_t s = mi->module[i].start;
        paddr_t e = s + PAGE_ALIGN(mi->module[i].size);

        if ( mi->module[i].kind == BOOTMOD_XEN )
            continue;

        if ( !mfn_valid(maddr_to_mfn(s)) ||
             !mfn_valid(maddr_to_mfn(e)) )
            continue;

        fw_unreserved_regions(s, e, init_domheap_pages, 0);
    }

    mi->nr_mods = 0;

    remove_early_mappings();
}

/* Relocate the FDT in Xen heap */
static void * __init relocate_fdt(paddr_t dtb_paddr, size_t dtb_size)
{
    void *fdt = xmalloc_bytes(dtb_size);

    if ( !fdt )
        panic("Unable to allocate memory for relocating the Device-Tree.\n");

    copy_from_paddr(fdt, dtb_paddr, dtb_size);

    return fdt;
}

#ifdef CONFIG_ARM_32
/*
 * Returns the end address of the highest region in the range s..e
 * with required size and alignment that does not conflict with the
 * modules from first_mod to nr_modules.
 *
 * For non-recursive callers first_mod should normally be 0 (all
 * modules and Xen itself) or 1 (all modules but not Xen).
 */
static paddr_t __init consider_modules(paddr_t s, paddr_t e,
                                       uint32_t size, paddr_t align,
                                       int first_mod)
{
    const struct bootmodules *mi = &bootinfo.modules;
    int i;
    int nr;

    s = (s+align-1) & ~(align-1);
    e = e & ~(align-1);

    if ( s > e ||  e - s < size )
        return 0;

    /* First check the boot modules */
    for ( i = first_mod; i < mi->nr_mods; i++ )
    {
        paddr_t mod_s = mi->module[i].start;
        paddr_t mod_e = mod_s + mi->module[i].size;

        if ( s < mod_e && mod_s < e )
        {
            mod_e = consider_modules(mod_e, e, size, align, i+1);
            if ( mod_e )
                return mod_e;

            return consider_modules(s, mod_s, size, align, i+1);
        }
    }

    /* Now check any fdt reserved areas. */

    nr = fdt_num_mem_rsv(device_tree_flattened);

    for ( ; i < mi->nr_mods + nr; i++ )
    {
        paddr_t mod_s, mod_e;

        if ( fdt_get_mem_rsv(device_tree_flattened,
                             i - mi->nr_mods,
                             &mod_s, &mod_e ) < 0 )
            /* If we can't read it, pretend it doesn't exist... */
            continue;

        /* fdt_get_mem_rsv returns length */
        mod_e += mod_s;

        if ( s < mod_e && mod_s < e )
        {
            mod_e = consider_modules(mod_e, e, size, align, i+1);
            if ( mod_e )
                return mod_e;

            return consider_modules(s, mod_s, size, align, i+1);
        }
    }

    /*
     * i is the current bootmodule we are evaluating, across all
     * possible kinds of bootmodules.
     *
     * When retrieving the corresponding reserved-memory addresses, we
     * need to index the bootinfo.reserved_mem bank starting from 0, and
     * only counting the reserved-memory modules. Hence, we need to use
     * i - nr.
     */
    nr += mi->nr_mods;
    for ( ; i - nr < bootinfo.reserved_mem.nr_banks; i++ )
    {
        paddr_t r_s = bootinfo.reserved_mem.bank[i - nr].start;
        paddr_t r_e = r_s + bootinfo.reserved_mem.bank[i - nr].size;

        if ( s < r_e && r_s < e )
        {
            r_e = consider_modules(r_e, e, size, align, i + 1);
            if ( r_e )
                return r_e;

            return consider_modules(s, r_s, size, align, i + 1);
        }
    }
    return e;
}

/*
 * Find a contiguous region that fits in the static heap region with
 * required size and alignment, and return the end address of the region
 * if found otherwise 0.
 */
static paddr_t __init fit_xenheap_in_static_heap(uint32_t size, paddr_t align)
{
    unsigned int i;
    paddr_t end = 0, aligned_start, aligned_end;
    paddr_t bank_start, bank_size, bank_end;

    for ( i = 0 ; i < bootinfo.reserved_mem.nr_banks; i++ )
    {
        if ( bootinfo.reserved_mem.bank[i].type != MEMBANK_STATIC_HEAP )
            continue;

        bank_start = bootinfo.reserved_mem.bank[i].start;
        bank_size = bootinfo.reserved_mem.bank[i].size;
        bank_end = bank_start + bank_size;

        if ( bank_size < size )
            continue;

        aligned_end = bank_end & ~(align - 1);
        aligned_start = (aligned_end - size) & ~(align - 1);

        if ( aligned_start > bank_start )
            /*
             * Allocate the xenheap as high as possible to keep low-memory
             * available (assuming the admin supplied region below 4GB)
             * for other use (e.g. domain memory allocation).
             */
            end = max(end, aligned_end);
    }

    return end;
}
#endif

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

static void __init init_pdx(void)
{
    paddr_t bank_start, bank_size, bank_end;

    /*
     * Arm does not have any restrictions on the bits to compress. Pass 0 to
     * let the common code further restrict the mask.
     *
     * If the logic changes in pfn_pdx_hole_setup we might have to
     * update this function too.
     */
    uint64_t mask = pdx_init_mask(0x0);
    int bank;

    for ( bank = 0 ; bank < bootinfo.mem.nr_banks; bank++ )
    {
        bank_start = bootinfo.mem.bank[bank].start;
        bank_size = bootinfo.mem.bank[bank].size;

        mask |= bank_start | pdx_region_mask(bank_start, bank_size);
    }

    for ( bank = 0 ; bank < bootinfo.mem.nr_banks; bank++ )
    {
        bank_start = bootinfo.mem.bank[bank].start;
        bank_size = bootinfo.mem.bank[bank].size;

        if (~mask & pdx_region_mask(bank_start, bank_size))
            mask = 0;
    }

    pfn_pdx_hole_setup(mask >> PAGE_SHIFT);

    for ( bank = 0 ; bank < bootinfo.mem.nr_banks; bank++ )
    {
        bank_start = bootinfo.mem.bank[bank].start;
        bank_size = bootinfo.mem.bank[bank].size;
        bank_end = bank_start + bank_size;

        set_pdx_range(paddr_to_pfn(bank_start),
                      paddr_to_pfn(bank_end));
    }
}

/* Static memory initialization */
static void __init init_staticmem_pages(void)
{
#ifdef CONFIG_STATIC_MEMORY
    unsigned int bank;

    for ( bank = 0 ; bank < bootinfo.reserved_mem.nr_banks; bank++ )
    {
        if ( bootinfo.reserved_mem.bank[bank].type == MEMBANK_STATIC_DOMAIN )
        {
            mfn_t bank_start = _mfn(PFN_UP(bootinfo.reserved_mem.bank[bank].start));
            unsigned long bank_pages = PFN_DOWN(bootinfo.reserved_mem.bank[bank].size);
            mfn_t bank_end = mfn_add(bank_start, bank_pages);

            if ( mfn_x(bank_end) <= mfn_x(bank_start) )
                return;

            unprepare_staticmem_pages(mfn_to_page(bank_start),
                                      bank_pages, false);
        }
    }
#endif
}

/*
 * Populate the boot allocator.
 * If a static heap was not provided by the admin, all the RAM but the
 * following regions will be added:
 *  - Modules (e.g., Xen, Kernel)
 *  - Reserved regions
 *  - Xenheap (arm32 only)
 * If a static heap was provided by the admin, populate the boot
 * allocator with the corresponding regions only, but with Xenheap excluded
 * on arm32.
 */
static void __init populate_boot_allocator(void)
{
    unsigned int i;
    const struct meminfo *banks = &bootinfo.mem;
    paddr_t s, e;

    if ( bootinfo.static_heap )
    {
        for ( i = 0 ; i < bootinfo.reserved_mem.nr_banks; i++ )
        {
            if ( bootinfo.reserved_mem.bank[i].type != MEMBANK_STATIC_HEAP )
                continue;

            s = bootinfo.reserved_mem.bank[i].start;
            e = s + bootinfo.reserved_mem.bank[i].size;
#ifdef CONFIG_ARM_32
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

#ifdef CONFIG_ARM_32
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

#ifdef CONFIG_ARM_32
static void __init setup_mm(void)
{
    paddr_t ram_start, ram_end, ram_size, e, bank_start, bank_end, bank_size;
    paddr_t static_heap_end = 0, static_heap_size = 0;
    unsigned long heap_pages, xenheap_pages, domheap_pages;
    unsigned int i;
    const uint32_t ctr = READ_CP32(CTR);

    if ( !bootinfo.mem.nr_banks )
        panic("No memory bank\n");

    /* We only supports instruction caches implementing the IVIPT extension. */
    if ( ((ctr >> CTR_L1IP_SHIFT) & CTR_L1IP_MASK) == ICACHE_POLICY_AIVIVT )
        panic("AIVIVT instruction cache not supported\n");

    init_pdx();

    ram_start = bootinfo.mem.bank[0].start;
    ram_size  = bootinfo.mem.bank[0].size;
    ram_end   = ram_start + ram_size;

    for ( i = 1; i < bootinfo.mem.nr_banks; i++ )
    {
        bank_start = bootinfo.mem.bank[i].start;
        bank_size = bootinfo.mem.bank[i].size;
        bank_end = bank_start + bank_size;

        ram_size  = ram_size + bank_size;
        ram_start = min(ram_start,bank_start);
        ram_end   = max(ram_end,bank_end);
    }

    total_pages = ram_size >> PAGE_SHIFT;

    if ( bootinfo.static_heap )
    {
        for ( i = 0 ; i < bootinfo.reserved_mem.nr_banks; i++ )
        {
            if ( bootinfo.reserved_mem.bank[i].type != MEMBANK_STATIC_HEAP )
                continue;

            bank_start = bootinfo.reserved_mem.bank[i].start;
            bank_size = bootinfo.reserved_mem.bank[i].size;
            bank_end = bank_start + bank_size;

            static_heap_size += bank_size;
            static_heap_end = max(static_heap_end, bank_end);
        }

        heap_pages = static_heap_size >> PAGE_SHIFT;
    }
    else
        heap_pages = total_pages;

    /*
     * If the user has not requested otherwise via the command line
     * then locate the xenheap using these constraints:
     *
     *  - must be contiguous
     *  - must be 32 MiB aligned
     *  - must not include Xen itself or the boot modules
     *  - must be at most 1GB or 1/32 the total RAM in the system (or static
          heap if enabled) if less
     *  - must be at least 32M
     *
     * We try to allocate the largest xenheap possible within these
     * constraints.
     */
    if ( opt_xenheap_megabytes )
        xenheap_pages = opt_xenheap_megabytes << (20-PAGE_SHIFT);
    else
    {
        xenheap_pages = (heap_pages/32 + 0x1fffUL) & ~0x1fffUL;
        xenheap_pages = max(xenheap_pages, 32UL<<(20-PAGE_SHIFT));
        xenheap_pages = min(xenheap_pages, 1UL<<(30-PAGE_SHIFT));
    }

    do
    {
        e = bootinfo.static_heap ?
            fit_xenheap_in_static_heap(pfn_to_paddr(xenheap_pages), MB(32)) :
            consider_modules(ram_start, ram_end,
                             pfn_to_paddr(xenheap_pages),
                             32<<20, 0);
        if ( e )
            break;

        xenheap_pages >>= 1;
    } while ( !opt_xenheap_megabytes && xenheap_pages > 32<<(20-PAGE_SHIFT) );

    if ( ! e )
        panic("Not enough space for xenheap\n");

    domheap_pages = heap_pages - xenheap_pages;

    printk("Xen heap: %"PRIpaddr"-%"PRIpaddr" (%lu pages%s)\n",
           e - (pfn_to_paddr(xenheap_pages)), e, xenheap_pages,
           opt_xenheap_megabytes ? ", from command-line" : "");
    printk("Dom heap: %lu pages\n", domheap_pages);

    /*
     * We need some memory to allocate the page-tables used for the
     * directmap mappings. So populate the boot allocator first.
     *
     * This requires us to set directmap_mfn_{start, end} first so the
     * direct-mapped Xenheap region can be avoided.
     */
    directmap_mfn_start = _mfn((e >> PAGE_SHIFT) - xenheap_pages);
    directmap_mfn_end = mfn_add(directmap_mfn_start, xenheap_pages);

    populate_boot_allocator();

    setup_directmap_mappings(mfn_x(directmap_mfn_start), xenheap_pages);

    /* Frame table covers all of RAM region, including holes */
    setup_frametable_mappings(ram_start, ram_end);
    max_page = PFN_DOWN(ram_end);

    /*
     * The allocators may need to use map_domain_page() (such as for
     * scrubbing pages). So we need to prepare the domheap area first.
     */
    if ( !init_domheap_mappings(smp_processor_id()) )
        panic("CPU%u: Unable to prepare the domheap page-tables\n",
              smp_processor_id());

    /* Add xenheap memory that was not already added to the boot allocator. */
    init_xenheap_pages(mfn_to_maddr(directmap_mfn_start),
                       mfn_to_maddr(directmap_mfn_end));

    init_staticmem_pages();
}
#else /* CONFIG_ARM_64 */
static void __init setup_mm(void)
{
    const struct meminfo *banks = &bootinfo.mem;
    paddr_t ram_start = INVALID_PADDR;
    paddr_t ram_end = 0;
    paddr_t ram_size = 0;
    unsigned int i;

    init_pdx();

    /*
     * We need some memory to allocate the page-tables used for the directmap
     * mappings. But some regions may contain memory already allocated
     * for other uses (e.g. modules, reserved-memory...).
     *
     * For simplicity, add all the free regions in the boot allocator.
     */
    populate_boot_allocator();

    total_pages = 0;

    for ( i = 0; i < banks->nr_banks; i++ )
    {
        const struct membank *bank = &banks->bank[i];
        paddr_t bank_end = bank->start + bank->size;

        ram_size = ram_size + bank->size;
        ram_start = min(ram_start, bank->start);
        ram_end = max(ram_end, bank_end);

        setup_directmap_mappings(PFN_DOWN(bank->start),
                                 PFN_DOWN(bank->size));
    }

    total_pages += ram_size >> PAGE_SHIFT;

    directmap_virt_end = XENHEAP_VIRT_START + ram_end - ram_start;
    directmap_mfn_start = maddr_to_mfn(ram_start);
    directmap_mfn_end = maddr_to_mfn(ram_end);

    setup_frametable_mappings(ram_start, ram_end);
    max_page = PFN_DOWN(ram_end);

    init_staticmem_pages();
}
#endif

static bool __init is_dom0less_mode(void)
{
    struct bootmodules *mods = &bootinfo.modules;
    struct bootmodule *mod;
    unsigned int i;
    bool dom0found = false;
    bool domUfound = false;

    /* Look into the bootmodules */
    for ( i = 0 ; i < mods->nr_mods ; i++ )
    {
        mod = &mods->module[i];
        /* Find if dom0 and domU kernels are present */
        if ( mod->kind == BOOTMOD_KERNEL )
        {
            if ( mod->domU == false )
            {
                dom0found = true;
                break;
            }
            else
                domUfound = true;
        }
    }

    /*
     * If there is no dom0 kernel but at least one domU, then we are in
     * dom0less mode
     */
    return ( !dom0found && domUfound );
}

size_t __read_mostly dcache_line_bytes;

/* C entry point for boot CPU */
void __init start_xen(unsigned long boot_phys_offset,
                      unsigned long fdt_paddr)
{
    size_t fdt_size;
    const char *cmdline;
    struct bootmodule *xen_bootmodule;
    struct domain *d;
    int rc, i;

    dcache_line_bytes = read_dcache_line_bytes();

    percpu_init_areas();
    set_processor_id(0); /* needed early, for smp_processor_id() */

    setup_virtual_regions(NULL, NULL);
    /* Initialize traps early allow us to get backtrace when an error occurred */
    init_traps();

    setup_pagetables(boot_phys_offset);

    smp_clear_cpu_maps();

    device_tree_flattened = early_fdt_map(fdt_paddr);
    if ( !device_tree_flattened )
        panic("Invalid device tree blob at physical address %#lx.\n"
              "The DTB must be 8-byte aligned and must not exceed 2 MB in size.\n\n"
              "Please check your bootloader.\n",
              fdt_paddr);

    /* Register Xen's load address as a boot module. */
    xen_bootmodule = add_boot_module(BOOTMOD_XEN,
                             (paddr_t)(uintptr_t)(_start + boot_phys_offset),
                             (paddr_t)(uintptr_t)(_end - _start), false);
    BUG_ON(!xen_bootmodule);

    fdt_size = boot_fdt_info(device_tree_flattened, fdt_paddr);

    cmdline = boot_fdt_cmdline(device_tree_flattened);
    printk("Command line: %s\n", cmdline);
    cmdline_parse(cmdline);

    setup_mm();

    /* Parse the ACPI tables for possible boot-time configuration */
    acpi_boot_table_init();

    end_boot_allocator();

    /*
     * The memory subsystem has been initialized, we can now switch from
     * early_boot -> boot.
     */
    system_state = SYS_STATE_boot;

    vm_init();

    if ( acpi_disabled )
    {
        printk("Booting using Device Tree\n");
        device_tree_flattened = relocate_fdt(fdt_paddr, fdt_size);
        dt_unflatten_host_device_tree();
    }
    else
    {
        printk("Booting using ACPI\n");
        device_tree_flattened = NULL;
    }

    init_IRQ();

    platform_init();

    preinit_xen_time();

    gic_preinit();

    arm_uart_init();
    console_init_preirq();
    console_init_ring();

    processor_id();

    smp_init_cpus();
    nr_cpu_ids = smp_get_max_cpus();
    printk(XENLOG_INFO "SMP: Allowing %u CPUs\n", nr_cpu_ids);

    /*
     * Some errata relies on SMCCC version which is detected by psci_init()
     * (called from smp_init_cpus()).
     */
    check_local_cpu_errata();

    check_local_cpu_features();

    init_xen_time();

    gic_init();

    tasklet_subsys_init();

    if ( xsm_dt_init() != 1 )
        warning_add("WARNING: SILO mode is not enabled.\n"
                    "It has implications on the security of the system,\n"
                    "unless the communications have been forbidden between\n"
                    "untrusted domains.\n");

    init_maintenance_interrupt();
    init_timer_interrupt();

    timer_init();

    init_idle_domain();

    rcu_init();

    setup_system_domains();

    local_irq_enable();
    local_abort_enable();

    smp_prepare_cpus();

    initialize_keytable();

    console_init_postirq();

    do_presmp_initcalls();

    for_each_present_cpu ( i )
    {
        if ( (num_online_cpus() < nr_cpu_ids) && !cpu_online(i) )
        {
            int ret = cpu_up(i);
            if ( ret != 0 )
                printk("Failed to bring up CPU %u (error %d)\n", i, ret);
        }
    }

    printk("Brought up %ld CPUs\n", (long)num_online_cpus());
    /* TODO: smp_cpus_done(); */

    /* This should be done in a vpmu driver but we do not have one yet. */
    vpmu_is_available = cpu_has_pmu;

    /*
     * The IOMMU subsystem must be initialized before P2M as we need
     * to gather requirements regarding the maximum IPA bits supported by
     * each IOMMU device.
     */
    rc = iommu_setup();
    if ( !iommu_enabled && rc != -ENODEV )
        panic("Couldn't configure correctly all the IOMMUs.\n");

    setup_virt_paging();

    do_initcalls();

    /*
     * It needs to be called after do_initcalls to be able to use
     * stop_machine (tasklets initialized via an initcall).
     */
    apply_alternatives_all();
    enable_errata_workarounds();
    enable_cpu_features();

    /* Create initial domain 0. */
    if ( !is_dom0less_mode() )
        create_dom0();
    else
        printk(XENLOG_INFO "Xen dom0less mode detected\n");

    if ( acpi_disabled )
    {
        create_domUs();
        alloc_static_evtchn();
    }

    /*
     * This needs to be called **before** heap_init_late() so modules
     * will be scrubbed (unless suppressed).
     */
    discard_initial_modules();

    heap_init_late();

    init_trace_bufs();

    init_constructors();

    console_endboot();

    /* Hide UART from DOM0 if we're using it */
    serial_endboot();

    if ( (rc = xsm_set_system_active()) != 0 )
        panic("xsm: unable to switch to SYSTEM_ACTIVE privilege: %d\n", rc);

    system_state = SYS_STATE_active;

    for_each_domain( d )
        domain_unpause_by_systemcontroller(d);

    /* Switch on to the dynamically allocated stack for the idle vcpu
     * since the static one we're running on is about to be freed. */
    memcpy(idle_vcpu[0]->arch.cpu_info, get_cpu_info(),
           sizeof(struct cpu_info));
    switch_stack_and_jump(idle_vcpu[0]->arch.cpu_info, init_done);
}

void arch_get_xen_caps(xen_capabilities_info_t *info)
{
    /* Interface name is always xen-3.0-* for Xen-3.x. */
    int major = 3, minor = 0;
    char s[32];

    (*info)[0] = '\0';

#ifdef CONFIG_ARM_64
    snprintf(s, sizeof(s), "xen-%d.%d-aarch64 ", major, minor);
    safe_strcat(*info, s);
#endif
    if ( cpu_has_aarch32 )
    {
        snprintf(s, sizeof(s), "xen-%d.%d-armv7l ", major, minor);
        safe_strcat(*info, s);
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
