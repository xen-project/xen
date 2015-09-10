/*
 * xen/arch/arm/setup.c
 *
 * Early bringup code for an ARMv7-A with virt extensions.
 *
 * Tim Deegan <tim@xen.org>
 * Copyright (c) 2011 Citrix Systems.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <xen/config.h>
#include <xen/compile.h>
#include <xen/device_tree.h>
#include <xen/domain_page.h>
#include <xen/types.h>
#include <xen/string.h>
#include <xen/serial.h>
#include <xen/sched.h>
#include <xen/console.h>
#include <xen/err.h>
#include <xen/init.h>
#include <xen/irq.h>
#include <xen/mm.h>
#include <xen/softirq.h>
#include <xen/keyhandler.h>
#include <xen/cpu.h>
#include <xen/pfn.h>
#include <xen/vmap.h>
#include <xen/libfdt/libfdt.h>
#include <asm/page.h>
#include <asm/current.h>
#include <asm/setup.h>
#include <asm/early_printk.h>
#include <asm/gic.h>
#include <asm/cpufeature.h>
#include <asm/platform.h>

struct cpuinfo_arm __read_mostly boot_cpu_data;

static __used void init_done(void)
{
    free_init_memory();
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
    struct cpuinfo_arm *c = &boot_cpu_data;

    identify_cpu(c);
    current_cpu_data = *c;

    if ( c->midr.implementer < ARRAY_SIZE(processor_implementers) &&
         processor_implementers[c->midr.implementer] )
        implementer = processor_implementers[c->midr.implementer];

    if ( c->midr.architecture != 0xf )
        printk("Huh, cpu architecture %x, expected 0xf (defined by cpuid)\n",
               c->midr.architecture);

    printk("Processor: %08"PRIx32": \"%s\", variant: 0x%x, part 0x%03x, rev 0x%x\n",
           c->midr.bits, implementer,
           c->midr.variant, c->midr.part_number, c->midr.revision);

#if defined(CONFIG_ARM_64)
    printk("64-bit Execution:\n");
    printk("  Processor Features: %016"PRIx64" %016"PRIx64"\n",
           boot_cpu_data.pfr64.bits[0], boot_cpu_data.pfr64.bits[1]);
    printk("    Exception Levels: EL3:%s EL2:%s EL1:%s EL0:%s\n",
           cpu_has_el3_32 ? "64+32" : cpu_has_el3_64 ? "64" : "No",
           cpu_has_el2_32 ? "64+32" : cpu_has_el2_64 ? "64" : "No",
           cpu_has_el1_32 ? "64+32" : cpu_has_el1_64 ? "64" : "No",
           cpu_has_el0_32 ? "64+32" : cpu_has_el0_64 ? "64" : "No");
    printk("    Extensions:%s%s\n",
           cpu_has_fp ? " FloatingPoint" : "",
           cpu_has_simd ? " AdvancedSIMD" : "");

    printk("  Debug Features: %016"PRIx64" %016"PRIx64"\n",
           boot_cpu_data.dbg64.bits[0], boot_cpu_data.dbg64.bits[1]);
    printk("  Auxiliary Features: %016"PRIx64" %016"PRIx64"\n",
           boot_cpu_data.aux64.bits[0], boot_cpu_data.aux64.bits[1]);
    printk("  Memory Model Features: %016"PRIx64" %016"PRIx64"\n",
           boot_cpu_data.mm64.bits[0], boot_cpu_data.mm64.bits[1]);
    printk("  ISA Features:  %016"PRIx64" %016"PRIx64"\n",
           boot_cpu_data.isa64.bits[0], boot_cpu_data.isa64.bits[1]);
#endif

    /*
     * On AArch64 these refer to the capabilities when running in
     * AArch32 mode.
     */
    if ( cpu_has_aarch32 )
    {
        printk("32-bit Execution:\n");
        printk("  Processor Features: %08"PRIx32":%08"PRIx32"\n",
               boot_cpu_data.pfr32.bits[0], boot_cpu_data.pfr32.bits[1]);
        printk("    Instruction Sets:%s%s%s%s%s\n",
               cpu_has_aarch32 ? " AArch32" : "",
               cpu_has_thumb ? " Thumb" : "",
               cpu_has_thumb2 ? " Thumb-2" : "",
               cpu_has_thumbee ? " ThumbEE" : "",
               cpu_has_jazelle ? " Jazelle" : "");
        printk("    Extensions:%s%s\n",
               cpu_has_gentimer ? " GenericTimer" : "",
               cpu_has_security ? " Security" : "");

        printk("  Debug Features: %08"PRIx32"\n",
               boot_cpu_data.dbg32.bits[0]);
        printk("  Auxiliary Features: %08"PRIx32"\n",
               boot_cpu_data.aux32.bits[0]);
        printk("  Memory Model Features: "
               "%08"PRIx32" %08"PRIx32" %08"PRIx32" %08"PRIx32"\n",
               boot_cpu_data.mm32.bits[0], boot_cpu_data.mm32.bits[1],
               boot_cpu_data.mm32.bits[2], boot_cpu_data.mm32.bits[3]);
        printk(" ISA Features: %08x %08x %08x %08x %08x %08x\n",
               boot_cpu_data.isa32.bits[0], boot_cpu_data.isa32.bits[1],
               boot_cpu_data.isa32.bits[2], boot_cpu_data.isa32.bits[3],
               boot_cpu_data.isa32.bits[4], boot_cpu_data.isa32.bits[5]);
    }
    else
    {
        printk("32-bit Execution: Unsupported\n");
    }
}

static void dt_unreserved_regions(paddr_t s, paddr_t e,
                                  void (*cb)(paddr_t, paddr_t), int first)
{
    int i, nr = fdt_num_mem_rsv(device_tree_flattened);

    for ( i = first; i < nr ; i++ )
    {
        paddr_t r_s, r_e;

        if ( fdt_get_mem_rsv(device_tree_flattened, i, &r_s, &r_e ) < 0 )
            /* If we can't read it, pretend it doesn't exist... */
            continue;

        r_e += r_s; /* fdt_get_mem_rsc returns length */

        if ( s < r_e && r_s < e )
        {
            dt_unreserved_regions(r_e, e, cb, i+1);
            dt_unreserved_regions(s, r_s, cb, i+1);
            return;
        }
    }

    cb(s, e);
}

void __init discard_initial_modules(void)
{
    struct dt_module_info *mi = &early_info.modules;
    int i;

    for ( i = MOD_DISCARD_FIRST; i <= mi->nr_mods; i++ )
    {
        paddr_t s = mi->module[i].start;
        paddr_t e = s + PAGE_ALIGN(mi->module[i].size);

        dt_unreserved_regions(s, e, init_domheap_pages, 0);
    }

    mi->nr_mods = 0;

    remove_early_mappings();
}

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
    const struct dt_module_info *mi = &early_info.modules;
    int i;
    int nr_rsvd;

    s = (s+align-1) & ~(align-1);
    e = e & ~(align-1);

    if ( s > e ||  e - s < size )
        return 0;

    /* First check the boot modules */
    for ( i = first_mod; i <= mi->nr_mods; i++ )
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

    nr_rsvd = fdt_num_mem_rsv(device_tree_flattened);

    for ( ; i < mi->nr_mods + nr_rsvd; i++ )
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
    return e;
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
    struct dt_module_info *mi = &early_info.modules;
    paddr_t lowest = ~(paddr_t)0;
    int i;

    for ( i = 0; i <= mi->nr_mods; i++ )
    {
        paddr_t mod_s = mi->module[i].start;
        paddr_t mod_e = mod_s + mi->module[i].size;

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


/**
 * get_xen_paddr - get physical address to relocate Xen to
 *
 * Xen is relocated to as near to the top of RAM as possible and
 * aligned to a XEN_PADDR_ALIGN boundary.
 */
static paddr_t __init get_xen_paddr(void)
{
    struct dt_mem_info *mi = &early_info.mem;
    paddr_t min_size;
    paddr_t paddr = 0, last_end;
    int i;

    min_size = (_end - _start + (XEN_PADDR_ALIGN-1)) & ~(XEN_PADDR_ALIGN-1);

    last_end = mi->bank[0].start;

    /* Find the highest bank with enough space. */
    for ( i = 0; i < mi->nr_banks; i++ )
    {
        const struct membank *bank = &mi->bank[i];
        paddr_t s, e;

        /* We can only deal with contiguous memory at the moment */
        if ( last_end != bank->start )
            break;

        last_end = bank->start + bank->size;

        if ( bank->size >= min_size )
        {
            e = consider_modules(bank->start, bank->start + bank->size,
                                 min_size, XEN_PADDR_ALIGN, 1);
            if ( !e )
                continue;

#ifdef CONFIG_ARM_32
            /* Xen must be under 4GB */
            if ( e > 0x100000000ULL )
                e = 0x100000000ULL;
            if ( e < bank->start )
                continue;
#endif

            s = e - min_size;

            if ( s > paddr )
                paddr = s;
        }
    }

    if ( !paddr )
        early_panic("Not enough memory to relocate Xen");

    early_printk("Placing Xen at 0x%"PRIpaddr"-0x%"PRIpaddr"\n",
                 paddr, paddr + min_size);

    early_info.modules.module[MOD_XEN].start = paddr;
    early_info.modules.module[MOD_XEN].size = min_size;

    return paddr;
}

#ifdef CONFIG_ARM_32
static void __init setup_mm(unsigned long dtb_paddr, size_t dtb_size)
{
    paddr_t ram_start, ram_end, ram_size;
    paddr_t contig_start, contig_end;
    paddr_t s, e;
    unsigned long ram_pages;
    unsigned long heap_pages, xenheap_pages, domheap_pages;
    unsigned long dtb_pages;
    unsigned long boot_mfn_start, boot_mfn_end;
    int i;
    void *fdt;

    if ( !early_info.mem.nr_banks )
        early_panic("No memory bank");

    /*
     * We are going to accumulate two regions here.
     *
     * The first is the bounds of the initial memory region which is
     * contiguous with the first bank. For simplicity the xenheap is
     * always allocated from this region.
     *
     * The second is the complete bounds of the regions containing RAM
     * (ie. from the lowest RAM address to the highest), which
     * includes any holes.
     *
     * We also track the number of actual RAM pages (i.e. not counting
     * the holes).
     */
    ram_size  = early_info.mem.bank[0].size;

    contig_start = ram_start = early_info.mem.bank[0].start;
    contig_end   = ram_end = ram_start + ram_size;

    for ( i = 1; i < early_info.mem.nr_banks; i++ )
    {
        paddr_t bank_start = early_info.mem.bank[i].start;
        paddr_t bank_size = early_info.mem.bank[i].size;
        paddr_t bank_end = bank_start + bank_size;

        paddr_t new_ram_size = ram_size + bank_size;
        paddr_t new_ram_start = min(ram_start,bank_start);
        paddr_t new_ram_end = max(ram_end,bank_end);

        /*
         * If the new bank is contiguous with the initial contiguous
         * region then incorporate it into the contiguous region.
         *
         * Otherwise we allow non-contigious regions so long as at
         * least half of the total RAM region actually contains
         * RAM. We actually fudge this slightly and require that
         * adding the current bank does not cause us to violate this
         * restriction.
         *
         * This restriction ensures that the frametable (which is not
         * currently sparse) does not consume all available RAM.
         */
        if ( bank_start == contig_end )
            contig_end = bank_end;
        else if ( bank_end == contig_start )
            contig_start = bank_start;
        else if ( 2 * new_ram_size < new_ram_end - new_ram_start )
            /* Would create memory map which is too sparse, so stop here. */
            break;

        ram_size = new_ram_size;
        ram_start = new_ram_start;
        ram_end = new_ram_end;
    }

    if ( i != early_info.mem.nr_banks )
    {
        early_printk("WARNING: only using %d out of %d memory banks\n",
                     i, early_info.mem.nr_banks);
        early_info.mem.nr_banks = i;
    }

    total_pages = ram_pages = ram_size >> PAGE_SHIFT;

    /*
     * Locate the xenheap using these constraints:
     *
     *  - must be 32 MiB aligned
     *  - must not include Xen itself or the boot modules
     *  - must be at most 1/8 the total RAM in the system
     *  - must be at least 128M
     *
     * We try to allocate the largest xenheap possible within these
     * constraints.
     */
    heap_pages = ram_pages;
    xenheap_pages = (heap_pages/8 + 0x1fffUL) & ~0x1fffUL;
    xenheap_pages = max(xenheap_pages, 128UL<<(20-PAGE_SHIFT));

    do
    {
        /* xenheap is always in the initial contiguous region */
        e = consider_modules(contig_start, contig_end,
                             pfn_to_paddr(xenheap_pages),
                             32<<20, 0);
        if ( e )
            break;

        xenheap_pages >>= 1;
    } while ( xenheap_pages > 128<<(20-PAGE_SHIFT) );

    if ( ! e )
        early_panic("Not not enough space for xenheap");

    domheap_pages = heap_pages - xenheap_pages;

    early_printk("Xen heap: %"PRIpaddr"-%"PRIpaddr" (%lu pages)\n",
                 e - (pfn_to_paddr(xenheap_pages)), e,
                 xenheap_pages);
    early_printk("Dom heap: %lu pages\n", domheap_pages);

    setup_xenheap_mappings((e >> PAGE_SHIFT) - xenheap_pages, xenheap_pages);

    /*
     * Need a single mapped page for populating bootmem_region_list
     * and enough mapped pages for copying the DTB.
     */
    dtb_pages = (dtb_size + PAGE_SIZE-1) >> PAGE_SHIFT;
    boot_mfn_start = xenheap_mfn_end - dtb_pages - 1;
    boot_mfn_end = xenheap_mfn_end;

    init_boot_pages(pfn_to_paddr(boot_mfn_start), pfn_to_paddr(boot_mfn_end));

    /* Copy the DTB. */
    fdt = mfn_to_virt(alloc_boot_pages(dtb_pages, 1));
    copy_from_paddr(fdt, dtb_paddr, dtb_size, BUFFERABLE);
    device_tree_flattened = fdt;

    /* Add non-xenheap memory */
    for ( i = 0; i < early_info.mem.nr_banks; i++ )
    {
        paddr_t bank_start = early_info.mem.bank[i].start;
        paddr_t bank_end = bank_start + early_info.mem.bank[i].size;

        s = bank_start;
        while ( s < bank_end )
        {
            paddr_t n = bank_end;

            e = next_module(s, &n);

            if ( e == ~(paddr_t)0 )
            {
                e = n = ram_end;
            }

            /*
             * Module in a RAM bank other than the one which we are
             * not dealing with here.
             */
            if ( e > bank_end )
                e = bank_end;

            /* Avoid the xenheap */
            if ( s < pfn_to_paddr(xenheap_mfn_start+xenheap_pages)
                 && pfn_to_paddr(xenheap_mfn_start) < e )
            {
                e = pfn_to_paddr(xenheap_mfn_start);
                n = pfn_to_paddr(xenheap_mfn_start+xenheap_pages);
            }

            dt_unreserved_regions(s, e, init_boot_pages, 0);

            s = n;
        }
    }

    /* Frame table covers all of RAM region, including holes */
    setup_frametable_mappings(ram_start, ram_end);
    max_page = PFN_DOWN(ram_end);

    /* Add xenheap memory that was not already added to the boot
       allocator. */
    init_xenheap_pages(pfn_to_paddr(xenheap_mfn_start),
                       pfn_to_paddr(boot_mfn_start));

    end_boot_allocator();
}
#else /* CONFIG_ARM_64 */
static void __init setup_mm(unsigned long dtb_paddr, size_t dtb_size)
{
    paddr_t ram_start = ~0;
    paddr_t ram_end = 0;
    paddr_t ram_size = 0;
    int bank;
    unsigned long dtb_pages;
    void *fdt;

    total_pages = 0;
    for ( bank = 0 ; bank < early_info.mem.nr_banks; bank++ )
    {
        paddr_t bank_start = early_info.mem.bank[bank].start;
        paddr_t bank_size = early_info.mem.bank[bank].size;
        paddr_t bank_end = bank_start + bank_size;
        paddr_t s, e;

        paddr_t new_ram_size = ram_size + bank_size;
        paddr_t new_ram_start = min(ram_start,bank_start);
        paddr_t new_ram_end = max(ram_end,bank_end);

        /*
         * We allow non-contigious regions so long as at least half of
         * the total RAM region actually contains RAM. We actually
         * fudge this slightly and require that adding the current
         * bank does not cause us to violate this restriction.
         *
         * This restriction ensures that the frametable (which is not
         * currently sparse) does not consume all available RAM.
         */
        if ( bank > 0 && 2 * new_ram_size < new_ram_end - new_ram_start )
            /* Would create memory map which is too sparse, so stop here. */
            break;

        ram_start = new_ram_start;
        ram_end = new_ram_end;
        ram_size = new_ram_size;

        setup_xenheap_mappings(bank_start>>PAGE_SHIFT, bank_size>>PAGE_SHIFT);

        s = bank_start;
        while ( s < bank_end )
        {
            paddr_t n = bank_end;

            e = next_module(s, &n);

            if ( e == ~(paddr_t)0 )
            {
                e = n = bank_end;
            }

            if ( e > bank_end )
                e = bank_end;

            xenheap_mfn_end = e;

            dt_unreserved_regions(s, e, init_boot_pages, 0);
            s = n;
        }
    }

    if ( bank != early_info.mem.nr_banks )
    {
        early_printk("WARNING: only using %d out of %d memory banks\n",
                     bank, early_info.mem.nr_banks);
        early_info.mem.nr_banks = bank;
    }

    total_pages += ram_size >> PAGE_SHIFT;

    xenheap_virt_end = XENHEAP_VIRT_START + ram_end - ram_start;
    xenheap_mfn_start = ram_start >> PAGE_SHIFT;
    xenheap_mfn_end = ram_end >> PAGE_SHIFT;

    /*
     * Need enough mapped pages for copying the DTB.
     */
    dtb_pages = (dtb_size + PAGE_SIZE-1) >> PAGE_SHIFT;

    /* Copy the DTB. */
    fdt = mfn_to_virt(alloc_boot_pages(dtb_pages, 1));
    copy_from_paddr(fdt, dtb_paddr, dtb_size, BUFFERABLE);
    device_tree_flattened = fdt;

    setup_frametable_mappings(ram_start, ram_end);
    max_page = PFN_DOWN(ram_end);

    end_boot_allocator();
}
#endif

size_t __read_mostly cacheline_bytes;

/* Very early check of the CPU cache properties */
void __init setup_cache(void)
{
    uint32_t ccsid;

    /* Read the cache size ID register for the level-0 data cache */
    WRITE_SYSREG32(0, CSSELR_EL1);
    ccsid = READ_SYSREG32(CCSIDR_EL1);

    /* Low 3 bits are log2(cacheline size in words) - 2. */
    cacheline_bytes = 1U << (4 + (ccsid & 0x7));
}

/* C entry point for boot CPU */
void __init start_xen(unsigned long boot_phys_offset,
                      unsigned long fdt_paddr,
                      unsigned long cpuid)
{
    size_t fdt_size;
    int cpus, i;
    const char *cmdline;

    setup_cache();

    percpu_init_areas();
    set_processor_id(0); /* needed early, for smp_processor_id() */

    smp_clear_cpu_maps();

    /* This is mapped by head.S */
    device_tree_flattened = (void *)BOOT_FDT_VIRT_START
        + (fdt_paddr & ((1 << SECOND_SHIFT) - 1));
    fdt_size = device_tree_early_init(device_tree_flattened, fdt_paddr);

    cmdline = device_tree_bootargs(device_tree_flattened);
    early_printk("Command line: %s\n", cmdline);
    cmdline_parse(cmdline);

    setup_pagetables(boot_phys_offset, get_xen_paddr());
    setup_mm(fdt_paddr, fdt_size);

    vm_init();
    dt_unflatten_host_device_tree();
    dt_irq_xlate = gic_irq_xlate;

    dt_uart_init();
    console_init_preirq();

    system_state = SYS_STATE_boot;

    processor_id();

    platform_init();

    smp_init_cpus();
    cpus = smp_get_max_cpus();

    init_xen_time();

    gic_init();

    set_current((struct vcpu *)0xfffff000); /* debug sanity */
    idle_vcpu[0] = current;

    init_traps();

    setup_virt_paging();

    p2m_vmid_allocator_init();

    softirq_init();

    tasklet_subsys_init();

    init_IRQ();

    gic_route_ppis();
    gic_route_spis();

    init_maintenance_interrupt();
    init_timer_interrupt();

    timer_init();

    init_idle_domain();

    rcu_init();

    arch_init_memory();

    local_irq_enable();
    local_abort_enable();

    smp_prepare_cpus(cpus);

    initialize_keytable();

    console_init_postirq();

    do_presmp_initcalls();

    for_each_present_cpu ( i )
    {
        if ( (num_online_cpus() < cpus) && !cpu_online(i) )
        {
            int ret = cpu_up(i);
            if ( ret != 0 )
                printk("Failed to bring up CPU %u (error %d)\n", i, ret);
        }
    }

    printk("Brought up %ld CPUs\n", (long)num_online_cpus());
    /* TODO: smp_cpus_done(); */

    do_initcalls();

    /* Create initial domain 0. */
    dom0 = domain_create(0, 0, 0);
    if ( IS_ERR(dom0) || (alloc_dom0_vcpu0() == NULL) )
            panic("Error creating domain 0");

    dom0->is_privileged = 1;
    dom0->target = NULL;

    if ( construct_dom0(dom0) != 0)
            panic("Could not set up DOM0 guest OS");

    /* Scrub RAM that is still free and so may go to an unprivileged domain. */
    scrub_heap_pages();

    init_constructors();

    console_endboot();

    /* Hide UART from DOM0 if we're using it */
    serial_endboot();

    system_state = SYS_STATE_active;

    domain_unpause_by_systemcontroller(dom0);

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
    snprintf(s, sizeof(s), "xen-%d.%d-armv7l ", major, minor);
    safe_strcat(*info, s);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
