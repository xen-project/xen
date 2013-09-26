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
    ['D'] = "Digital Equipment Corp",
    ['M'] = "Motorola, Freescale Semiconductor Inc.",
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

    printk("Processor: \"%s\", variant: 0x%x, part 0x%03x, rev 0x%x\n",
           implementer, c->midr.variant, c->midr.part_number, c->midr.revision);

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

void __init discard_initial_modules(void)
{
    struct dt_module_info *mi = &early_info.modules;
    int i;

    for ( i = MOD_DISCARD_FIRST; i <= mi->nr_mods; i++ )
    {
        paddr_t s = mi->module[i].start;
        paddr_t e = s + PAGE_ALIGN(mi->module[i].size);

        init_domheap_pages(s, e);
    }

    mi->nr_mods = 0;
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

    s = (s+align-1) & ~(align-1);
    e = e & ~(align-1);

    if ( s > e ||  e - s < size )
        return 0;

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

    return e;
}

/*
 * Return the end of the non-module region starting at s. In other
 * words return s the start of the next modules after s.
 *
 * Also returns the end of that module in *n.
 */
static paddr_t __init next_module(paddr_t s, paddr_t *n)
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
        lowest = mod_s;
        *n = mod_e;
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
    paddr_t paddr = 0;
    int i;

    min_size = (_end - _start + (XEN_PADDR_ALIGN-1)) & ~(XEN_PADDR_ALIGN-1);

    /* Find the highest bank with enough space. */
    for ( i = 0; i < mi->nr_banks; i++ )
    {
        const struct membank *bank = &mi->bank[i];
        paddr_t s, e;

        if ( bank->size >= min_size )
        {
            e = consider_modules(bank->start, bank->start + bank->size,
                                 min_size, XEN_PADDR_ALIGN, 1);
            if ( !e )
                continue;

            s = e - min_size;

            if ( s > paddr )
                paddr = s;
        }
    }

    if ( !paddr )
        early_panic("Not enough memory to relocate Xen\n");

    early_printk("Placing Xen at 0x%"PRIpaddr"-0x%"PRIpaddr"\n",
                 paddr, paddr + min_size);

    early_info.modules.module[MOD_XEN].start = paddr;
    early_info.modules.module[MOD_XEN].size = min_size;

    return paddr;
}

#ifdef CONFIG_ARM_32
static void __init setup_mm(unsigned long dtb_paddr, size_t dtb_size)
{
    paddr_t ram_start;
    paddr_t ram_end;
    paddr_t ram_size;
    paddr_t s, e;
    unsigned long ram_pages;
    unsigned long heap_pages, xenheap_pages, domheap_pages;
    unsigned long dtb_pages;
    unsigned long boot_mfn_start, boot_mfn_end;
    int i = 0;
    void *fdt;

    /* TODO: Handle non-contiguous memory bank */
    if ( !early_info.mem.nr_banks )
        early_panic("No memory bank\n");
    ram_start = early_info.mem.bank[0].start;
    ram_size  = early_info.mem.bank[0].size;
    ram_end = ram_start + ram_size;

    for ( i = 1; i < early_info.mem.nr_banks; i++ )
    {
        if ( ram_end != early_info.mem.bank[i].start )
            break;

        ram_size += early_info.mem.bank[i].size;
        ram_end += early_info.mem.bank[i].size;
    }

    if ( i != early_info.mem.nr_banks )
        early_printk("WARNING: some memory banks are not used\n");

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
    heap_pages = (ram_size >> PAGE_SHIFT);
    xenheap_pages = max(heap_pages/8, 128UL<<(20-PAGE_SHIFT));

    do
    {
        e = consider_modules(ram_start, ram_end, xenheap_pages<<PAGE_SHIFT,
                             32<<20, 0);
        if ( e )
            break;

        xenheap_pages >>= 1;
    } while ( xenheap_pages > 128<<(20-PAGE_SHIFT) );

    if ( ! e )
        early_panic("Not not enough space for xenheap\n");

    domheap_pages = heap_pages - xenheap_pages;

    early_printk("Xen heap: %lu pages  Dom heap: %lu pages\n",
                 xenheap_pages, domheap_pages);

    setup_xenheap_mappings((e >> PAGE_SHIFT) - xenheap_pages, xenheap_pages);

    /*
     * Need a single mapped page for populating bootmem_region_list
     * and enough mapped pages for copying the DTB.
     *
     * TODO: The DTB (and other payloads) are assumed to be towards
     * the start of RAM.
     */
    dtb_pages = (dtb_size + PAGE_SIZE-1) >> PAGE_SHIFT;
    boot_mfn_start = xenheap_mfn_end - dtb_pages - 1;
    boot_mfn_end = xenheap_mfn_end;

    init_boot_pages(pfn_to_paddr(boot_mfn_start), pfn_to_paddr(boot_mfn_end));

    /*
     * Copy the DTB.
     *
     * TODO: handle other payloads too.
     */
    fdt = mfn_to_virt(alloc_boot_pages(dtb_pages, 1));
    copy_from_paddr(fdt, dtb_paddr, dtb_size, BUFFERABLE);
    device_tree_flattened = fdt;

    /* Add non-xenheap memory */
    s = ram_start;
    while ( s < ram_end )
    {
        paddr_t n = ram_end;

        e = next_module(s, &n);

        if ( e == ~(paddr_t)0 )
        {
            e = n = ram_end;
        }

        /* Avoid the xenheap */
        if ( s < ((xenheap_mfn_start+xenheap_pages) << PAGE_SHIFT)
             && (xenheap_mfn_start << PAGE_SHIFT) < e )
        {
            e = pfn_to_paddr(xenheap_mfn_start);
            n = pfn_to_paddr(xenheap_mfn_start+xenheap_pages);
        }

        init_boot_pages(s, e);

        s = n;
    }

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
    int bank;
    unsigned long  xenheap_pages = 0;
    unsigned long dtb_pages;
    void *fdt;

    total_pages = 0;
    for ( bank = 0 ; bank < early_info.mem.nr_banks; bank++ )
    {
        paddr_t bank_start = early_info.mem.bank[bank].start;
        paddr_t bank_size  = early_info.mem.bank[bank].size;
        paddr_t  bank_end = bank_start + bank_size;
        unsigned long bank_pages = bank_size >> PAGE_SHIFT;
        paddr_t s, e;

        total_pages += bank_pages;

        if ( bank_start < ram_start )
            ram_start = bank_start;
        if ( bank_end > ram_end )
            ram_end = bank_end;

        xenheap_pages += (bank_size >> PAGE_SHIFT);

        /* XXX we assume that the ram regions are ordered */
        s = bank_start;
        while ( s < bank_end )
        {
            paddr_t n = bank_end;

            e = next_module(s, &n);

            if ( e == ~(paddr_t)0 )
            {
                e = n = bank_end;
            }

            setup_xenheap_mappings(s>>PAGE_SHIFT, (e-s)>>PAGE_SHIFT);

            xenheap_mfn_end = e;

            init_boot_pages(s, e);
            s = n;
        }
    }

    xenheap_virt_end = XENHEAP_VIRT_START + ram_end - ram_start;
    xenheap_mfn_start = ram_start >> PAGE_SHIFT;
    xenheap_mfn_end = ram_end >> PAGE_SHIFT;
    xenheap_max_mfn(xenheap_mfn_end);

    /*
     * Need enough mapped pages for copying the DTB.
     *
     * TODO: The DTB (and other payloads) are assumed to be towards
     * the start of RAM.
     */
    dtb_pages = (dtb_size + PAGE_SIZE-1) >> PAGE_SHIFT;

    /*
     * Copy the DTB.
     *
     * TODO: handle other payloads too.
     */
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

/* Parse the device tree and build the logical map array containing
 * MPIDR values related to logical cpus
 * Code base on Linux arch/arm/kernel/devtree.c
 */
static void __init init_cpus_maps(void)
{
    register_t mpidr;
    struct dt_device_node *cpus = dt_find_node_by_path("/cpus");
    struct dt_device_node *cpu;
    unsigned int i, j;
    unsigned int cpuidx = 1;
    static u32 tmp_map[NR_CPUS] __initdata =
    {
        [0 ... NR_CPUS - 1] = MPIDR_INVALID
    };
    bool_t bootcpu_valid = 0;

    mpidr = boot_cpu_data.mpidr.bits & MPIDR_HWID_MASK;

    if ( !cpus )
    {
        printk(XENLOG_WARNING "WARNING: Can't find /cpus in the device tree.\n"
               "Using only 1 CPU\n");
        return;
    }

    dt_for_each_child_node( cpus, cpu )
    {
        u32 hwid;

        if ( !dt_device_type_is_equal(cpu, "cpu") )
            continue;

        if ( !dt_property_read_u32(cpu, "reg", &hwid) )
        {
            printk(XENLOG_WARNING "cpu node `%s`: missing reg property\n",
                   dt_node_full_name(cpu));
            continue;
        }

        /*
         * 8 MSBs must be set to 0 in the DT since the reg property
         * defines the MPIDR[23:0]
         */
        if ( hwid & ~MPIDR_HWID_MASK )
        {
            printk(XENLOG_WARNING "cpu node `%s`: invalid hwid value (0x%x)\n",
                   dt_node_full_name(cpu), hwid);
            continue;
        }

        /*
         * Duplicate MPIDRs are a recipe for disaster. Scan all initialized
         * entries and check for duplicates. If any found just skip the node.
         * temp values values are initialized to MPIDR_INVALID to avoid
         * matching valid MPIDR[23:0] values.
         */
        for ( j = 0; j < cpuidx; j++ )
        {
            if ( tmp_map[j] == hwid )
            {
                printk(XENLOG_WARNING "cpu node `%s`: duplicate /cpu reg properties in the DT\n",
                       dt_node_full_name(cpu));
                continue;
            }
        }

        /*
         * Build a stashed array of MPIDR values. Numbering scheme requires
         * that if detected the boot CPU must be assigned logical id 0. Other
         * CPUs get sequential indexes starting from 1. If a CPU node
         * with a reg property matching the boot CPU MPIDR is detected,
         * this is recorded and so that the logical map build from DT is
         * validated and can be used to set the map.
         */
        if ( hwid == mpidr )
        {
            i = 0;
            bootcpu_valid = 1;
        }
        else
            i = cpuidx++;

        if ( cpuidx > NR_CPUS )
        {
            printk(XENLOG_WARNING "DT /cpu %u node greater than max cores %u, capping them\n",
                   cpuidx, NR_CPUS);
            cpuidx = NR_CPUS;
            break;
        }

        tmp_map[i] = hwid;
    }

    if ( !bootcpu_valid )
    {
        printk(XENLOG_WARNING "DT missing boot CPU MPIDR[23:0]\n"
               "Using only 1 CPU\n");
        return;
    }

    for ( i = 0; i < cpuidx; i++ )
    {
        cpumask_set_cpu(i, &cpu_possible_map);
        cpu_logical_map(i) = tmp_map[i];
    }
}

/* C entry point for boot CPU */
void __init start_xen(unsigned long boot_phys_offset,
                      unsigned long fdt_paddr,
                      unsigned long cpuid)
{
    size_t fdt_size;
    int cpus, i;

    setup_cache();

    percpu_init_areas();
    set_processor_id(0); /* needed early, for smp_processor_id() */

    smp_clear_cpu_maps();

    device_tree_flattened = (void *)BOOT_MISC_VIRT_START
        + (fdt_paddr & ((1 << SECOND_SHIFT) - 1));
    fdt_size = device_tree_early_init(device_tree_flattened);

    cmdline_parse(device_tree_bootargs(device_tree_flattened));

    setup_pagetables(boot_phys_offset, get_xen_paddr());
    setup_mm(fdt_paddr, fdt_size);

    vm_init();
    dt_unflatten_host_device_tree();
    dt_irq_xlate = gic_irq_xlate;

    dt_uart_init();
    console_init_preirq();

    system_state = SYS_STATE_boot;

    processor_id();

    init_cpus_maps();
    cpus = smp_get_max_cpus();

    platform_init();

    init_xen_time();

    gic_init();
    make_cpus_ready(cpus, boot_phys_offset);

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
            panic("Error creating domain 0\n");

    dom0->is_privileged = 1;
    dom0->target = NULL;

    if ( construct_dom0(dom0) != 0)
            panic("Could not set up DOM0 guest OS\n");

    /* Scrub RAM that is still free and so may go to an unprivileged domain.
       XXX too slow in simulator
       scrub_heap_pages();
    */

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
