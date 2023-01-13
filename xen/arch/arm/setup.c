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
#include <xen/llc-coloring.h>
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
#include <xen/version.h>
#include <xen/vmap.h>
#include <xen/trace.h>
#include <xen/libfdt/libfdt-xen.h>
#include <xen/acpi.h>
#include <xen/warning.h>
#include <xen/hypercall.h>
#include <asm/alternative.h>
#include <asm/dom0less-build.h>
#include <asm/page.h>
#include <asm/static-evtchn.h>
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

/*
 * Sanitized version of cpuinfo containing only features available on all
 * cores (only on arm64 as there is no sanitization support on arm32).
 */
struct cpuinfo_arm __read_mostly system_cpuinfo;

#ifdef CONFIG_ACPI
bool __read_mostly acpi_disabled;
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
    printk("    Extensions:%s%s%s%s\n",
           cpu_has_fp ? " FloatingPoint" : "",
           cpu_has_simd ? " AdvancedSIMD" : "",
           cpu_has_gicv3 ? " GICv3-SysReg" : "",
           cpu_has_sve ? " SVE" : "");

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

void __init discard_initial_modules(void)
{
    struct bootmodules *mi = &bootinfo.modules;
    int i;

    /*
     * When using static heap feature, don't give bootmodules memory back to
     * the heap allocator
     */
    if ( using_static_heap )
        goto out;

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

 out:
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

void __init init_pdx(void)
{
    const struct membanks *mem = bootinfo_get_mem();
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

    for ( bank = 0 ; bank < mem->nr_banks; bank++ )
    {
        bank_start = mem->bank[bank].start;
        bank_size = mem->bank[bank].size;

        mask |= bank_start | pdx_region_mask(bank_start, bank_size);
    }

    for ( bank = 0 ; bank < mem->nr_banks; bank++ )
    {
        bank_start = mem->bank[bank].start;
        bank_size = mem->bank[bank].size;

        if (~mask & pdx_region_mask(bank_start, bank_size))
            mask = 0;
    }

    pfn_pdx_hole_setup(mask >> PAGE_SHIFT);

    for ( bank = 0 ; bank < mem->nr_banks; bank++ )
    {
        bank_start = mem->bank[bank].start;
        bank_size = mem->bank[bank].size;
        bank_end = bank_start + bank_size;

        set_pdx_range(paddr_to_pfn(bank_start),
                      paddr_to_pfn(bank_end));
    }
}

size_t __read_mostly dcache_line_bytes;

/* C entry point for boot CPU */
void asmlinkage __init start_xen(unsigned long fdt_paddr)
{
    size_t fdt_size;
    const char *cmdline;
    struct bootmodule *xen_bootmodule;
    struct domain *d;
    int rc, i;

    dcache_line_bytes = read_dcache_line_bytes();

    percpu_init_areas();
    set_processor_id(0); /* needed early, for smp_processor_id() */

    /* Initialize traps early allow us to get backtrace when an error occurred */
    init_traps();

    smp_clear_cpu_maps();

    device_tree_flattened = early_fdt_map(fdt_paddr);
    if ( !device_tree_flattened )
        panic("Invalid device tree blob at physical address %#lx.\n"
              "The DTB must be 8-byte aligned and must not exceed 2 MB in size.\n\n"
              "Please check your bootloader.\n",
              fdt_paddr);

    /* Register Xen's load address as a boot module. */
    xen_bootmodule = add_boot_module(BOOTMOD_XEN,
                             virt_to_maddr(_start),
                             (paddr_t)(uintptr_t)(_end - _start), false);
    BUG_ON(!xen_bootmodule);

    fdt_size = boot_fdt_info(device_tree_flattened, fdt_paddr);

    cmdline = boot_fdt_cmdline(device_tree_flattened);
    printk("Command line: %s\n", cmdline);
    cmdline_parse(cmdline);

    llc_coloring_init();

    /*
     * Page tables must be setup after LLC coloring initialization because
     * coloring info are required in order to create colored mappings
     */
    setup_pagetables();
    /* Device-tree was mapped in boot page tables, remap it in the new tables */
    device_tree_flattened = early_fdt_map(fdt_paddr);

    setup_mm();

    vm_init();

    /* Parse the ACPI tables for possible boot-time configuration */
    acpi_boot_table_init();

    end_boot_allocator();

    /*
     * The memory subsystem has been initialized, we can now switch from
     * early_boot -> boot.
     */
    system_state = SYS_STATE_boot;

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

    uart_init();
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
#ifdef CONFIG_HAS_ALTERNATIVE
    apply_alternatives_all();
#endif
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

static int __init init_xen_cap_info(void)
{
    /* Interface name is always xen-3.0-* for Xen-3.x. */

#ifdef CONFIG_ARM_64
    safe_strcat(xen_cap_info, "xen-3.0-aarch64 ");
#endif
    if ( cpu_has_aarch32 )
        safe_strcat(xen_cap_info, "xen-3.0-armv7l ");

    return 0;
}
__initcall(init_xen_cap_info);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
