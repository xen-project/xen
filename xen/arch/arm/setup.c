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
#include <xen/init.h>
#include <xen/irq.h>
#include <xen/mm.h>
#include <xen/softirq.h>
#include <xen/keyhandler.h>
#include <xen/cpu.h>
#include <asm/page.h>
#include <asm/current.h>
#include <asm/setup.h>
#include "gic.h"

/* maxcpus: maximum number of CPUs to activate. */
static unsigned int __initdata max_cpus = NR_CPUS;

/* Xen stack for bringing up the first CPU. */
unsigned char init_stack[STACK_SIZE] __attribute__((__aligned__(STACK_SIZE)));

extern char __init_begin[], __init_end[], __bss_start[];

static __attribute_used__ void init_done(void)
{
    /* TODO: free (or page-protect) the init areas.
       memset(__init_begin, 0xcc, __init_end - __init_begin);
       free_xen_data(__init_begin, __init_end);
    */
    printk("Freed %ldkB init memory.\n", (long)(__init_end-__init_begin)>>10);

    startup_cpu_idle_loop();
}

static void __init init_idle_domain(void)
{
        scheduler_init();
        set_current(idle_vcpu[0]);
        this_cpu(curr_vcpu) = current;
        /* TODO: setup_idle_pagetable(); */
}

static void __init setup_mm(unsigned long dtb_paddr, size_t dtb_size)
{
    paddr_t ram_start;
    paddr_t ram_end;
    paddr_t ram_size;
    unsigned long ram_pages;
    unsigned long heap_pages, xenheap_pages, domheap_pages;
    unsigned long dtb_pages;
    unsigned long boot_mfn_start, boot_mfn_end;

    /*
     * TODO: only using the first RAM bank for now.  The heaps and the
     * frame table assume RAM is physically contiguous.
     */
    ram_start = early_info.mem.bank[0].start;
    ram_size  = early_info.mem.bank[0].size;
    ram_end = ram_start + ram_size;
    ram_pages = ram_size >> PAGE_SHIFT;

    /*
     * Calculate the sizes for the heaps using these constraints:
     *
     *  - heaps must be 32 MiB aligned
     *  - must not include Xen itself
     *  - xen heap must be at most 1 GiB
     *
     * XXX: needs a platform with at least 1GiB of RAM or the dom
     * heap will be empty and no domains can be created.
     */
    heap_pages = (ram_size >> PAGE_SHIFT) - (32 << (20 - PAGE_SHIFT));
    xenheap_pages = min(1ul << (30 - PAGE_SHIFT), heap_pages);
    domheap_pages = heap_pages - xenheap_pages;

    printk("Xen heap: %lu pages  Dom heap: %lu pages\n", xenheap_pages, domheap_pages);

    setup_xenheap_mappings(ram_start >> PAGE_SHIFT, xenheap_pages);

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
    device_tree_flattened = mfn_to_virt(alloc_boot_pages(dtb_pages, 1));
    copy_from_paddr(device_tree_flattened, dtb_paddr, dtb_size);

    /* Add non-xenheap memory */
    init_boot_pages(pfn_to_paddr(xenheap_mfn_start + xenheap_pages),
                    pfn_to_paddr(xenheap_mfn_start + xenheap_pages + domheap_pages));

    setup_frametable_mappings(ram_start, ram_end);

    /* Add xenheap memory that was not already added to the boot
       allocator. */
    init_xenheap_pages(pfn_to_paddr(xenheap_mfn_start),
                       pfn_to_paddr(boot_mfn_start));

    end_boot_allocator();
}

void __init start_xen(unsigned long boot_phys_offset,
                      unsigned long arm_type,
                      unsigned long atag_paddr)

{
    void *fdt;
    size_t fdt_size;
    int i;

    fdt = (void *)BOOT_MISC_VIRT_START
        + (atag_paddr & ((1 << SECOND_SHIFT) - 1));
    fdt_size = device_tree_early_init(fdt);

    setup_pagetables(boot_phys_offset);

#ifdef EARLY_UART_ADDRESS
    /* Map the UART */
    /* TODO Need to get device tree or command line for UART address */
    set_fixmap(FIXMAP_CONSOLE, EARLY_UART_ADDRESS >> PAGE_SHIFT, DEV_SHARED);
    pl011_init(0, FIXMAP_ADDR(FIXMAP_CONSOLE));
    console_init_preirq();
#endif

    set_current((struct vcpu *)0xfffff000); /* debug sanity */
    idle_vcpu[0] = current;
    set_processor_id(0); /* needed early, for smp_processor_id() */

    /* TODO: smp_prepare_boot_cpu(void) */
    cpumask_set_cpu(smp_processor_id(), &cpu_online_map);
    cpumask_set_cpu(smp_processor_id(), &cpu_present_map);

    smp_prepare_cpus(max_cpus);

    init_xen_time();

    setup_mm(atag_paddr, fdt_size);

    /* Setup Hyp vector base */
    WRITE_CP32((uint32_t) hyp_traps_vector, HVBAR);
    printk("Set hyp vector base to %"PRIx32" (expected %p)\n",
           READ_CP32(HVBAR), hyp_traps_vector);

    /* Setup Stage 2 address translation */
    /* SH0=00, ORGN0=IRGN0=01
     * SL0=01 (Level-1)
     * T0SZ=(1)1000 = -8 (40 bit physical addresses)
     */
    WRITE_CP32(0x80002558, VTCR); isb();

    softirq_init();
    tasklet_subsys_init();

    init_IRQ();

    gic_init();

    gic_route_irqs();

    init_maintenance_interrupt();
    init_timer_interrupt();

    timer_init();

    init_idle_domain();

    rcu_init();

    local_irq_enable();

    initialize_keytable();

    console_init_postirq();

    do_presmp_initcalls();

    for_each_present_cpu ( i )
    {
        if ( (num_online_cpus() < max_cpus) && !cpu_online(i) )
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
    if ( dom0 == NULL )
            printk("domain_create failed\n");
    if ( (dom0 == NULL) || (alloc_dom0_vcpu0() == NULL) )
            panic("Error creating domain 0\n");

    dom0->is_privileged = 1;
    dom0->target = NULL;

    if ( construct_dom0(dom0) != 0)
            panic("Could not set up DOM0 guest OS\n");

    /* Scrub RAM that is still free and so may go to an unprivileged domain.
       XXX too slow in simulator
       scrub_heap_pages();
    */

    console_endboot();

    /* Hide UART from DOM0 if we're using it */
    serial_endboot();

    domain_unpause_by_systemcontroller(dom0);

    reset_stack_and_jump(init_done);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
