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

void __init start_xen(unsigned long boot_phys_offset,
                      unsigned long arm_type,
                      unsigned long atag_paddr)

{
    int i;

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

    /* TODO: This needs some thought, as well as device-tree mapping.
     * For testing, assume that the whole xenheap is contiguous in RAM */
    setup_xenheap_mappings(0x8000000, 0x40000); /* 1 GB @ 512GB */
    /* Must pass a single mapped page for populating bootmem_region_list. */
    init_boot_pages(pfn_to_paddr(xenheap_mfn_start),
                    pfn_to_paddr(xenheap_mfn_start+1));

    /* Add non-xenheap memory */
    init_boot_pages(0x8040000000, 0x80c0000000); /* 2 GB @513GB */

    /* TODO Make sure Xen's own pages aren't added
     *     -- the memory above doesn't include our relocation target.  */
    /* TODO Handle payloads too */

    /* TODO Need to find actual memory, for now use 4GB at 512GB */
    setup_frametable_mappings(0x8000000000ULL, 0x8100000000UL);

    /* Add xenheap memory */
    init_xenheap_pages(pfn_to_paddr(xenheap_mfn_start+1),
                       pfn_to_paddr(xenheap_mfn_end));

    end_boot_allocator();

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
