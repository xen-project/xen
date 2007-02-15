/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) IBM Corp. 2005, 2006
 *
 * Authors: Jimi Xenidis <jimix@watson.ibm.com>
 *          Amos Waterland <apw@us.ibm.com>
 *          Hollis Blanchard <hollisb@us.ibm.com>
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/cpumask.h>
#include <xen/sched.h>
#include <xen/multiboot.h>
#include <xen/serial.h>
#include <xen/softirq.h>
#include <xen/console.h>
#include <xen/trace.h>
#include <xen/mm.h>
#include <xen/domain.h>
#include <xen/gdbstub.h>
#include <xen/symbols.h>
#include <xen/keyhandler.h>
#include <xen/numa.h>
#include <xen/rcupdate.h>
#include <acm/acm_hooks.h>
#include <public/version.h>
#include <asm/mpic.h>
#include <asm/processor.h>
#include <asm/desc.h>
#include <asm/cache.h>
#include <asm/debugger.h>
#include <asm/delay.h>
#include <asm/percpu.h>
#include <asm/io.h>
#include "exceptions.h"
#include "of-devtree.h"
#include "oftree.h"
#include "rtas.h"

#define DEBUG

/* opt_noht: If true, Hyperthreading is ignored. */
int opt_noht = 0;
boolean_param("noht", opt_noht);

int opt_earlygdb = 0;
boolean_param("earlygdb", opt_earlygdb);

/* opt_nosmp: If true, secondary processors are ignored. */
static int opt_nosmp = 0;
boolean_param("nosmp", opt_nosmp);

/* maxcpus: maximum number of CPUs to activate. */
static unsigned int max_cpus = NR_CPUS;
integer_param("maxcpus", max_cpus);

u32 tlbflush_clock = 1U;
DEFINE_PER_CPU(u32, tlbflush_time);

unsigned int watchdog_on;
unsigned long wait_init_idle;
ulong oftree;
ulong oftree_len;
ulong oftree_end;

uint cpu_hard_id[NR_CPUS] __initdata;
cpumask_t cpu_present_map;

/* XXX get this from ISA node in device tree */
char *vgabase;
ulong isa_io_base;
struct ns16550_defaults ns16550;

extern char __per_cpu_start[], __per_cpu_data_end[], __per_cpu_end[];

static struct domain *idle_domain;

volatile struct processor_area * volatile global_cpu_table[NR_CPUS];

static void __init do_initcalls(void)
{
    initcall_t *call;
    for (call = &__initcall_start; call < &__initcall_end; call++) {
        (*call)();
    }
}


void noinline __attn(void)
{
    /* To continue the probe will step over the ATTN instruction.  The
     * NOP is there to make sure there is something sane to "step
     * over" to. */
    console_start_sync();
    asm volatile(".long 0x200;nop");
    console_end_sync();
}

static void key_hw_probe_attn(unsigned char key)
{
    __attn();
}

static void key_ofdump(unsigned char key)
{
    printk("ofdump:\n");
    /* make sure the OF devtree is good */
    ofd_walk((void *)oftree, "devtree", OFD_ROOT,
             ofd_dump_props, OFD_DUMP_ALL);
}

static void percpu_init_areas(void)
{
    unsigned int i, data_size = __per_cpu_data_end - __per_cpu_start;

    BUG_ON(data_size > PERCPU_SIZE);

    for ( i = 1; i < NR_CPUS; i++ )
        memcpy(__per_cpu_start + (i << PERCPU_SHIFT),
               __per_cpu_start,
               data_size);
}

static void percpu_free_unused_areas(void)
{
    unsigned int i, first_unused;

    /* Find first unused CPU number. */
    for ( i = 0; i < NR_CPUS; i++ )
        if ( !cpu_online(i) )
            break;
    first_unused = i;

    /* Check that there are no holes in cpu_online_map. */
    for ( ; i < NR_CPUS; i++ )
        BUG_ON(cpu_online(i));

    init_xenheap_pages((ulong)__per_cpu_start + (first_unused << PERCPU_SHIFT),
                       (ulong)__per_cpu_end);
}

static void __init start_of_day(void)
{
    init_IRQ();

    scheduler_init();

    /* create idle domain */
    idle_domain = domain_create(IDLE_DOMAIN_ID, 0);
    if ((idle_domain == NULL) || (alloc_vcpu(idle_domain, 0, 0) == NULL))
        BUG();
    set_current(idle_domain->vcpu[0]);
    idle_vcpu[0] = current;

    initialize_keytable();
    /* Register another key that will allow for the the Harware Probe
     * to be contacted, this works with RiscWatch probes and should
     * work with Chronos and FSPs */
    register_keyhandler('^', key_hw_probe_attn, "Trap to Hardware Probe");

    /* allow the dumping of the devtree */
    register_keyhandler('D', key_ofdump , "Dump OF Devtree");

    timer_init();
    rcu_init();
    serial_init_postirq();
    do_initcalls();
}

void startup_cpu_idle_loop(void)
{
    struct vcpu *v = current;

    ASSERT(is_idle_vcpu(v));
    cpu_set(smp_processor_id(), v->domain->domain_dirty_cpumask);
    cpu_set(smp_processor_id(), v->vcpu_dirty_cpumask);

    /* Finally get off the boot stack. */
    reset_stack_and_jump(idle_loop);
}

/* The boot_pa is enough "parea" for the boot CPU to get thru
 * initialization, it will ultimately get replaced later */
static __init void init_boot_cpu(void)
{
    static struct processor_area boot_pa;
    boot_pa.whoami = 0;
    parea = &boot_pa;
}    

static void init_parea(int cpuid)
{
    /* Be careful not to shadow the global variable.  */
    volatile struct processor_area *pa;
    void *stack;

    pa = xmalloc(struct processor_area);
    if (pa == NULL)
        panic("%s: failed to allocate parea for cpu #%d\n", __func__, cpuid);

    stack = alloc_xenheap_pages(STACK_ORDER);
    if (stack == NULL)
        panic("%s: failed to allocate stack (order %d) for cpu #%d\n", 
              __func__, STACK_ORDER, cpuid);

    pa->whoami = cpuid;
    pa->hard_id = cpu_hard_id[cpuid];
    pa->hyp_stack_base = (void *)((ulong)stack + STACK_SIZE);
    mb();

    /* This store has the effect of invoking secondary_cpu_init.  */
    global_cpu_table[cpuid] = pa;
    mb();
}

static int kick_secondary_cpus(int maxcpus)
{
    int cpuid;

    for_each_present_cpu(cpuid) {
        int threads;
        int i;
        
        threads = cpu_threads(cpuid);
        for (i = 0; i < threads; i++)
            cpu_set(i, cpu_sibling_map[cpuid]);

        /* For now everything is single core */
        cpu_set(cpuid, cpu_core_map[cpuid]);

        rcu_online_cpu(cpuid);

        numa_set_node(cpuid, 0);
        numa_add_cpu(cpuid);

        if (cpuid == 0)
            continue;
        if (cpuid >= maxcpus)
            break;
        init_parea(cpuid);
        smp_generic_give_timebase();

        /* wait for it */
        while (!cpu_online(cpuid))
            cpu_relax();
    }

    return 0;
}

/* This is the first C code that secondary processors invoke.  */
void secondary_cpu_init(int cpuid, unsigned long r4)
{
    struct vcpu *vcpu;

    cpu_initialize(cpuid);
    smp_generic_take_timebase();

    /* If we are online, we must be able to ACK IPIs.  */
    mpic_setup_this_cpu();
    cpu_set(cpuid, cpu_online_map);

    vcpu = alloc_vcpu(idle_domain, cpuid, cpuid);
    BUG_ON(vcpu == NULL);

    set_current(idle_domain->vcpu[cpuid]);
    idle_vcpu[cpuid] = current;
    startup_cpu_idle_loop();

    panic("should never get here\n");
}

static void __init __start_xen(multiboot_info_t *mbi)
{
    char *cmdline;
    module_t *mod = (module_t *)((ulong)mbi->mods_addr);
    ulong dom0_start, dom0_len;
    ulong initrd_start, initrd_len;

    memcpy(0, exception_vectors, exception_vectors_end - exception_vectors);
    synchronize_caches(0, exception_vectors_end - exception_vectors);

    ticks_per_usec = timebase_freq / 1000000ULL;

    /* Parse the command-line options. */
    if ((mbi->flags & MBI_CMDLINE) && (mbi->cmdline != 0))
        cmdline_parse(__va((ulong)mbi->cmdline));

    /* we need to be able to identify this CPU early on */
    init_boot_cpu();

    /* We initialise the serial devices very early so we can get debugging. */
    ns16550.io_base = 0x3f8;
    ns16550_init(0, &ns16550);
    ns16550.io_base = 0x2f8;
    ns16550_init(1, &ns16550);
    serial_init_preirq();

    init_console();
    /* let synchronize until we really get going */
    console_start_sync();

    /* Check that we have at least one Multiboot module. */
    if (!(mbi->flags & MBI_MODULES) || (mbi->mods_count == 0)) {
        panic("FATAL ERROR: Require at least one Multiboot module.\n");
    }

    /* OF dev tree is the last module */
    oftree = mod[mbi->mods_count-1].mod_start;
    oftree_end = mod[mbi->mods_count-1].mod_end;
    oftree_len = oftree_end - oftree;

    /* remove it from consideration */
    mod[mbi->mods_count-1].mod_start = 0;
    mod[mbi->mods_count-1].mod_end = 0;
    --mbi->mods_count;

    if (rtas_entry) {
        rtas_init((void *)oftree);
        /* remove rtas module from consideration */
        mod[mbi->mods_count-1].mod_start = 0;
        mod[mbi->mods_count-1].mod_end = 0;
        --mbi->mods_count;
    }
    memory_init(mod, mbi->mods_count);

#ifdef OF_DEBUG
    key_ofdump(0);
#endif
    percpu_init_areas();

    init_parea(0);
    cpu_initialize(0);

#ifdef CONFIG_GDB
    initialise_gdb();
    if (opt_earlygdb)
        debugger_trap_immediate();
#endif

    start_of_day();

    mpic_setup_this_cpu();

    /* Deal with secondary processors.  */
    if (opt_nosmp || ofd_boot_cpu == -1) {
        printk("nosmp: leaving secondary processors spinning forever\n");
    } else {
        printk("spinning up at most %d total processors ...\n", max_cpus);
        kick_secondary_cpus(max_cpus);
    }

    /* Secondary processors must be online before we call this.  */
    schedulers_start();

    /* This cannot be called before secondary cpus are marked online.  */
    percpu_free_unused_areas();

    /* Create initial domain 0. */
    dom0 = domain_create(0, 0);
    if (dom0 == NULL)
        panic("Error creating domain 0\n");
    dom0->max_pages = ~0U;
    if (0 > allocate_rma(dom0, cpu_default_rma_order_pages()))
        panic("Error allocating domain 0 RMA\n");
    if (NULL == alloc_vcpu(dom0, 0, 0))
        panic("Error creating domain 0 vcpu 0\n");

    /* The Interrupt Controller will route everything to CPU 0 so we
     * need to make sure Dom0's vVCPU 0 is pinned to the CPU */
    dom0->vcpu[0]->cpu_affinity = cpumask_of_cpu(0);

    dom0->is_privileged = 1;

    /* Post-create hook sets security label. */
    acm_post_domain0_create(dom0->domain_id);

    cmdline = (char *)(mod[0].string ? __va((ulong)mod[0].string) : NULL);

    /* scrub_heap_pages() requires IRQs enabled, and we're post IRQ setup... */
    local_irq_enable();
    /* Scrub RAM that is still free and so may go to an unprivileged domain. */
    scrub_heap_pages();

    dom0_start = mod[0].mod_start;
    dom0_len = mod[0].mod_end - mod[0].mod_start;
    if (mbi->mods_count > 1) {
        initrd_start = mod[1].mod_start;
        initrd_len = mod[1].mod_end - mod[1].mod_start;
    } else {
        initrd_start = 0;
        initrd_len = 0;
    }
    if (construct_dom0(dom0, dom0_start, dom0_len,
                       initrd_start, initrd_len,
                       cmdline) != 0) {
        panic("Could not set up DOM0 guest OS\n");
    }

    init_xenheap_pages(ALIGN_UP(dom0_start, PAGE_SIZE),
                       ALIGN_DOWN(dom0_start + dom0_len, PAGE_SIZE));
    if (initrd_start)
        init_xenheap_pages(ALIGN_UP(initrd_start, PAGE_SIZE),
                           ALIGN_DOWN(initrd_start + initrd_len, PAGE_SIZE));

    init_trace_bufs();

    console_endboot();

    /* Hide UART from DOM0 if we're using it */
    serial_endboot();

    console_end_sync();

    domain_unpause_by_systemcontroller(dom0);
#ifdef DEBUG_IPI
    ipi_torture_test();
#endif
    startup_cpu_idle_loop();
}

void __init __start_xen_ppc(
    ulong r3, ulong r4, ulong r5, ulong r6, ulong r7, ulong orig_msr)
{
    multiboot_info_t *mbi = NULL;

    /* clear bss */
    memset(__bss_start, 0, (ulong)_end - (ulong)__bss_start);

    if (r5 > 0) {
        /* we were booted by OpenFirmware */
        mbi = boot_of_init(r3, r4, r5, r6, r7, orig_msr);

    } else {
        /* booted by someone else that hopefully has a trap handler */
        __builtin_trap();
    }

    __start_xen(mbi);

}

extern void arch_get_xen_caps(xen_capabilities_info_t *info);
void arch_get_xen_caps(xen_capabilities_info_t *info)
{
}



/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
