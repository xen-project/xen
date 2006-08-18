/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
#include <acm/acm_hooks.h>
#include <public/version.h>
#include <asm/processor.h>
#include <asm/desc.h>
#include <asm/cache.h>
#include <asm/debugger.h>
#include <asm/delay.h>
#include <asm/percpu.h>
#include "exceptions.h"
#include "of-devtree.h"

#define DEBUG
unsigned long xenheap_phys_end;

/* opt_noht: If true, Hyperthreading is ignored. */
int opt_noht = 0;
boolean_param("noht", opt_noht);

int opt_earlygdb = 0;
boolean_param("earlygdb", opt_earlygdb);

u32 tlbflush_clock = 1U;
DEFINE_PER_CPU(u32, tlbflush_time);

unsigned int watchdog_on;
unsigned long wait_init_idle;
ulong oftree;
ulong oftree_len;
ulong oftree_end;

cpumask_t cpu_sibling_map[NR_CPUS] __read_mostly;
cpumask_t cpu_online_map; /* missing ifdef in schedule.c */

/* XXX get this from ISA node in device tree */
ulong isa_io_base;
struct ns16550_defaults ns16550;

extern char __per_cpu_start[], __per_cpu_data_end[], __per_cpu_end[];
extern void idle_loop(void);

/* move us to a header file */
extern void initialize_keytable(void);

int is_kernel_text(unsigned long addr)
{
    if (addr >= (unsigned long) &_start &&
        addr <= (unsigned long) &_etext)
        return 1;
    return 0;
}

unsigned long kernel_text_end(void)
{
    return (unsigned long) &_etext;
}

void idle_loop(void)
{
    int cpu = smp_processor_id();

    for ( ; ; )
    {
        while (!softirq_pending(cpu)) {
            void sleep(void);
            page_scrub_schedule_work();
            sleep();
        }
        do_softirq();
    }
}

static void __init do_initcalls(void)
{
    initcall_t *call;
    for (call = &__initcall_start; call < &__initcall_end; call++) {
        (*call)();
    }
}

static void hw_probe_attn(unsigned char key, struct cpu_user_regs *regs)
{
    /* To continue the probe will step over the ATTN instruction.  The
     * NOP is there to make sure there is something sane to "step
     * over" to. */
    asm volatile(".long 0x00000200; nop");
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
    struct domain *idle_domain;

    init_IRQ();

    scheduler_init();

    /* create idle domain */
    idle_domain = domain_create(IDLE_DOMAIN_ID);
    if ((idle_domain == NULL) || (alloc_vcpu(idle_domain, 0, 0) == NULL))
        BUG();
    set_current(idle_domain->vcpu[0]);
    idle_vcpu[0] = current;

    /* for some reason we need to set our own bit in the thread map */
    cpu_set(0, cpu_sibling_map[0]);

    percpu_free_unused_areas();

    initialize_keytable();
    /* Register another key that will allow for the the Harware Probe
     * to be contacted, this works with RiscWatch probes and should
     * work with Chronos and FSPs */
    register_irq_keyhandler('^', hw_probe_attn,   "Trap to Hardware Probe");

    timer_init();
    serial_init_postirq();
    do_initcalls();
    schedulers_start();
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

static ulong free_xenheap(ulong start, ulong end)
{
    start = ALIGN_UP(start, PAGE_SIZE);
    end = ALIGN_DOWN(end, PAGE_SIZE);

    printk("%s: 0x%lx - 0x%lx\n", __func__, start, end);

    if (oftree <= end && oftree >= start) {
        printk("%s:     Go around the devtree: 0x%lx - 0x%lx\n",
                  __func__, oftree, oftree_end);
        init_xenheap_pages(start, ALIGN_DOWN(oftree, PAGE_SIZE));
        init_xenheap_pages(ALIGN_UP(oftree_end, PAGE_SIZE), end);
    } else {
        init_xenheap_pages(start, end);
    }
    return ALIGN_UP(end, PAGE_SIZE);
}

static void __init __start_xen(multiboot_info_t *mbi)
{
    char *cmdline;
    module_t *mod = (module_t *)((ulong)mbi->mods_addr);
    ulong heap_start;
    ulong eomem = 0;
    ulong heap_size = 0;
    ulong bytes = 0;
    ulong freemem;
    ulong dom0_start, dom0_len;
    ulong initrd_start, initrd_len;
    
    int i;

    memcpy(0, exception_vectors, exception_vectors_end - exception_vectors);
    synchronize_caches(0, exception_vectors_end - exception_vectors);

    ticks_per_usec = timebase_freq / 1000000ULL;

    /* Parse the command-line options. */
    if ((mbi->flags & MBI_CMDLINE) && (mbi->cmdline != 0))
        cmdline_parse(__va((ulong)mbi->cmdline));

    /* We initialise the serial devices very early so we can get debugging. */
    ns16550.io_base = 0x3f8;
    ns16550_init(0, &ns16550);
    ns16550.io_base = 0x2f8;
    ns16550_init(1, &ns16550);
    serial_init_preirq();

    init_console();
#ifdef CONSOLE_SYNC
    console_start_sync();
#endif

    /* Check that we have at least one Multiboot module. */
    if (!(mbi->flags & MBI_MODULES) || (mbi->mods_count == 0)) {
        panic("FATAL ERROR: Require at least one Multiboot module.\n");
    }

    if (!(mbi->flags & MBI_MEMMAP)) {
        panic("FATAL ERROR: Bootloader provided no memory information.\n");
    }

    /* OF dev tree is the last module */
    oftree = mod[mbi->mods_count-1].mod_start;
    oftree_end = mod[mbi->mods_count-1].mod_end;
    oftree_len = oftree_end - oftree;

    /* remove it from consideration */
    mod[mbi->mods_count-1].mod_start = 0;
    mod[mbi->mods_count-1].mod_end = 0;
    --mbi->mods_count;

    printk("Physical RAM map:\n");

    /* lets find out how much memory there is */
    while (bytes < mbi->mmap_length) {
        u64 end;
        u64 addr;
        u64 size;

        memory_map_t *map = (memory_map_t *)((ulong)mbi->mmap_addr + bytes);
        addr = ((u64)map->base_addr_high << 32) | (u64)map->base_addr_low;
        size = ((u64)map->length_high << 32) | (u64)map->length_low;
        end = addr + size;

        printk(" %016lx - %016lx (usable)\n", addr, end);

        if (addr > eomem) {
            printk("found a hole skipping remainder of memory at:\n"
                   " %016lx and beyond\n", addr);
            break;
        }
        if (end > eomem) {
            eomem = end;
        }
        bytes += map->size + 4;
    }

    printk("System RAM: %luMB (%lukB)\n", eomem >> 20, eomem >> 10);

    /* top of memory */
    max_page = PFN_DOWN(ALIGN_DOWN(eomem, PAGE_SIZE));
    total_pages = max_page;

    /* Architecturally the first 4 pages are exception hendlers, we
     * will also be copying down some code there */
    heap_start = 4 << PAGE_SHIFT;
    if (oftree < (ulong)_start)
        heap_start = ALIGN_UP(oftree_end, PAGE_SIZE);

    heap_start = init_boot_allocator(heap_start);
    if (heap_start > (ulong)_start) {
        panic("space below _start (%p) is not enough memory "
              "for heap (0x%lx)\n", _start, heap_start);
    }

    /* we give the first RMA to the hypervisor */
    xenheap_phys_end = rma_size(cpu_rma_order());

    /* allow everything else to be allocated */
    init_boot_pages(xenheap_phys_end, eomem);
    init_frametable();
    end_boot_allocator();

    /* Add memory between the beginning of the heap and the beginning
     * of out text */
    free_xenheap(heap_start, (ulong)_start);
    freemem = ALIGN_UP((ulong)_end, PAGE_SIZE);

    for (i = 0; i < mbi->mods_count; i++) {
        u32 s;

        if(mod[i].mod_end == mod[i].mod_start)
            continue;

        s = ALIGN_DOWN(mod[i].mod_start, PAGE_SIZE);

        if (mod[i].mod_start > (ulong)_start &&
            mod[i].mod_start < (ulong)_end) {
            /* mod was linked in */
            continue;
        }

        if (s < freemem) 
            panic("module addresses must assend\n");

        free_xenheap(freemem, s);
        freemem = ALIGN_UP(mod[i].mod_end, PAGE_SIZE);
        
    }

    /* the rest of the xenheap, starting at the end of modules */
    free_xenheap(freemem, xenheap_phys_end);


#ifdef OF_DEBUG
    printk("ofdump:\n");
    /* make sure the OF devtree is good */
    ofd_walk((void *)oftree, OFD_ROOT, ofd_dump_props, OFD_DUMP_ALL);
#endif

    heap_size = xenheap_phys_end - heap_start;

    printk("Xen heap: %luMB (%lukB)\n", heap_size >> 20, heap_size >> 10);

    percpu_init_areas();

    cpu_initialize();

#ifdef CONFIG_GDB
    initialise_gdb();
    if (opt_earlygdb)
        debugger_trap_immediate();
#endif

    start_of_day();

    /* Create initial domain 0. */
    dom0 = domain_create(0);
    if ((dom0 == NULL) || (alloc_vcpu(dom0, 0, 0) == NULL))
        panic("Error creating domain 0\n");

    set_bit(_DOMF_privileged, &dom0->domain_flags);
    /* post-create hooks sets security label */
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

    free_xenheap(ALIGN_UP(dom0_start, PAGE_SIZE),
                 ALIGN_DOWN(dom0_start + dom0_len, PAGE_SIZE));
    if (initrd_start)
        free_xenheap(ALIGN_UP(initrd_start, PAGE_SIZE),
                     ALIGN_DOWN(initrd_start + initrd_len, PAGE_SIZE));

    init_trace_bufs();

    console_endboot();

    /* Hide UART from DOM0 if we're using it */
    serial_endboot();

    domain_unpause_by_systemcontroller(dom0);

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
        trap();
    }

    __start_xen(mbi);

}

extern void arch_get_xen_caps(xen_capabilities_info_t info);
void arch_get_xen_caps(xen_capabilities_info_t info)
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
