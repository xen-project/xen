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

static void __init __start_xen(multiboot_info_t *mbi)
{
    char *cmdline;
    module_t *mod = (module_t *)((ulong)mbi->mods_addr);
    ulong heap_start;
    ulong modules_start, modules_size;
    ulong eomem = 0;
    ulong heap_size = 0;
    ulong bytes = 0;
    ulong freemem = (ulong)_end;
    ulong oftree_end;

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

    /* mark the begining of images */
    modules_start = mod[0].mod_start;
    modules_size = mod[mbi->mods_count-1].mod_end - mod[0].mod_start;

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
    heap_start = init_boot_allocator(4 << PAGE_SHIFT);

    /* we give the first RMA to the hypervisor */
    xenheap_phys_end = rma_size(cpu_rma_order());

    /* allow everything else to be allocated */
    init_boot_pages(xenheap_phys_end, eomem);
    init_frametable();
    end_boot_allocator();

    /* Add memory between the beginning of the heap and the beginning
     * of out text */
    init_xenheap_pages(heap_start, (ulong)_start);

    /* move the modules to just after _end */
    if (modules_start) {
        printk("modules at: %016lx - %016lx\n", modules_start,
                modules_start + modules_size);
        freemem = ALIGN_UP(freemem, PAGE_SIZE);
        memmove((void *)freemem, (void *)modules_start, modules_size);

        oftree -= modules_start - freemem;
        modules_start = freemem;
        freemem += modules_size;
        printk("  moved to: %016lx - %016lx\n", modules_start,
                modules_start + modules_size);
    }

    /* the rest of the xenheap, starting at the end of modules */
    init_xenheap_pages(freemem, xenheap_phys_end);


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

    /*
     * We're going to setup domain0 using the module(s) that we
     * stashed safely above our heap. The second module, if present,
     * is an initrd ramdisk.  The last module is the OF devtree.
     */
    if (construct_dom0(dom0,
                       modules_start, 
                       mod[0].mod_end-mod[0].mod_start,
                       (mbi->mods_count == 1) ? 0 :
                       modules_start + 
                       (mod[1].mod_start-mod[0].mod_start),
                       (mbi->mods_count == 1) ? 0 :
                       mod[mbi->mods_count-1].mod_end - mod[1].mod_start,
                       cmdline) != 0) {
        panic("Could not set up DOM0 guest OS\n");
    }

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
