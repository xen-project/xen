/******************************************************************************
 * kernel.c
 * 
 * This file should contain architecture-independent bootstrap and low-level
 * help routines. It's a bit x86/PC specific right now!
 * 
 * Copyright (c) 2002-2003 K A Fraser
 */

#include <stdarg.h>
#include <xen/config.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/spinlock.h>
#include <xen/multiboot.h>
#include <xen/sched.h>
#include <xen/mm.h>
#include <xen/delay.h>
#include <xen/compile.h>
#include <xen/console.h>
#include <xen/serial.h>
#include <xen/shadow.h>
#include <xen/trace.h>
#include <asm/io.h>
#include <asm/msr.h>
#include <asm/uaccess.h>
#include <asm/domain_page.h>
#include <hypervisor-ifs/dom0_ops.h>

kmem_cache_t *domain_struct_cachep;

struct e820entry {
    unsigned long addr_lo, addr_hi;        /* start of memory segment */
    unsigned long size_lo, size_hi;        /* size of memory segment */
    unsigned long type;                    /* type of memory segment */
};

void start_of_day(void);

/* opt_console: comma-separated list of console outputs. */
unsigned char opt_console[30] = "com1,vga";
/* opt_com[12]: Config serial port with a string <baud>,DPS,<io-base>,<irq>. */
unsigned char opt_com1[30] = "", opt_com2[30] = "";
/* opt_dom0_mem: Kilobytes of memory allocated to domain 0. */
unsigned int opt_dom0_mem = 16000;
/* opt_noht: If true, Hyperthreading is ignored. */
int opt_noht=0;
/* opt_noacpi: If true, ACPI tables are not parsed. */
int opt_noacpi=0;
/* opt_nosmp: If true, secondary processors are ignored. */
int opt_nosmp=0;
/* opt_noreboot: If true, machine will need manual reset on error. */
int opt_noreboot=0;
/* opt_ignorebiostables: If true, ACPI and MP tables are ignored. */
/* NB. This flag implies 'nosmp' and 'noacpi'. */
int opt_ignorebiostables=0;
/* opt_watchdog: If true, run a watchdog NMI on each processor. */
int opt_watchdog=0;
/* opt_pdb: Name of serial port for Xen pervasive debugger (and enable pdb) */
unsigned char opt_pdb[10] = "none";
/* opt_tbuf_size: trace buffer size (in pages) */
unsigned int opt_tbuf_size = 1;
/* opt_sched: scheduler - default to Borrowed Virtual Time */
char opt_sched[10] = "bvt";
/* opt_physdev_dom0_hide: list of PCI slots to hide from domain 0. */
/* Format is '(%02x:%02x.%1x)(%02x:%02x.%1x)' and so on. */
char opt_physdev_dom0_hide[200] = "";
/* opt_leveltrigger, opt_edgetrigger: Force an IO-APIC-routed IRQ to be */
/*                                    level- or edge-triggered.         */
/* Example: 'leveltrigger=4,5,6,20 edgetrigger=21'. */
char opt_leveltrigger[30] = "", opt_edgetrigger[30] = "";

static struct {
    unsigned char *name;
    enum { OPT_STR, OPT_UINT, OPT_BOOL } type;
    void *var;
} opts[] = {
    { "console",           OPT_STR,  &opt_console },
    { "com1",              OPT_STR,  &opt_com1 },
    { "com2",              OPT_STR,  &opt_com2 },
    { "dom0_mem",          OPT_UINT, &opt_dom0_mem }, 
    { "noht",              OPT_BOOL, &opt_noht },
    { "noacpi",            OPT_BOOL, &opt_noacpi },
    { "nosmp",             OPT_BOOL, &opt_nosmp },
    { "noreboot",          OPT_BOOL, &opt_noreboot },
    { "ignorebiostables",  OPT_BOOL, &opt_ignorebiostables },
    { "watchdog",          OPT_BOOL, &opt_watchdog },
    { "pdb",               OPT_STR,  &opt_pdb },
    { "tbuf_size",         OPT_UINT, &opt_tbuf_size },
    { "sched",             OPT_STR,  &opt_sched },
    { "physdev_dom0_hide", OPT_STR,  &opt_physdev_dom0_hide },
    { "leveltrigger",      OPT_STR,  &opt_leveltrigger },
    { "edgetrigger",       OPT_STR,  &opt_edgetrigger },
    { NULL,               0,        NULL     }
};


void cmain(unsigned long magic, multiboot_info_t *mbi)
{
    struct domain *new_dom;
    unsigned long max_page;
    unsigned char *cmdline;
    module_t *mod = (module_t *)__va(mbi->mods_addr);
    void *heap_start;
    int i;
    unsigned long max_mem;
    unsigned long dom0_memory_start, dom0_memory_end;
    unsigned long initial_images_start, initial_images_end;

    /* Parse the command-line options. */
    cmdline = (unsigned char *)(mbi->cmdline ? __va(mbi->cmdline) : NULL);
    if ( cmdline != NULL )
    {
        unsigned char *opt_end, *opt;
        while ( *cmdline == ' ' ) cmdline++;
        cmdline = strchr(cmdline, ' ');
        while ( cmdline != NULL )
        {
            while ( *cmdline == ' ' ) cmdline++;
            if ( *cmdline == '\0' ) break;
            opt_end = strchr(cmdline, ' ');
            if ( opt_end != NULL ) *opt_end++ = '\0';
            opt = strchr(cmdline, '=');
            if ( opt != NULL ) *opt++ = '\0';
            for ( i = 0; opts[i].name != NULL; i++ )
            {
                if ( strcmp(opts[i].name, cmdline ) != 0 ) continue;
                switch ( opts[i].type )
                {
                case OPT_STR:
                    if ( opt != NULL )
                        strcpy(opts[i].var, opt);
                    break;
                case OPT_UINT:
                    if ( opt != NULL )
                        *(unsigned int *)opts[i].var =
                            simple_strtol(opt, (char **)&opt, 0);
                    break;
                case OPT_BOOL:
                    *(int *)opts[i].var = 1;
                    break;
                }
            }
            cmdline = opt_end;
        }
    }

    /* We initialise the serial devices very early so we can get debugging. */
    serial_init_stage1();

    init_console();

    /* HELLO WORLD --- start-of-day banner text. */
    printk(XEN_BANNER);
    printk(" http://www.cl.cam.ac.uk/netos/xen\n");
    printk(" University of Cambridge Computer Laboratory\n\n");
    printk(" Xen version %d.%d%s (%s@%s) (%s) %s\n\n",
           XEN_VERSION, XEN_SUBVERSION, XEN_EXTRAVERSION,
           XEN_COMPILE_BY, XEN_COMPILE_DOMAIN,
           XEN_COMPILER, XEN_COMPILE_DATE);
    set_printk_prefix("(XEN) ");

    if ( magic != MULTIBOOT_BOOTLOADER_MAGIC )
    {
        printk("FATAL ERROR: Invalid magic number: 0x%08lx\n", magic);
        for ( ; ; ) ;
    }

    /* We require memory and module information. */
    if ( (mbi->flags & 9) != 9 )
    {
        printk("FATAL ERROR: Bad flags passed by bootloader: 0x%x\n", 
               (unsigned)mbi->flags);
        for ( ; ; ) ;
    }

    if ( mbi->mods_count == 0 )
    {
        printk("Require at least one Multiboot module!\n");
        for ( ; ; ) ;
    }

    max_mem = max_page = (mbi->mem_upper+1024) >> (PAGE_SHIFT - 10);

    /* The array of pfn_info structures must fit into the reserved area. */
    if ( (sizeof(struct pfn_info) * max_page) >
         (FRAMETABLE_VIRT_END - FRAMETABLE_VIRT_START) )
    {
        unsigned long new_max =
            (FRAMETABLE_VIRT_END - FRAMETABLE_VIRT_START) /
            sizeof(struct pfn_info);
        printk("Truncating available memory to %lu/%luMB\n",
               new_max >> (20 - PAGE_SHIFT), max_page >> (20 - PAGE_SHIFT));
        max_page = new_max;
    }

    set_current(&idle0_task);

    init_frametable(max_page);
    printk("Initialised %luMB memory (%lu pages) on a %luMB machine\n",
           max_page >> (20-PAGE_SHIFT), max_page,
	   max_mem  >> (20-PAGE_SHIFT));

    initial_images_start = MAX_DIRECTMAP_ADDRESS;
    initial_images_end   = initial_images_start + 
        (mod[mbi->mods_count-1].mod_end - mod[0].mod_start);
    dom0_memory_start    = (initial_images_end + ((4<<20)-1)) & ~((4<<20)-1);
    dom0_memory_end      = dom0_memory_start + (opt_dom0_mem << 10);
    dom0_memory_end      = (dom0_memory_end + PAGE_SIZE - 1) & PAGE_MASK;
    
    /* Cheesy sanity check: enough memory for DOM0 allocation + some slack? */
    if ( (dom0_memory_end + (8<<20)) > (max_page<<PAGE_SHIFT) )
        panic("Not enough memory to craete initial domain!\n");

    add_to_domain_alloc_list(dom0_memory_end, max_page << PAGE_SHIFT);

    heap_start = memguard_init(&_end);

    printk("Xen heap size is %luKB\n", 
	   (MAX_XENHEAP_ADDRESS-__pa(heap_start))/1024 );

    if ( ((MAX_XENHEAP_ADDRESS-__pa(heap_start))/1024) <= 4096 )
    {
        printk("Xen heap size is too small to safely continue!\n");
        for ( ; ; ) ;
    }

    init_page_allocator(__pa(heap_start), MAX_XENHEAP_ADDRESS);
 
    /* Initialise the slab allocator. */
    kmem_cache_init();
    kmem_cache_sizes_init(max_page);

    domain_struct_cachep = kmem_cache_create(
        "domain_cache", sizeof(struct domain),
        0, SLAB_HWCACHE_ALIGN, NULL, NULL);
    if ( domain_struct_cachep == NULL )
        panic("No slab cache for task structs.");

    start_of_day();

    /* Add CPU0 idle task to the task hash list */
    task_hash[TASK_HASH(IDLE_DOMAIN_ID)] = &idle0_task;

    /* Create initial domain 0. */
    new_dom = do_createdomain(0, 0);
    if ( new_dom == NULL )
        panic("Error creating domain 0\n");

    set_bit(DF_PRIVILEGED, &new_dom->flags);

    shadow_mode_init();

    /*
     * We're going to setup domain0 using the module(s) that we stashed safely
     * above our MAX_DIRECTMAP_ADDRESS in boot/boot.S. The second module, if
     * present, is an initrd ramdisk.
     */
    if ( construct_dom0(new_dom, dom0_memory_start, dom0_memory_end,
                        (char *)initial_images_start, 
                        mod[0].mod_end-mod[0].mod_start,
                        (mbi->mods_count == 1) ? 0 :
                        (char *)initial_images_start + 
                        (mod[1].mod_start-mod[0].mod_start),
                        (mbi->mods_count == 1) ? 0 :
                        mod[mbi->mods_count-1].mod_end - mod[1].mod_start,
                        __va(mod[0].string)) != 0)
        panic("Could not set up DOM0 guest OS\n");

    /* The stash space for the initial kernel image can now be freed up. */
    add_to_domain_alloc_list(__pa(frame_table) + frame_table_size,
                             dom0_memory_start);

    init_trace_bufs();

    domain_unpause_by_systemcontroller(current);
    domain_unpause_by_systemcontroller(new_dom);
    startup_cpu_idle_loop();
}

/*
 * Simple hypercalls.
 */

long do_xen_version(int cmd)
{
    if ( cmd != 0 )
        return -ENOSYS;
    return (XEN_VERSION<<16) | (XEN_SUBVERSION);
}

long do_ni_hypercall(void)
{
    /* No-op hypercall. */
    return -ENOSYS;
}
