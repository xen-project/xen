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
#include <xen/trace.h>
#include <asm/shadow.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/domain_page.h>
#include <hypervisor-ifs/dom0_ops.h>

unsigned long xenheap_phys_end;

xmem_cache_t *domain_struct_cachep;

struct e820entry {
    unsigned long addr_lo, addr_hi;        /* start of memory segment */
    unsigned long size_lo, size_hi;        /* size of memory segment */
    unsigned long type;                    /* type of memory segment */
};

void start_of_day(void);

/* opt_console: comma-separated list of console outputs. */
unsigned char opt_console[30] = "com1,vga";
/* opt_conswitch: a character pair controlling console switching. */
/* Char 1: CTRL+<char1> is used to switch console input between Xen and DOM0 */
/* Char 2: If this character is 'x', then do not auto-switch to DOM0 when it */
/*         boots. Any other value, or omitting the char, enables auto-switch */
unsigned char opt_conswitch[5] = "a"; /* NB. '`' would disable switching. */
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
/* opt_pdb: Name of serial port for Xen debugger (and enable xendbg) */
unsigned char opt_xendbg[10] = "none";
/* opt_tbuf_size: trace buffer size (in pages) */
unsigned int opt_tbuf_size = 10;
/* opt_sched: scheduler - default to Borrowed Virtual Time */
char opt_sched[10] = "bvt";
/* opt_physdev_dom0_hide: list of PCI slots to hide from domain 0. */
/* Format is '(%02x:%02x.%1x)(%02x:%02x.%1x)' and so on. */
char opt_physdev_dom0_hide[200] = "";
/* opt_leveltrigger, opt_edgetrigger: Force an IO-APIC-routed IRQ to be */
/*                                    level- or edge-triggered.         */
/* Example: 'leveltrigger=4,5,6,20 edgetrigger=21'. */
char opt_leveltrigger[30] = "", opt_edgetrigger[30] = "";
/*
 * opt_xenheap_megabytes: Size of Xen heap in megabytes, excluding the
 * pfn_info table and allocation bitmap.
 */
unsigned int opt_xenheap_megabytes = XENHEAP_DEFAULT_MB;

static struct {
    unsigned char *name;
    enum { OPT_STR, OPT_UINT, OPT_BOOL } type;
    void *var;
} opts[] = {
    { "console",           OPT_STR,  &opt_console },
    { "conswitch",         OPT_STR,  &opt_conswitch },
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
    { "xendbg",            OPT_STR,  &opt_xendbg },
    { "tbuf_size",         OPT_UINT, &opt_tbuf_size },
    { "sched",             OPT_STR,  &opt_sched },
    { "physdev_dom0_hide", OPT_STR,  &opt_physdev_dom0_hide },
    { "leveltrigger",      OPT_STR,  &opt_leveltrigger },
    { "edgetrigger",       OPT_STR,  &opt_edgetrigger },
    { "xenheap_megabytes", OPT_UINT, &opt_xenheap_megabytes },
    { NULL,               0,        NULL     }
};


void initialize_xendbg(void);

void cmain(multiboot_info_t *mbi)
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

    initialize_xendbg();

    /* HELLO WORLD --- start-of-day banner text. */
    printk(XEN_BANNER);
    printk(" http://www.cl.cam.ac.uk/netos/xen\n");
    printk(" University of Cambridge Computer Laboratory\n\n");
    printk(" Xen version %d.%d%s (%s@%s) (%s) %s\n\n",
           XEN_VERSION, XEN_SUBVERSION, XEN_EXTRAVERSION,
           XEN_COMPILE_BY, XEN_COMPILE_DOMAIN,
           XEN_COMPILER, XEN_COMPILE_DATE);
    set_printk_prefix("(XEN) ");

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

    if ( opt_xenheap_megabytes < 4 )
    {
        printk("Xen heap size is too small to safely continue!\n");
        for ( ; ; ) ;
    }

    set_current(&idle0_task);

    xenheap_phys_end = opt_xenheap_megabytes << 20;

    max_mem = max_page = (mbi->mem_upper+1024) >> (PAGE_SHIFT - 10);

#if defined(__i386__)

    initial_images_start = DIRECTMAP_PHYS_END;
    initial_images_end   = initial_images_start + 
        (mod[mbi->mods_count-1].mod_end - mod[0].mod_start);
    if ( initial_images_end > (max_page << PAGE_SHIFT) )
    {
        printk("Not enough memory to stash the DOM0 kernel image.\n");
        for ( ; ; ) ;
    }
    memmove((void *)initial_images_start,  /* use low mapping */
            (void *)mod[0].mod_start,      /* use low mapping */
            mod[mbi->mods_count-1].mod_end - mod[0].mod_start);

    if ( opt_xenheap_megabytes > XENHEAP_DEFAULT_MB )
    {
        printk("Xen heap size is limited to %dMB - you specified %dMB.\n",
               XENHEAP_DEFAULT_MB, opt_xenheap_megabytes);
        for ( ; ; ) ;
    }

    ASSERT((sizeof(struct pfn_info) << 20) <=
           (FRAMETABLE_VIRT_END - FRAMETABLE_VIRT_START));

    init_frametable((void *)FRAMETABLE_VIRT_START, max_page);

#elif defined(__x86_64__)

    init_frametable(__va(xenheap_phys_end), max_page);

    initial_images_start = __pa(frame_table) + frame_table_size;
    initial_images_end   = initial_images_start + 
        (mod[mbi->mods_count-1].mod_end - mod[0].mod_start);
    if ( initial_images_end > (max_page << PAGE_SHIFT) )
    {
        printk("Not enough memory to stash the DOM0 kernel image.\n");
        for ( ; ; ) ;
    }
    memmove(__va(initial_images_start),
            __va(mod[0].mod_start),
            mod[mbi->mods_count-1].mod_end - mod[0].mod_start);

#endif

    dom0_memory_start    = (initial_images_end + ((4<<20)-1)) & ~((4<<20)-1);
    dom0_memory_end      = dom0_memory_start + (opt_dom0_mem << 10);
    dom0_memory_end      = (dom0_memory_end + PAGE_SIZE - 1) & PAGE_MASK;
    
    /* Cheesy sanity check: enough memory for DOM0 allocation + some slack? */
    if ( (dom0_memory_end + (8<<20)) > (max_page << PAGE_SHIFT) )
    {
        printk("Not enough memory for DOM0 memory reservation.\n");
        for ( ; ; ) ;
    }

    printk("Initialised %luMB memory (%lu pages) on a %luMB machine\n",
           max_page >> (20-PAGE_SHIFT), max_page,
	   max_mem  >> (20-PAGE_SHIFT));

    heap_start = memguard_init(&_end);
    heap_start = __va(init_heap_allocator(__pa(heap_start), max_page));
 
    init_xenheap_pages(__pa(heap_start), xenheap_phys_end);
    printk("Xen heap size is %luKB\n", 
	   (xenheap_phys_end-__pa(heap_start))/1024 );

    init_domheap_pages(dom0_memory_end, max_page << PAGE_SHIFT);

    /* Initialise the slab allocator. */
    xmem_cache_init();
    xmem_cache_sizes_init(max_page);

    domain_struct_cachep = xmem_cache_create(
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
     * above our heap. The second module, if present, is an initrd ramdisk.
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
    init_domheap_pages(__pa(frame_table) + frame_table_size,
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
