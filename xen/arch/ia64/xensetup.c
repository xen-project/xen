/******************************************************************************
 * kernel.c
 * 
 * This file should contain architecture-independent bootstrap and low-level
 * help routines. It's a bit x86/PC specific right now!
 * 
 * Copyright (c) 2002-2003 K A Fraser
 */

//#include <stdarg.h>
#include <xen/config.h>
#include <xen/lib.h>
#include <xen/errno.h>
//#include <xen/spinlock.h>
#include <xen/multiboot.h>
#include <xen/sched.h>
#include <xen/mm.h>
//#include <xen/delay.h>
#include <xen/compile.h>
//#include <xen/console.h>
//#include <xen/serial.h>
#include <xen/trace.h>
//#include <asm/shadow.h>
//#include <asm/io.h>
//#include <asm/uaccess.h>
//#include <asm/domain_page.h>
//#include <public/dom0_ops.h>

unsigned long xenheap_phys_end;

struct exec_domain *idle_task[NR_CPUS] = { &idle0_exec_domain };

xmem_cache_t *domain_struct_cachep;
#ifdef IA64
kmem_cache_t *mm_cachep;
kmem_cache_t *vm_area_cachep;
#ifdef CLONE_DOMAIN0
struct domain *clones[CLONE_DOMAIN0];
#endif
#endif
extern struct domain *dom0;
extern unsigned long domain0_ready;

#ifndef IA64
vm_assist_info_t vm_assist_info[MAX_VMASST_TYPE + 1];
#endif

#ifndef IA64
struct e820entry {
    unsigned long addr_lo, addr_hi;        /* start of memory segment */
    unsigned long size_lo, size_hi;        /* size of memory segment */
    unsigned long type;                    /* type of memory segment */
};
#endif

void start_of_day(void);

/* opt_console: comma-separated list of console outputs. */
#ifdef IA64
unsigned char opt_console[30] = "com1";
#else
unsigned char opt_console[30] = "com1,vga";
#endif
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
/*
 * opt_nmi: one of 'ignore', 'dom0', or 'fatal'.
 *  fatal:  Xen prints diagnostic message and then hangs.
 *  dom0:   The NMI is virtualised to DOM0.
 *  ignore: The NMI error is cleared and ignored.
 */
#ifdef NDEBUG
char opt_nmi[10] = "dom0";
#else
char opt_nmi[10] = "fatal";
#endif
/*
 * Comma-separated list of hexadecimal page numbers containing bad bytes.
 * e.g. 'badpage=0x3f45,0x8a321'.
 */
char opt_badpage[100] = "";

extern long running_on_sim;

void cmain(multiboot_info_t *mbi)
{
    unsigned long max_page;
    unsigned char *cmdline;
    module_t *mod = (module_t *)__va(mbi->mods_addr);
    void *heap_start;
    int i;
    unsigned long max_mem;
    unsigned long dom0_memory_start, dom0_memory_end;
    unsigned long initial_images_start, initial_images_end;


    running_on_sim = is_platform_hp_ski();

    /* Parse the command-line options. */
    cmdline = (unsigned char *)(mbi->cmdline ? __va(mbi->cmdline) : NULL);
    cmdline_parse(cmdline);

    /* Must do this early -- e.g., spinlocks rely on get_current(). */
    set_current(&idle0_exec_domain);

    early_setup_arch();

    /* We initialise the serial devices very early so we can get debugging. */
    serial_init_stage1();

    init_console(); 
    set_printk_prefix("(XEN) ");

#ifdef IA64
	//set_current(&idle0_exec_domain);
	{ char *cmdline;
	setup_arch(&cmdline);
	}
	setup_per_cpu_areas();
	build_all_zonelists();
	mem_init();
	//show_mem();	// call to dump lots of memory info for debug
#else
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

    xenheap_phys_end = opt_xenheap_megabytes << 20;

    max_mem = max_page = (mbi->mem_upper+1024) >> (PAGE_SHIFT - 10);
#endif

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

#ifndef IA64
    dom0_memory_start    = (initial_images_end + ((4<<20)-1)) & ~((4<<20)-1);
    dom0_memory_end      = dom0_memory_start + (opt_dom0_mem << 10);
    dom0_memory_end      = (dom0_memory_end + PAGE_SIZE - 1) & PAGE_MASK;
    
    /* Cheesy sanity check: enough memory for DOM0 allocation + some slack? */
    if ( (dom0_memory_end + (8<<20)) > (max_page << PAGE_SHIFT) )
    {
        printk("Not enough memory for DOM0 memory reservation.\n");
        for ( ; ; ) ;
    }
#endif

    printk("Initialised %luMB memory (%lu pages) on a %luMB machine\n",
           max_page >> (20-PAGE_SHIFT), max_page,
	   max_mem  >> (20-PAGE_SHIFT));

#ifndef IA64
    heap_start = memguard_init(&_end);
    heap_start = __va(init_heap_allocator(__pa(heap_start), max_page));
 
    init_xenheap_pages(__pa(heap_start), xenheap_phys_end);
    printk("Xen heap size is %luKB\n", 
	   (xenheap_phys_end-__pa(heap_start))/1024 );

    init_domheap_pages(dom0_memory_end, max_page << PAGE_SHIFT);
#endif

    /* Initialise the slab allocator. */
#ifdef IA64
    kmem_cache_init();
#else
    xmem_cache_init();
    xmem_cache_sizes_init(max_page);
#endif

    domain_struct_cachep = xmem_cache_create(
        "domain_cache", sizeof(struct domain),
        0, SLAB_HWCACHE_ALIGN, NULL, NULL);
    if ( domain_struct_cachep == NULL )
        panic("No slab cache for task structs.");

#ifdef IA64
    // following from proc_caches_init in linux/kernel/fork.c
    vm_area_cachep = kmem_cache_create("vm_area_struct",
			sizeof(struct vm_area_struct), 0,
			SLAB_PANIC, NULL, NULL);
    mm_cachep = kmem_cache_create("mm_struct",
			sizeof(struct mm_struct), 0,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL, NULL);
printk("About to call scheduler_init()\n");
    scheduler_init();
    local_irq_disable();
printk("About to call time_init()\n");
    time_init();
printk("About to call ac_timer_init()\n");
    ac_timer_init();
// init_xen_time(); ???
// schedulers_start(); ???
// do_initcalls(); ???
#else
    start_of_day();

    grant_table_init();
#endif

    /* Create initial domain 0. */
printk("About to call do_createdomain()\n");
    dom0 = do_createdomain(0, 0);
printk("About to call init_idle_task()\n");
    init_task.domain = &idle0_domain;
    init_task.processor = 0;
    init_task.mm = &init_mm;
//    init_task.thread = INIT_THREAD;
    init_idle_task();
    //arch_do_createdomain(current);
#ifdef CLONE_DOMAIN0
    {
    int i;
    for (i = 0; i < CLONE_DOMAIN0; i++) {
    	clones[i] = do_createdomain(i+1, 0);
        if ( clones[i] == NULL )
            panic("Error creating domain0 clone %d\n",i);
    }
    }
#endif
    if ( dom0 == NULL )
        panic("Error creating domain 0\n");

    set_bit(DF_PRIVILEGED, &dom0->d_flags);

//printk("About to call shadow_mode_init()\n");
//    shadow_mode_init();

    /* Grab the DOM0 command line. Skip past the image name. */
printk("About to  process command line\n");
#ifndef IA64
    cmdline = (unsigned char *)(mod[0].string ? __va(mod[0].string) : NULL);
    if ( cmdline != NULL )
    {
        while ( *cmdline == ' ' ) cmdline++;
        if ( (cmdline = strchr(cmdline, ' ')) != NULL )
            while ( *cmdline == ' ' ) cmdline++;
    }
#endif

    /*
     * We're going to setup domain0 using the module(s) that we stashed safely
     * above our heap. The second module, if present, is an initrd ramdisk.
     */
#ifdef IA64
printk("About to call construct_dom0()\n");
    if ( construct_dom0(dom0, dom0_memory_start, dom0_memory_end,
			0,
                        0,
			0) != 0)
#else
    if ( construct_dom0(dom0, dom0_memory_start, dom0_memory_end,
                        (char *)initial_images_start, 
                        mod[0].mod_end-mod[0].mod_start,
                        (mbi->mods_count == 1) ? 0 :
                        (char *)initial_images_start + 
                        (mod[1].mod_start-mod[0].mod_start),
                        (mbi->mods_count == 1) ? 0 :
                        mod[mbi->mods_count-1].mod_end - mod[1].mod_start,
                        cmdline) != 0)
#endif
        panic("Could not set up DOM0 guest OS\n");
#ifdef CLONE_DOMAIN0
    {
    int i;
    for (i = 0; i < CLONE_DOMAIN0; i++) {
printk("CONSTRUCTING DOMAIN0 CLONE #%d\n",i+1);
        if ( construct_dom0(clones[i], dom0_memory_start, dom0_memory_end,
                        0, 
                        0,
			0) != 0)
            panic("Could not set up DOM0 clone %d\n",i);
    }
    }
#endif

    /* The stash space for the initial kernel image can now be freed up. */
#ifndef IA64
    init_domheap_pages(__pa(frame_table) + frame_table_size,
                       dom0_memory_start);

    scrub_heap_pages();
#endif

printk("About to call init_trace_bufs()\n");
    init_trace_bufs();

    /* Give up the VGA console if DOM0 is configured to grab it. */
#ifndef IA64
    console_endboot(cmdline && strstr(cmdline, "tty0"));
#endif

    domain_unpause_by_systemcontroller(current);
#ifdef CLONE_DOMAIN0
    {
    int i;
    for (i = 0; i < CLONE_DOMAIN0; i++)
	domain_unpause_by_systemcontroller(clones[i]);
    }
#endif
    domain_unpause_by_systemcontroller(dom0);
    domain0_ready = 1;
    local_irq_enable();
printk("About to call startup_cpu_idle_loop()\n");
    startup_cpu_idle_loop();
}
