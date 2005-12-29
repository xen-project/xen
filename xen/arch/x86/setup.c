
#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/serial.h>
#include <xen/softirq.h>
#include <xen/acpi.h>
#include <xen/console.h>
#include <xen/serial.h>
#include <xen/trace.h>
#include <xen/multiboot.h>
#include <xen/domain_page.h>
#include <xen/compile.h>
#include <public/version.h>
#include <asm/bitops.h>
#include <asm/smp.h>
#include <asm/processor.h>
#include <asm/mpspec.h>
#include <asm/apic.h>
#include <asm/desc.h>
#include <asm/shadow.h>
#include <asm/e820.h>
#include <acm/acm_hooks.h>

extern void dmi_scan_machine(void);
extern void generic_apic_probe(void);

/*
 * opt_xenheap_megabytes: Size of Xen heap in megabytes, excluding the
 * pfn_info table and allocation bitmap.
 */
static unsigned int opt_xenheap_megabytes = XENHEAP_DEFAULT_MB;
#if defined(CONFIG_X86_64)
integer_param("xenheap_megabytes", opt_xenheap_megabytes);
#endif

/* opt_nosmp: If true, secondary processors are ignored. */
static int opt_nosmp = 0;
boolean_param("nosmp", opt_nosmp);

/* maxcpus: maximum number of CPUs to activate. */
static unsigned int max_cpus = NR_CPUS;
integer_param("maxcpus", max_cpus); 

/* opt_watchdog: If true, run a watchdog NMI on each processor. */
static int opt_watchdog = 0;
boolean_param("watchdog", opt_watchdog);

/* **** Linux config option: propagated to domain0. */
/* "acpi=off":    Sisables both ACPI table parsing and interpreter. */
/* "acpi=force":  Override the disable blacklist.                   */
/* "acpi=strict": Disables out-of-spec workarounds.                 */
/* "acpi=ht":     Limit ACPI just to boot-time to enable HT.        */
/* "acpi=noirq":  Disables ACPI interrupt routing.                  */
static void parse_acpi_param(char *s);
custom_param("acpi", parse_acpi_param);

/* **** Linux config option: propagated to domain0. */
/* acpi_skip_timer_override: Skip IRQ0 overrides. */
extern int acpi_skip_timer_override;
boolean_param("acpi_skip_timer_override", acpi_skip_timer_override);

/* **** Linux config option: propagated to domain0. */
/* noapic: Disable IOAPIC setup. */
extern int skip_ioapic_setup;
boolean_param("noapic", skip_ioapic_setup);

int early_boot = 1;

cpumask_t cpu_present_map;

/* Limits of Xen heap, used to initialise the allocator. */
unsigned long xenheap_phys_start, xenheap_phys_end;

extern void arch_init_memory(void);
extern void init_IRQ(void);
extern void trap_init(void);
extern void early_time_init(void);
extern void initialize_keytable(void);
extern void early_cpu_init(void);

extern unsigned long cpu0_stack[];

struct cpuinfo_x86 boot_cpu_data = { 0, 0, 0, 0, -1, 1, 0, 0, -1 };

#if CONFIG_PAGING_LEVELS > 2
unsigned long mmu_cr4_features = X86_CR4_PSE | X86_CR4_PGE | X86_CR4_PAE;
#else
unsigned long mmu_cr4_features = X86_CR4_PSE;
#endif
EXPORT_SYMBOL(mmu_cr4_features);

struct vcpu *idle_task[NR_CPUS] = { &idle0_vcpu };

int acpi_disabled;

int acpi_force;
char acpi_param[10] = "";
static void parse_acpi_param(char *s)
{
    /* Save the parameter so it can be propagated to domain0. */
    strncpy(acpi_param, s, sizeof(acpi_param));
    acpi_param[sizeof(acpi_param)-1] = '\0';

    /* Interpret the parameter for use within Xen. */
    if ( !strcmp(s, "off") )
    {
        disable_acpi();
    }
    else if ( !strcmp(s, "force") )
    {
        acpi_force = 1;
        acpi_ht = 1;
        acpi_disabled = 0;
    }
    else if ( !strcmp(s, "strict") )
    {
        acpi_strict = 1;
    }
    else if ( !strcmp(s, "ht") )
    {
        if ( !acpi_force )
            disable_acpi();
        acpi_ht = 1;
    }
    else if ( !strcmp(s, "noirq") )
    {
        acpi_noirq_set();
    }
}

static void __init do_initcalls(void)
{
    initcall_t *call;
    for ( call = &__initcall_start; call < &__initcall_end; call++ )
        (*call)();
}

#define EARLY_FAIL() for ( ; ; ) __asm__ __volatile__ ( "hlt" )

static struct e820entry e820_raw[E820MAX];

static multiboot_info_t *mbi;

void __init start_of_day(void)
{
    unsigned long vgdt, gdt_pfn;
    char *cmdline;
    unsigned long _initrd_start = 0, _initrd_len = 0;
    unsigned int initrdidx = 1;
    module_t *mod = (module_t *)__va(mbi->mods_addr);
    unsigned long nr_pages, modules_length;
    unsigned long initial_images_start, initial_images_end;
    physaddr_t s, e;
    int i, e820_warn = 0, e820_raw_nr = 0, bytes = 0;
    struct ns16550_defaults ns16550 = {
        .data_bits = 8,
        .parity    = 'n',
        .stop_bits = 1
    };

    /* Parse the command-line options. */
    if ( (mbi->flags & MBI_CMDLINE) && (mbi->cmdline != 0) )
        cmdline_parse(__va(mbi->cmdline));

    /* Must do this early -- e.g., spinlocks rely on get_current(). */
    set_current(&idle0_vcpu);
    set_processor_id(0);

    smp_prepare_boot_cpu();

    /* We initialise the serial devices very early so we can get debugging. */
    ns16550.io_base = 0x3f8;
    ns16550.irq     = 4;
    ns16550_init(0, &ns16550);
    ns16550.io_base = 0x2f8;
    ns16550.irq     = 3;
    ns16550_init(1, &ns16550);
    serial_init_preirq();

    init_console();

    /* Check that we have at least one Multiboot module. */
    if ( !(mbi->flags & MBI_MODULES) || (mbi->mods_count == 0) )
    {
        printk("FATAL ERROR: dom0 kernel not specified."
               " Check bootloader configuration.\n");
        EARLY_FAIL();
    }

    if ( ((unsigned long)cpu0_stack & (STACK_SIZE-1)) != 0 )
    {
        printk("FATAL ERROR: Misaligned CPU0 stack.\n");
        EARLY_FAIL();
    }

    xenheap_phys_end = opt_xenheap_megabytes << 20;

    if ( mbi->flags & MBI_MEMMAP )
    {
        while ( bytes < mbi->mmap_length )
        {
            memory_map_t *map = __va(mbi->mmap_addr + bytes);

            /*
             * This is a gross workaround for a BIOS bug. Some bootloaders do
             * not write e820 map entries into pre-zeroed memory. This is
             * okay if the BIOS fills in all fields of the map entry, but
             * some broken BIOSes do not bother to write the high word of
             * the length field if the length is smaller than 4GB. We
             * detect and fix this by flagging sections below 4GB that
             * appear to be larger than 4GB in size.
             */
            if ( (map->base_addr_high == 0) && (map->length_high != 0) )
            {
                e820_warn = 1;
                map->length_high = 0;
            }

            e820_raw[e820_raw_nr].addr = 
                ((u64)map->base_addr_high << 32) | (u64)map->base_addr_low;
            e820_raw[e820_raw_nr].size = 
                ((u64)map->length_high << 32) | (u64)map->length_low;
            e820_raw[e820_raw_nr].type = 
                (map->type > E820_SHARED_PAGE) ? E820_RESERVED : map->type;
            e820_raw_nr++;

            bytes += map->size + 4;
        }
    }
    else if ( mbi->flags & MBI_MEMLIMITS )
    {
        e820_raw[0].addr = 0;
        e820_raw[0].size = mbi->mem_lower << 10;
        e820_raw[0].type = E820_RAM;
        e820_raw[1].addr = 0x100000;
        e820_raw[1].size = mbi->mem_upper << 10;
        e820_raw[1].type = E820_RAM;
        e820_raw_nr = 2;
    }
    else
    {
        printk("FATAL ERROR: Bootloader provided no memory information.\n");
        for ( ; ; ) ;
    }

    if ( e820_warn )
        printk("WARNING: Buggy e820 map detected and fixed "
               "(truncated length fields).\n");

    max_page = init_e820(e820_raw, &e820_raw_nr);

    modules_length = mod[mbi->mods_count-1].mod_end - mod[0].mod_start;

    /* Find a large enough RAM extent to stash the DOM0 modules. */
    for ( i = 0; ; i++ )
    {
        if ( i == e820.nr_map )
        {
            printk("Not enough memory to stash the DOM0 kernel image.\n");
            for ( ; ; ) ;
        }
        
        if ( (e820.map[i].type == E820_RAM) &&
             (e820.map[i].size >= modules_length) &&
             ((e820.map[i].addr + e820.map[i].size) >=
              (xenheap_phys_end + modules_length)) )
            break;
    }

    /* Stash as near as possible to the beginning of the RAM extent. */
    initial_images_start = e820.map[i].addr;
    if ( initial_images_start < xenheap_phys_end )
        initial_images_start = xenheap_phys_end;
    initial_images_end = initial_images_start + modules_length;

#if defined(CONFIG_X86_32)
    memmove((void *)initial_images_start,  /* use low mapping */
            (void *)mod[0].mod_start,      /* use low mapping */
            mod[mbi->mods_count-1].mod_end - mod[0].mod_start);
#elif defined(CONFIG_X86_64)
    memmove(__va(initial_images_start),
            __va(mod[0].mod_start),
            mod[mbi->mods_count-1].mod_end - mod[0].mod_start);
#endif

    /* Initialise boot-time allocator with all RAM situated after modules. */
    xenheap_phys_start = init_boot_allocator(__pa(&_end));
    nr_pages = 0;
    for ( i = 0; i < e820.nr_map; i++ )
    {
        if ( e820.map[i].type != E820_RAM )
            continue;

        nr_pages += e820.map[i].size >> PAGE_SHIFT;

        /* Initialise boot heap, skipping Xen heap and dom0 modules. */
        s = e820.map[i].addr;
        e = s + e820.map[i].size;
        if ( s < xenheap_phys_end )
            s = xenheap_phys_end;
        if ( (s < initial_images_end) && (e > initial_images_start) )
            s = initial_images_end;
        init_boot_pages(s, e);

#if defined (CONFIG_X86_64)
        /*
         * x86/64 maps all registered RAM. Points to note:
         *  1. The initial pagetable already maps low 64MB, so skip that.
         *  2. We must map *only* RAM areas, taking care to avoid I/O holes.
         *     Failure to do this can cause coherency problems and deadlocks
         *     due to cache-attribute mismatches (e.g., AMD/AGP Linux bug).
         */
        {
            /* Calculate page-frame range, discarding partial frames. */
            unsigned long start, end;
            start = PFN_UP(e820.map[i].addr);
            end   = PFN_DOWN(e820.map[i].addr + e820.map[i].size);
            /* Clip the range to above 64MB. */
            if ( end < (64UL << (20-PAGE_SHIFT)) )
                continue;
            if ( start < (64UL << (20-PAGE_SHIFT)) )
                start = 64UL << (20-PAGE_SHIFT);
            /* Request the mapping. */
            map_pages_to_xen(
                PAGE_OFFSET + (start << PAGE_SHIFT),
                start, end-start, PAGE_HYPERVISOR);
        }
#endif
    }

    memguard_init();

    printk("System RAM: %luMB (%lukB)\n", 
           nr_pages >> (20 - PAGE_SHIFT),
           nr_pages << (PAGE_SHIFT - 10));
    total_pages = nr_pages;

    /* Sanity check for unwanted bloat of dom0_op_t structure. */
    BUG_ON(sizeof(((dom0_op_t *)0)->u) != sizeof(((dom0_op_t *)0)->u.pad));

    BUG_ON(sizeof(start_info_t) > PAGE_SIZE);
    BUG_ON(sizeof(shared_info_t) > PAGE_SIZE);
    BUG_ON(sizeof(vcpu_info_t) != 64);

    init_frametable();

    end_boot_allocator();

    /* Initialise the Xen heap, skipping RAM holes. */
    nr_pages = 0;
    for ( i = 0; i < e820.nr_map; i++ )
    {
        if ( e820.map[i].type != E820_RAM )
            continue;

        s = e820.map[i].addr;
        e = s + e820.map[i].size;
        if ( s < xenheap_phys_start )
            s = xenheap_phys_start;
        if ( e > xenheap_phys_end )
            e = xenheap_phys_end;
 
        if ( s < e )
        {
            nr_pages += (e - s) >> PAGE_SHIFT;
            init_xenheap_pages(s, e);
        }
    }

    printk("Xen heap: %luMB (%lukB)\n", 
           nr_pages >> (20 - PAGE_SHIFT),
           nr_pages << (PAGE_SHIFT - 10));

    early_boot = 0;

    early_cpu_init();

    paging_init();

    /* Unmap the first page of CPU0's stack. */
    memguard_guard_stack(cpu0_stack);

    open_softirq(NEW_TLBFLUSH_CLOCK_PERIOD_SOFTIRQ, new_tlbflush_clock_period);

    if ( opt_watchdog ) 
        nmi_watchdog = NMI_LOCAL_APIC;

    sort_exception_tables();

    arch_do_createdomain(current);
    
    /*
     * Map default GDT into its final positions in the idle page table. As
     * noted in arch_do_createdomain(), we must map for every possible VCPU#.
     */
    vgdt = GDT_VIRT_START(current) + FIRST_RESERVED_GDT_BYTE;
    gdt_pfn = virt_to_phys(gdt_table) >> PAGE_SHIFT;
    for ( i = 0; i < MAX_VIRT_CPUS; i++ )
    {
        map_pages_to_xen(vgdt, gdt_pfn, 1, PAGE_HYPERVISOR);
        vgdt += 1 << PDPT_VCPU_VA_SHIFT;
    }

    find_smp_config();

    smp_alloc_memory();

    dmi_scan_machine();

    generic_apic_probe();

    acpi_boot_table_init();
    acpi_boot_init();

    if ( smp_found_config ) 
        get_smp_config();

    init_apic_mappings();

    init_IRQ();

    trap_init();

    ac_timer_init();

    early_time_init();

    arch_init_memory();

    scheduler_init();

    identify_cpu(&boot_cpu_data);
    if ( cpu_has_fxsr )
        set_in_cr4(X86_CR4_OSFXSR);
    if ( cpu_has_xmm )
        set_in_cr4(X86_CR4_OSXMMEXCPT);

    if ( opt_nosmp )
    {
        max_cpus = 0;
        smp_num_siblings = 1;
        boot_cpu_data.x86_num_cores = 1;
    }

    smp_prepare_cpus(max_cpus);

    /* We aren't hotplug-capable yet. */
    BUG_ON(!cpus_empty(cpu_present_map));
    for_each_cpu ( i )
        cpu_set(i, cpu_present_map);

    /*
     * Initialise higher-level timer functions. We do this fairly late
     * (post-SMP) because the time bases and scale factors need to be updated 
     * regularly, and SMP initialisation can cause a long delay with 
     * interrupts not yet enabled.
     */
    init_xen_time();

    initialize_keytable();

    serial_init_postirq();

    BUG_ON(!local_irq_is_enabled());

    for_each_present_cpu ( i )
    {
        if ( num_online_cpus() >= max_cpus )
            break;
        if ( !cpu_online(i) )
            __cpu_up(i);
    }

    printk("Brought up %ld CPUs\n", (long)num_online_cpus());
    smp_cpus_done(max_cpus);

    do_initcalls();

    schedulers_start();

    watchdog_enable();

    shadow_mode_init();

    /* initialize access control security module */
    acm_init(&initrdidx, mbi, initial_images_start);

    /* Create initial domain 0. */
    dom0 = do_createdomain(0, 0);
    if ( dom0 == NULL )
        panic("Error creating domain 0\n");

    set_bit(_DOMF_privileged, &dom0->domain_flags);
    /* post-create hooks sets security label */
    acm_post_domain0_create(dom0->domain_id);

    /* Grab the DOM0 command line. */
    cmdline = (char *)(mod[0].string ? __va(mod[0].string) : NULL);
    if ( cmdline != NULL )
    {
        static char dom0_cmdline[MAX_GUEST_CMDLINE];

        /* Skip past the image name and copy to a local buffer. */
        while ( *cmdline == ' ' ) cmdline++;
        if ( (cmdline = strchr(cmdline, ' ')) != NULL )
        {
            while ( *cmdline == ' ' ) cmdline++;
            strcpy(dom0_cmdline, cmdline);
        }

        cmdline = dom0_cmdline;

        /* Append any extra parameters. */
        if ( skip_ioapic_setup && !strstr(cmdline, "noapic") )
            strcat(cmdline, " noapic");
        if ( acpi_skip_timer_override &&
             !strstr(cmdline, "acpi_skip_timer_override") )
            strcat(cmdline, " acpi_skip_timer_override");
        if ( (strlen(acpi_param) != 0) && !strstr(cmdline, "acpi=") )
        {
            strcat(cmdline, " acpi=");
            strcat(cmdline, acpi_param);
        }
    }

    if ( (initrdidx > 0) && (initrdidx < mbi->mods_count) )
    {
        _initrd_start = initial_images_start +
            (mod[initrdidx].mod_start - mod[0].mod_start);
        _initrd_len   = mod[initrdidx].mod_end - mod[initrdidx].mod_start;
    }

    /*
     * We're going to setup domain0 using the module(s) that we stashed safely
     * above our heap. The second module, if present, is an initrd ramdisk.
     */
    if ( construct_dom0(dom0,
                        initial_images_start, 
                        mod[0].mod_end-mod[0].mod_start,
                        _initrd_start,
                        _initrd_len,
                        cmdline) != 0)
        panic("Could not set up DOM0 guest OS\n");

    /* Scrub RAM that is still free and so may go to an unprivileged domain. */
    scrub_heap_pages();

    init_trace_bufs();

    /* Give up the VGA console if DOM0 is configured to grab it. */
    console_endboot(cmdline && strstr(cmdline, "tty0"));

    /* Hide UART from DOM0 if we're using it */
    serial_endboot();

    domain_unpause_by_systemcontroller(dom0);

    startup_cpu_idle_loop();
}

void __init __start_xen(multiboot_info_t *__mbi)
{
    mbi = __mbi;
    reset_stack_and_jump(start_of_day);
}

void arch_get_xen_caps(xen_capabilities_info_t info)
{
    char *p = info;

#if defined(CONFIG_X86_32) && !defined(CONFIG_X86_PAE)

    p += sprintf(p, "xen-%d.%d-x86_32 ", XEN_VERSION, XEN_SUBVERSION);
    if ( hvm_enabled )
        p += sprintf(p, "hvm-%d.%d-x86_32 ", XEN_VERSION, XEN_SUBVERSION);

#elif defined(CONFIG_X86_32) && defined(CONFIG_X86_PAE)

    p += sprintf(p, "xen-%d.%d-x86_32p ", XEN_VERSION, XEN_SUBVERSION);
    if ( hvm_enabled )
    {
        //p += sprintf(p, "hvm-%d.%d-x86_32 ", XEN_VERSION, XEN_SUBVERSION);
        //p += sprintf(p, "hvm-%d.%d-x86_32p ", XEN_VERSION, XEN_SUBVERSION);
    }

#elif defined(CONFIG_X86_64)

    p += sprintf(p, "xen-%d.%d-x86_64 ", XEN_VERSION, XEN_SUBVERSION);
    if ( hvm_enabled )
    {
        p += sprintf(p, "hvm-%d.%d-x86_32 ", XEN_VERSION, XEN_SUBVERSION);
        //p += sprintf(p, "hvm-%d.%d-x86_32p ", XEN_VERSION, XEN_SUBVERSION);
        p += sprintf(p, "hvm-%d.%d-x86_64 ", XEN_VERSION, XEN_SUBVERSION);
    }

#else

    p++;

#endif

    *(p-1) = 0;

    BUG_ON((p - info) > sizeof(xen_capabilities_info_t));
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
