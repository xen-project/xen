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
#include <xen/version.h>
#include <xen/gdbstub.h>
#include <xen/percpu.h>
#include <xen/hypercall.h>
#include <xen/keyhandler.h>
#include <xen/numa.h>
#include <xen/rcupdate.h>
#include <public/version.h>
#ifdef CONFIG_COMPAT
#include <compat/platform.h>
#include <compat/xen.h>
#endif
#include <asm/bitops.h>
#include <asm/smp.h>
#include <asm/processor.h>
#include <asm/mpspec.h>
#include <asm/apic.h>
#include <asm/desc.h>
#include <asm/paging.h>
#include <asm/e820.h>
#include <acm/acm_hooks.h>
#include <xen/kexec.h>

extern void dmi_scan_machine(void);
extern void generic_apic_probe(void);
extern void numa_initmem_init(unsigned long start_pfn, unsigned long end_pfn);

/*
 * opt_xenheap_megabytes: Size of Xen heap in megabytes, excluding the
 * page_info table and allocation bitmap.
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
extern void early_cpu_init(void);

struct tss_struct init_tss[NR_CPUS];

extern unsigned long cpu0_stack[];

struct cpuinfo_x86 boot_cpu_data = { 0, 0, 0, 0, -1, 1, 0, 0, -1 };

#if CONFIG_PAGING_LEVELS > 2
unsigned long mmu_cr4_features = X86_CR4_PSE | X86_CR4_PGE | X86_CR4_PAE;
#else
unsigned long mmu_cr4_features = X86_CR4_PSE;
#endif
EXPORT_SYMBOL(mmu_cr4_features);

int acpi_disabled;

int acpi_force;
char acpi_param[10] = "";
static void parse_acpi_param(char *s)
{
    /* Save the parameter so it can be propagated to domain0. */
    safe_strcpy(acpi_param, s);

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

static unsigned long initial_images_start, initial_images_end;

unsigned long initial_images_nrpages(void)
{
    unsigned long s = initial_images_start + PAGE_SIZE - 1;
    unsigned long e = initial_images_end;
    return ((e >> PAGE_SHIFT) - (s >> PAGE_SHIFT));
}

void discard_initial_images(void)
{
    init_domheap_pages(initial_images_start, initial_images_end);
}

extern char __per_cpu_start[], __per_cpu_data_end[], __per_cpu_end[];

static void __init percpu_init_areas(void)
{
    unsigned int i, data_size = __per_cpu_data_end - __per_cpu_start;

    BUG_ON(data_size > PERCPU_SIZE);

    for_each_cpu ( i )
    {
        memguard_unguard_range(__per_cpu_start + (i << PERCPU_SHIFT),
                               1 << PERCPU_SHIFT);
        if ( i != 0 )
            memcpy(__per_cpu_start + (i << PERCPU_SHIFT),
                   __per_cpu_start,
                   data_size);
    }
}

static void __init percpu_guard_areas(void)
{
    memguard_guard_range(__per_cpu_start, __per_cpu_end - __per_cpu_start);
}

static void __init percpu_free_unused_areas(void)
{
    unsigned int i, first_unused;

    /* Find first unused CPU number. */
    for ( i = 0; i < NR_CPUS; i++ )
        if ( !cpu_possible(i) )
            break;
    first_unused = i;

    /* Check that there are no holes in cpu_possible_map. */
    for ( ; i < NR_CPUS; i++ )
        BUG_ON(cpu_possible(i));

#ifndef MEMORY_GUARD
    init_xenheap_pages(__pa(__per_cpu_start) + (first_unused << PERCPU_SHIFT),
                       __pa(__per_cpu_end));
#endif
}

/* Fetch acm policy module from multiboot modules. */
static void extract_acm_policy(
    multiboot_info_t *mbi,
    unsigned int *initrdidx,
    char **_policy_start,
    unsigned long *_policy_len)
{
    int i;
    module_t *mod = (module_t *)__va(mbi->mods_addr);
    unsigned long start, policy_len;
    char *policy_start;

    /*
     * Try all modules and see whichever could be the binary policy.
     * Adjust the initrdidx if module[1] is the binary policy.
     */
    for ( i = mbi->mods_count-1; i >= 1; i-- )
    {
        start = initial_images_start + (mod[i].mod_start-mod[0].mod_start);
#if defined(__i386__)
        policy_start = (char *)start;
#elif defined(__x86_64__)
        policy_start = __va(start);
#endif
        policy_len   = mod[i].mod_end - mod[i].mod_start;
        if ( acm_is_policy(policy_start, policy_len) )
        {
            printk("Policy len  0x%lx, start at %p - module %d.\n",
                   policy_len, policy_start, i);
            *_policy_start = policy_start;
            *_policy_len = policy_len;
            if ( i == 1 )
                *initrdidx = (mbi->mods_count > 2) ? 2 : 0;
            break;
        }
    }
}

static void __init init_idle_domain(void)
{
    struct domain *idle_domain;

    /* Domain creation requires that scheduler structures are initialised. */
    scheduler_init();

    idle_domain = domain_create(IDLE_DOMAIN_ID, 0, 0);
    if ( (idle_domain == NULL) || (alloc_vcpu(idle_domain, 0, 0) == NULL) )
        BUG();

    set_current(idle_domain->vcpu[0]);
    idle_vcpu[0] = this_cpu(curr_vcpu) = current;

    setup_idle_pagetable();
}

static void srat_detect_node(int cpu)
{
    unsigned node;
    u8 apicid = x86_cpu_to_apicid[cpu];

    node = apicid_to_node[apicid];
    if ( node == NUMA_NO_NODE )
        node = 0;
    numa_set_node(cpu, node);

    if ( acpi_numa > 0 )
        printk(KERN_INFO "CPU %d APIC %d -> Node %d\n", cpu, apicid, node);
}

void __init move_memory(unsigned long dst,
                          unsigned long src_start, unsigned long src_end)
{
#if defined(CONFIG_X86_32)
    memmove((void *)dst,            /* use low mapping */
            (void *)src_start,      /* use low mapping */
            src_end - src_start);
#elif defined(CONFIG_X86_64)
    memmove(__va(dst),
            __va(src_start),
            src_end - src_start);
#endif
}

void __init __start_xen(multiboot_info_t *mbi)
{
    char __cmdline[] = "", *cmdline = __cmdline;
    unsigned long _initrd_start = 0, _initrd_len = 0;
    unsigned int initrdidx = 1;
    char *_policy_start = NULL;
    unsigned long _policy_len = 0;
    module_t *mod = (module_t *)__va(mbi->mods_addr);
    unsigned long nr_pages, modules_length;
    paddr_t s, e;
    int i, e820_warn = 0, e820_raw_nr = 0, bytes = 0;
    struct ns16550_defaults ns16550 = {
        .data_bits = 8,
        .parity    = 'n',
        .stop_bits = 1
    };

    extern void early_page_fault(void);
    set_intr_gate(TRAP_page_fault, &early_page_fault);

    /* Parse the command-line options. */
    if ( (mbi->flags & MBI_CMDLINE) && (mbi->cmdline != 0) )
        cmdline = __va(mbi->cmdline);
    cmdline_parse(cmdline);

    set_current((struct vcpu *)0xfffff000); /* debug sanity */
    idle_vcpu[0] = current;
    set_processor_id(0); /* needed early, for smp_processor_id() */

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

    printk("Command line: %s\n", cmdline);

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

    /*
     * Since there are some stubs getting built on the stacks which use
     * direct calls/jumps, the heap must be confined to the lower 2G so
     * that those branches can reach their targets.
     */
    if ( opt_xenheap_megabytes > 2048 )
        opt_xenheap_megabytes = 2048;
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
                (map->type > E820_NVS) ? E820_RESERVED : map->type;
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

    /* Ensure that all E820 RAM regions are page-aligned and -sized. */
    for ( i = 0; i < e820_raw_nr; i++ )
    {
        uint64_t s, e;
        if ( e820_raw[i].type != E820_RAM )
            continue;
        s = PFN_UP(e820_raw[i].addr);
        e = PFN_DOWN(e820_raw[i].addr + e820_raw[i].size);
        e820_raw[i].size = 0; /* discarded later */
        if ( s < e )
        {
            e820_raw[i].addr = s << PAGE_SHIFT;
            e820_raw[i].size = (e - s) << PAGE_SHIFT;
        }
    }

    /* Sanitise the raw E820 map to produce a final clean version. */
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

    move_memory(initial_images_start, 
                mod[0].mod_start, mod[mbi->mods_count-1].mod_end);

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

#if defined(CONFIG_X86_64)
        /*
         * x86/64 maps all registered RAM. Points to note:
         *  1. The initial pagetable already maps low 1GB, so skip that.
         *  2. We must map *only* RAM areas, taking care to avoid I/O holes.
         *     Failure to do this can cause coherency problems and deadlocks
         *     due to cache-attribute mismatches (e.g., AMD/AGP Linux bug).
         */
        {
            /* Calculate page-frame range, discarding partial frames. */
            unsigned long start, end;
            unsigned long init_mapped = 1UL << (30 - PAGE_SHIFT); /* 1GB */
            start = PFN_UP(e820.map[i].addr);
            end   = PFN_DOWN(e820.map[i].addr + e820.map[i].size);
            /* Clip the range to exclude what the bootstrapper initialised. */
            if ( start < init_mapped )
                start = init_mapped;
            if ( end <= start )
                continue;
            /* Request the mapping. */
            map_pages_to_xen(
                PAGE_OFFSET + (start << PAGE_SHIFT),
                start, end-start, PAGE_HYPERVISOR);
        }
#endif
    }

    if ( kexec_crash_area.size > 0 && kexec_crash_area.start > 0)
    {
        unsigned long kdump_start, kdump_size, k;

        /* Mark images pages as free for now. */
        init_boot_pages(initial_images_start, initial_images_end);

        kdump_start = kexec_crash_area.start;
        kdump_size = kexec_crash_area.size;

        printk("Kdump: %luMB (%lukB) at 0x%lx\n",
               kdump_size >> 20,
               kdump_size >> 10,
               kdump_start);

        if ( (kdump_start & ~PAGE_MASK) || (kdump_size & ~PAGE_MASK) )
            panic("Kdump parameters not page aligned\n");

        kdump_start >>= PAGE_SHIFT;
        kdump_size >>= PAGE_SHIFT;

        /* Allocate pages for Kdump memory area. */
        if ( !reserve_boot_pages(kdump_start, kdump_size) )
            panic("Unable to reserve Kdump memory\n");

        /* Allocate pages for relocated initial images. */
        k = ((initial_images_end - initial_images_start) & ~PAGE_MASK) ? 1 : 0;
        k += (initial_images_end - initial_images_start) >> PAGE_SHIFT;

#if defined(CONFIG_X86_32)
        /* Must allocate within bootstrap 1:1 limits. */
        k = alloc_boot_low_pages(k, 1); /* 0x0 - HYPERVISOR_VIRT_START */
#else
        k = alloc_boot_pages(k, 1);
#endif
        if ( k == 0 )
            panic("Unable to allocate initial images memory\n");

        move_memory(k << PAGE_SHIFT, initial_images_start, initial_images_end);

        initial_images_end -= initial_images_start;
        initial_images_start = k << PAGE_SHIFT;
        initial_images_end += initial_images_start;
    }

    memguard_init();
    percpu_guard_areas();

    printk("System RAM: %luMB (%lukB)\n",
           nr_pages >> (20 - PAGE_SHIFT),
           nr_pages << (PAGE_SHIFT - 10));
    total_pages = nr_pages;

    /* Sanity check for unwanted bloat of certain hypercall structures. */
    BUILD_BUG_ON(sizeof(((struct xen_platform_op *)0)->u) !=
                 sizeof(((struct xen_platform_op *)0)->u.pad));
    BUILD_BUG_ON(sizeof(((struct xen_domctl *)0)->u) !=
                 sizeof(((struct xen_domctl *)0)->u.pad));
    BUILD_BUG_ON(sizeof(((struct xen_sysctl *)0)->u) !=
                 sizeof(((struct xen_sysctl *)0)->u.pad));

    BUILD_BUG_ON(sizeof(start_info_t) > PAGE_SIZE);
    BUILD_BUG_ON(sizeof(shared_info_t) > PAGE_SIZE);
    BUILD_BUG_ON(sizeof(struct vcpu_info) != 64);

#ifdef CONFIG_COMPAT
    BUILD_BUG_ON(sizeof(((struct compat_platform_op *)0)->u) !=
                 sizeof(((struct compat_platform_op *)0)->u.pad));
    BUILD_BUG_ON(sizeof(start_info_compat_t) > PAGE_SIZE);
    BUILD_BUG_ON(sizeof(struct compat_vcpu_info) != 64);
#endif

    /* Check definitions in public headers match internal defs. */
    BUILD_BUG_ON(__HYPERVISOR_VIRT_START != HYPERVISOR_VIRT_START);
#ifdef HYPERVISOR_VIRT_END
    BUILD_BUG_ON(__HYPERVISOR_VIRT_END   != HYPERVISOR_VIRT_END);
#endif
    BUILD_BUG_ON(MACH2PHYS_VIRT_START != RO_MPT_VIRT_START);
    BUILD_BUG_ON(MACH2PHYS_VIRT_END   != RO_MPT_VIRT_END);

    init_frametable();

    acpi_boot_table_init();

    acpi_numa_init();

    numa_initmem_init(0, max_page);

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

    end_boot_allocator();

    early_boot = 0;

    early_cpu_init();

    paging_init();

    /* Unmap the first page of CPU0's stack. */
    memguard_guard_stack(cpu0_stack);

    open_softirq(NEW_TLBFLUSH_CLOCK_PERIOD_SOFTIRQ, new_tlbflush_clock_period);

    if ( opt_watchdog ) 
        nmi_watchdog = NMI_LOCAL_APIC;

    sort_exception_tables();

    find_smp_config();

    smp_alloc_memory();

    dmi_scan_machine();

    generic_apic_probe();

    acpi_boot_init();

    init_cpu_to_node();

    if ( smp_found_config )
        get_smp_config();

    init_apic_mappings();

    init_IRQ();

    percpu_init_areas();

    init_idle_domain();

    trap_init();

    rcu_init();
    
    timer_init();

    early_time_init();

    arch_init_memory();

    identify_cpu(&boot_cpu_data);
    if ( cpu_has_fxsr )
        set_in_cr4(X86_CR4_OSFXSR);
    if ( cpu_has_xmm )
        set_in_cr4(X86_CR4_OSXMMEXCPT);

    if ( opt_nosmp )
        max_cpus = 0;

    smp_prepare_cpus(max_cpus);

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
        {
            rcu_online_cpu(i);
            __cpu_up(i);
        }

        /* Set up cpu_to_node[]. */
        srat_detect_node(i);
        /* Set up node_to_cpumask based on cpu_to_node[]. */
        numa_add_cpu(i);        
    }

    printk("Brought up %ld CPUs\n", (long)num_online_cpus());
    smp_cpus_done(max_cpus);

    percpu_free_unused_areas();

    initialise_gdb(); /* could be moved earlier */

    do_initcalls();

    if ( opt_watchdog ) 
        watchdog_enable();

    /* Extract policy from multiboot.  */
    extract_acm_policy(mbi, &initrdidx, &_policy_start, &_policy_len);

    /* initialize access control security module */
    acm_init(_policy_start, _policy_len);

    /* Create initial domain 0. */
    dom0 = domain_create(0, 0, DOM0_SSIDREF);
    if ( (dom0 == NULL) || (alloc_vcpu(dom0, 0, 0) == NULL) )
        panic("Error creating domain 0\n");

    dom0->is_privileged = 1;

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
            safe_strcpy(dom0_cmdline, cmdline);
        }

        /* Append any extra parameters. */
        if ( skip_ioapic_setup && !strstr(dom0_cmdline, "noapic") )
            safe_strcat(dom0_cmdline, " noapic");
        if ( acpi_skip_timer_override &&
             !strstr(dom0_cmdline, "acpi_skip_timer_override") )
            safe_strcat(dom0_cmdline, " acpi_skip_timer_override");
        if ( (strlen(acpi_param) != 0) && !strstr(dom0_cmdline, "acpi=") )
        {
            safe_strcat(dom0_cmdline, " acpi=");
            safe_strcat(dom0_cmdline, acpi_param);
        }

        cmdline = dom0_cmdline;
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

    console_endboot();

    /* Hide UART from DOM0 if we're using it */
    serial_endboot();

    domain_unpause_by_systemcontroller(dom0);

    startup_cpu_idle_loop();
}

void arch_get_xen_caps(xen_capabilities_info_t *info)
{
    /* Interface name is always xen-3.0-* for Xen-3.x. */
    int major = 3, minor = 0;
    char s[32];

    (*info)[0] = '\0';

#if defined(CONFIG_X86_32) && !defined(CONFIG_X86_PAE)

    snprintf(s, sizeof(s), "xen-%d.%d-x86_32 ", major, minor);
    safe_strcat(*info, s);
    if ( hvm_enabled )
    {
        snprintf(s, sizeof(s), "hvm-%d.%d-x86_32 ", major, minor);
        safe_strcat(*info, s);
    }

#elif defined(CONFIG_X86_32) && defined(CONFIG_X86_PAE)

    snprintf(s, sizeof(s), "xen-%d.%d-x86_32p ", major, minor);
    safe_strcat(*info, s);
    if ( hvm_enabled )
    {
        snprintf(s, sizeof(s), "hvm-%d.%d-x86_32 ", major, minor);
        safe_strcat(*info, s);
        snprintf(s, sizeof(s), "hvm-%d.%d-x86_32p ", major, minor);
        safe_strcat(*info, s);
    }

#elif defined(CONFIG_X86_64)

    snprintf(s, sizeof(s), "xen-%d.%d-x86_64 ", major, minor);
    safe_strcat(*info, s);
#ifdef CONFIG_COMPAT
    snprintf(s, sizeof(s), "xen-%d.%d-x86_32p ", major, minor);
    safe_strcat(*info, s);
#endif
    if ( hvm_enabled )
    {
        snprintf(s, sizeof(s), "hvm-%d.%d-x86_32 ", major, minor);
        safe_strcat(*info, s);
        snprintf(s, sizeof(s), "hvm-%d.%d-x86_32p ", major, minor);
        safe_strcat(*info, s);
        snprintf(s, sizeof(s), "hvm-%d.%d-x86_64 ", major, minor);
        safe_strcat(*info, s);
    }

#endif
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
