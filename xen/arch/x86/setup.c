
#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/pci.h>
#include <xen/serial.h>
#include <xen/softirq.h>
#include <xen/acpi.h>
#include <asm/bitops.h>
#include <asm/smp.h>
#include <asm/processor.h>
#include <asm/mpspec.h>
#include <asm/apic.h>
#include <asm/desc.h>
#include <asm/domain_page.h>
#include <asm/pdb.h>

extern void arch_init_memory(void);
extern void init_IRQ(void);
extern void trap_init(void);
extern void time_init(void);
extern void ac_timer_init(void);
extern void initialize_keytable();
extern int opt_nosmp, opt_watchdog, opt_noacpi;
extern int opt_ignorebiostables;
extern int do_timer_lists_from_pit;

char ignore_irq13;		/* set if exception 16 works */
struct cpuinfo_x86 boot_cpu_data = { 0, 0, 0, 0, -1 };

#if defined(__x86_64__)
unsigned long mmu_cr4_features = X86_CR4_PSE | X86_CR4_PGE | X86_CR4_PAE;
#else
unsigned long mmu_cr4_features = X86_CR4_PSE | X86_CR4_PGE;
#endif
EXPORT_SYMBOL(mmu_cr4_features);

unsigned long wait_init_idle;

struct exec_domain *idle_task[NR_CPUS] = { &idle0_exec_domain };

#ifdef	CONFIG_ACPI_INTERPRETER
int acpi_disabled = 0;
#else
int acpi_disabled = 1;
#endif
EXPORT_SYMBOL(acpi_disabled);

int phys_proc_id[NR_CPUS];
int logical_proc_id[NR_CPUS];

#if defined(__i386__)

/* Standard macro to see if a specific flag is changeable */
static inline int flag_is_changeable_p(u32 flag)
{
    u32 f1, f2;

    asm("pushfl\n\t"
        "pushfl\n\t"
        "popl %0\n\t"
        "movl %0,%1\n\t"
        "xorl %2,%0\n\t"
        "pushl %0\n\t"
        "popfl\n\t"
        "pushfl\n\t"
        "popl %0\n\t"
        "popfl\n\t"
        : "=&r" (f1), "=&r" (f2)
        : "ir" (flag));

    return ((f1^f2) & flag) != 0;
}

/* Probe for the CPUID instruction */
static int __init have_cpuid_p(void)
{
    return flag_is_changeable_p(X86_EFLAGS_ID);
}

#elif defined(__x86_64__)

#define have_cpuid_p() (1)

#endif

void __init get_cpu_vendor(struct cpuinfo_x86 *c)
{
    char *v = c->x86_vendor_id;

    if (!strcmp(v, "GenuineIntel"))
        c->x86_vendor = X86_VENDOR_INTEL;
    else if (!strcmp(v, "AuthenticAMD"))
        c->x86_vendor = X86_VENDOR_AMD;
    else if (!strcmp(v, "CyrixInstead"))
        c->x86_vendor = X86_VENDOR_CYRIX;
    else if (!strcmp(v, "UMC UMC UMC "))
        c->x86_vendor = X86_VENDOR_UMC;
    else if (!strcmp(v, "CentaurHauls"))
        c->x86_vendor = X86_VENDOR_CENTAUR;
    else if (!strcmp(v, "NexGenDriven"))
        c->x86_vendor = X86_VENDOR_NEXGEN;
    else if (!strcmp(v, "RiseRiseRise"))
        c->x86_vendor = X86_VENDOR_RISE;
    else if (!strcmp(v, "GenuineTMx86") ||
             !strcmp(v, "TransmetaCPU"))
        c->x86_vendor = X86_VENDOR_TRANSMETA;
    else
        c->x86_vendor = X86_VENDOR_UNKNOWN;
}

static void __init init_intel(struct cpuinfo_x86 *c)
{
    /* SEP CPUID bug: Pentium Pro reports SEP but doesn't have it */
    if ( c->x86 == 6 && c->x86_model < 3 && c->x86_mask < 3 )
        clear_bit(X86_FEATURE_SEP, &c->x86_capability);

#ifdef CONFIG_SMP
    if ( test_bit(X86_FEATURE_HT, &c->x86_capability) )
    {
        u32     eax, ebx, ecx, edx;
        int     initial_apic_id, siblings, cpu = smp_processor_id();
        
        cpuid(1, &eax, &ebx, &ecx, &edx);
        ht_per_core = siblings = (ebx & 0xff0000) >> 16;

        if ( opt_noht )
            clear_bit(X86_FEATURE_HT, &c->x86_capability[0]);

        if ( siblings <= 1 )
        {
            printk(KERN_INFO  "CPU#%d: Hyper-Threading is disabled\n", cpu);
        } 
        else if ( siblings > 2 )
        {
            panic("We don't support more than two logical CPUs per package!");
        }
        else
        {
            initial_apic_id = ebx >> 24 & 0xff;
            phys_proc_id[cpu]    = initial_apic_id >> 1;
            logical_proc_id[cpu] = initial_apic_id & 1;
            printk(KERN_INFO  "CPU#%d: Physical ID: %d, Logical ID: %d\n",
                   cpu, phys_proc_id[cpu], logical_proc_id[cpu]);
        }
    }
#endif
}

static void __init init_amd(struct cpuinfo_x86 *c)
{
    /* Bit 31 in normal CPUID used for nonstandard 3DNow ID;
       3DNow is IDd by bit 31 in extended CPUID (1*32+31) anyway */
    clear_bit(0*32+31, &c->x86_capability);
	
    switch(c->x86)
    {
    case 5:
        panic("AMD K6 is not supported.\n");
    case 6:	/* An Athlon/Duron. We can trust the BIOS probably */
        break;		
    }
}

/*
 * This does the hard work of actually picking apart the CPU stuff...
 */
void __init identify_cpu(struct cpuinfo_x86 *c)
{
    int junk, i, cpu = smp_processor_id();
    u32 xlvl, tfms;

    phys_proc_id[cpu]    = cpu;
    logical_proc_id[cpu] = 0;

    c->x86_vendor = X86_VENDOR_UNKNOWN;
    c->cpuid_level = -1;	/* CPUID not detected */
    c->x86_model = c->x86_mask = 0;	/* So far unknown... */
    c->x86_vendor_id[0] = '\0'; /* Unset */
    memset(&c->x86_capability, 0, sizeof c->x86_capability);

    if ( !have_cpuid_p() )
        panic("Ancient processors not supported\n");

    /* Get vendor name */
    cpuid(0x00000000, &c->cpuid_level,
          (int *)&c->x86_vendor_id[0],
          (int *)&c->x86_vendor_id[8],
          (int *)&c->x86_vendor_id[4]);

    get_cpu_vendor(c);
		
    if ( c->cpuid_level == 0 )
        panic("Decrepit CPUID not supported\n");

    cpuid(0x00000001, &tfms, &junk, &junk,
          &c->x86_capability[0]);
    c->x86 = (tfms >> 8) & 15;
    c->x86_model = (tfms >> 4) & 15;
    c->x86_mask = tfms & 15;

    /* AMD-defined flags: level 0x80000001 */
    xlvl = cpuid_eax(0x80000000);
    if ( (xlvl & 0xffff0000) == 0x80000000 ) {
        if ( xlvl >= 0x80000001 )
            c->x86_capability[1] = cpuid_edx(0x80000001);
    }

    /* Transmeta-defined flags: level 0x80860001 */
    xlvl = cpuid_eax(0x80860000);
    if ( (xlvl & 0xffff0000) == 0x80860000 ) {
        if (  xlvl >= 0x80860001 )
            c->x86_capability[2] = cpuid_edx(0x80860001);
    }

    printk("CPU%d: Before vendor init, caps: %08x %08x %08x, vendor = %d\n",
           smp_processor_id(),
           c->x86_capability[0],
           c->x86_capability[1],
           c->x86_capability[2],
           c->x86_vendor);

    switch ( c->x86_vendor ) {
    case X86_VENDOR_INTEL:
        init_intel(c);
        break;
    case X86_VENDOR_AMD:
        init_amd(c);
        break;
    case X86_VENDOR_UNKNOWN:  /* Connectix Virtual PC reports this */
	break;
    case X86_VENDOR_CENTAUR:
        break;
    default:
        printk("Unknown CPU identifier (%d): continuing anyway, "
               "but might fail.\n", c->x86_vendor);
    }
	
    printk("CPU caps: %08x %08x %08x %08x\n",
           c->x86_capability[0],
           c->x86_capability[1],
           c->x86_capability[2],
           c->x86_capability[3]);

    /*
     * On SMP, boot_cpu_data holds the common feature set between
     * all CPUs; so make sure that we indicate which features are
     * common between the CPUs.  The first time this routine gets
     * executed, c == &boot_cpu_data.
     */
    if ( c != &boot_cpu_data ) {
        /* AND the already accumulated flags with these */
        for ( i = 0 ; i < NCAPINTS ; i++ )
            boot_cpu_data.x86_capability[i] &= c->x86_capability[i];
    }
}


unsigned long cpu_initialized;
void __init cpu_init(void)
{
#if defined(__i386__) /* XXX */
    int nr = smp_processor_id();
    struct tss_struct * t = &init_tss[nr];

    if ( test_and_set_bit(nr, &cpu_initialized) )
        panic("CPU#%d already initialized!!!\n", nr);
    printk("Initializing CPU#%d\n", nr);

    t->bitmap = IOBMP_INVALID_OFFSET;
    memset(t->io_bitmap, ~0, sizeof(t->io_bitmap));

    /* Set up GDT and IDT. */
    SET_GDT_ENTRIES(current, DEFAULT_GDT_ENTRIES);
    SET_GDT_ADDRESS(current, DEFAULT_GDT_ADDRESS);
    __asm__ __volatile__("lgdt %0": "=m" (*current->mm.gdt));
    __asm__ __volatile__("lidt %0": "=m" (idt_descr));

    /* No nested task. */
    __asm__("pushfl ; andl $0xffffbfff,(%esp) ; popfl");

    /* Ensure FPU gets initialised for each domain. */
    stts();

    /* Set up and load the per-CPU TSS and LDT. */
    t->ss0  = __HYPERVISOR_DS;
    t->esp0 = get_stack_top();
    set_tss_desc(nr,t);
    load_TR(nr);
    __asm__ __volatile__("lldt %%ax"::"a" (0));

    /* Clear all 6 debug registers. */
#define CD(register) __asm__("movl %0,%%db" #register ::"r"(0) );
    CD(0); CD(1); CD(2); CD(3); /* no db4 and db5 */; CD(6); CD(7);
#undef CD

    /* Install correct page table. */
    write_ptbase(&current->mm);

    init_idle_task();
#endif
}

static void __init do_initcalls(void)
{
    initcall_t *call;
    for ( call = &__initcall_start; call < &__initcall_end; call++ )
        (*call)();
}

unsigned long pci_mem_start = 0x10000000;

void __init start_of_day(void)
{
    unsigned long low_mem_size;
    
#ifdef MEMORY_GUARD
    /* Unmap the first page of CPU0's stack. */
    extern unsigned long cpu0_stack[];
    memguard_guard_range(cpu0_stack, PAGE_SIZE);
#endif

    open_softirq(NEW_TLBFLUSH_CLOCK_PERIOD_SOFTIRQ, new_tlbflush_clock_period);

    if ( opt_watchdog ) 
        nmi_watchdog = NMI_LOCAL_APIC;

    sort_exception_tables();

    arch_do_createdomain(current);

    /* Tell the PCI layer not to allocate too close to the RAM area.. */
    low_mem_size = ((max_page << PAGE_SHIFT) + 0xfffff) & ~0xfffff;
    if ( low_mem_size > pci_mem_start ) pci_mem_start = low_mem_size;
    
    identify_cpu(&boot_cpu_data); /* get CPU type info */
    if ( cpu_has_fxsr ) set_in_cr4(X86_CR4_OSFXSR);
    if ( cpu_has_xmm )  set_in_cr4(X86_CR4_OSXMMEXCPT);
#ifdef CONFIG_SMP
    if ( opt_ignorebiostables )
    {
        opt_nosmp  = 1;           /* No SMP without configuration          */
        opt_noacpi = 1;           /* ACPI will just confuse matters also   */
    }
    else
    {
        find_smp_config();
        smp_alloc_memory();       /* trampoline which other CPUs jump at   */
    }
#endif
    paging_init();                /* not much here now, but sets up fixmap */
    if ( !opt_noacpi )
        acpi_boot_init();
#ifdef CONFIG_SMP
    if ( smp_found_config ) 
        get_smp_config();
#endif
    scheduler_init();	
    init_IRQ();  /* installs simple interrupt wrappers. Starts HZ clock. */
    trap_init();
    time_init(); /* installs software handler for HZ clock. */
    init_apic_mappings(); /* make APICs addressable in our pagetables. */

    arch_init_memory();

#ifndef CONFIG_SMP    
    APIC_init_uniprocessor();
#else
    if ( opt_nosmp )
	APIC_init_uniprocessor();
    else
    	smp_boot_cpus(); 
    /*
     * Does loads of stuff, including kicking the local
     * APIC, and the IO APIC after other CPUs are booted.
     * Each IRQ is preferably handled by IO-APIC, but
     * fall thru to 8259A if we have to (but slower).
     */
#endif

    __sti();

    initialize_keytable(); /* call back handling for key codes */

    serial_init_stage2();

#ifdef XEN_DEBUGGER
    initialize_pdb();      /* pervasive debugger */
#endif

    if ( !cpu_has_apic )
    {
        do_timer_lists_from_pit = 1;
        if ( smp_num_cpus != 1 )
            panic("We need local APICs on SMP machines!");
    }

    ac_timer_init();    /* init accurate timers */
    init_xen_time();	/* initialise the time */
    schedulers_start(); /* start scheduler for each CPU */

    check_nmi_watchdog();

#ifdef CONFIG_PCI
    pci_init();
#endif
    do_initcalls();

#ifdef CONFIG_SMP
    wait_init_idle = cpu_online_map;
    clear_bit(smp_processor_id(), &wait_init_idle);
    smp_threads_ready = 1;
    smp_commence(); /* Tell other CPUs that state of the world is stable. */
    while ( wait_init_idle != 0 )
    {
        cpu_relax();
        barrier();
    }
#endif

    watchdog_on = 1;
}
