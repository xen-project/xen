/******************************************************************************
 * xensetup.c
 * Copyright (c) 2004-2005  Hewlett-Packard Co
 *         Dan Magenheimer <dan.magenheimer@hp.com>
 */

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/errno.h>
//#include <xen/spinlock.h>
#include <xen/multiboot.h>
#include <xen/sched.h>
#include <xen/mm.h>
#include <public/version.h>
#include <xen/gdbstub.h>
#include <xen/version.h>
#include <xen/console.h>
#include <xen/domain.h>
#include <xen/serial.h>
#include <xen/trace.h>
#include <xen/keyhandler.h>
#include <asm/meminit.h>
#include <asm/page.h>
#include <asm/setup.h>
#include <xen/string.h>
#include <asm/vmx.h>
#include <linux/efi.h>
#include <asm/iosapic.h>
#include <xen/softirq.h>
#include <xen/rcupdate.h>

unsigned long xenheap_phys_end, total_pages;

char saved_command_line[COMMAND_LINE_SIZE];
char dom0_command_line[COMMAND_LINE_SIZE];

cpumask_t cpu_present_map;

extern unsigned long domain0_ready;

int find_max_pfn (unsigned long, unsigned long, void *);

/* FIXME: which header these declarations should be there ? */
extern long is_platform_hp_ski(void);
extern void early_setup_arch(char **);
extern void late_setup_arch(char **);
extern void hpsim_serial_init(void);
extern void alloc_dom0(void);
extern void setup_per_cpu_areas(void);
extern void mem_init(void);
extern void init_IRQ(void);
extern void trap_init(void);
extern void xen_patch_kernel(void);

/* opt_nosmp: If true, secondary processors are ignored. */
static int opt_nosmp;
boolean_param("nosmp", opt_nosmp);

/* maxcpus: maximum number of CPUs to activate. */
static unsigned int max_cpus = NR_CPUS;
integer_param("maxcpus", max_cpus); 

/* xencons: if true enable xenconsole input (and irq).
   Note: you have to disable 8250 serials in domains (to avoid use of the
   same resource).  */
static int opt_xencons = 1;
integer_param("xencons", opt_xencons);

/* Toggle to allow non-legacy xencons UARTs to run in polling mode */
static int opt_xencons_poll;
boolean_param("xencons_poll", opt_xencons_poll);

/*
 * opt_xenheap_megabytes: Size of Xen heap in megabytes, including:
 *	xen image
 *	bootmap bits
 *	xen heap
 * Note: To allow xenheap size configurable, the prerequisite is
 * to configure elilo allowing relocation defaultly. Then since
 * elilo chooses 256M as alignment when relocating, alignment issue
 * on IPF can be addressed.
 */
unsigned int opt_xenheap_megabytes = XENHEAP_DEFAULT_MB;
unsigned long xenheap_size = XENHEAP_DEFAULT_SIZE;
extern long running_on_sim;
unsigned long xen_pstart;
void *xen_heap_start __read_mostly;

static int
xen_count_pages(u64 start, u64 end, void *arg)
{
    unsigned long *count = arg;

    /* FIXME: do we need consider difference between DMA-usable memory and
     * normal memory? Seems that HV has no requirement to operate DMA which
     * is owned by Dom0? */
    *count += (end - start) >> PAGE_SHIFT;
    return 0;
}

static void __init do_initcalls(void)
{
    initcall_t *call;
    for ( call = &__initcall_start; call < &__initcall_end; call++ )
        (*call)();
}

/*
 * IPF loader only supports one commaind line currently, for
 * both xen and guest kernel. This function provides pre-parse
 * to mixed command line, to split it into two parts.
 *
 * User should split the parameters by "--", with strings after
 * spliter for guest kernel. Missing "--" means whole line belongs
 * to guest. Example:
 *	"com2=57600,8n1 console=com2 -- console=ttyS1 console=tty
 * root=/dev/sda3 ro"
 */
static char null[4] = { 0 };

void early_cmdline_parse(char **cmdline_p)
{
    char *guest_cmd;
    static const char * const split = "--";

    if (*cmdline_p == NULL) {
	*cmdline_p = &null[0];
	saved_command_line[0] = '\0';
	dom0_command_line[0] = '\0';
	return;
    }

    guest_cmd = strstr(*cmdline_p, split);
    /* If no spliter, whole line is for guest */
    if (guest_cmd == NULL) {
	guest_cmd = *cmdline_p;
	*cmdline_p = &null[0];
    } else {
	*guest_cmd = '\0';	/* Split boot parameters for xen and guest */
	guest_cmd += strlen(split);
	while (*guest_cmd == ' ') guest_cmd++;
    }

    strlcpy(saved_command_line, *cmdline_p, COMMAND_LINE_SIZE);
    strlcpy(dom0_command_line, guest_cmd, COMMAND_LINE_SIZE);
    return;
}

struct ns16550_defaults ns16550_com1 = {
    .data_bits = 8,
    .parity    = 'n',
    .stop_bits = 1
};

unsigned int ns16550_com1_gsi;
unsigned int ns16550_com1_polarity;
unsigned int ns16550_com1_trigger;

struct ns16550_defaults ns16550_com2 = {
    .data_bits = 8,
    .parity    = 'n',
    .stop_bits = 1
};

/* efi_print: print efi table at boot */
static int opt_efi_print;
boolean_param("efi_print", opt_efi_print);

/* print EFI memory map: */
static void
efi_print(void)
{
    void *efi_map_start, *efi_map_end;
    u64 efi_desc_size;

    efi_memory_desc_t *md;
    void *p;
    int i;

    if (!opt_efi_print)
        return;

    efi_map_start = __va(ia64_boot_param->efi_memmap);
    efi_map_end   = efi_map_start + ia64_boot_param->efi_memmap_size;
    efi_desc_size = ia64_boot_param->efi_memdesc_size;

    for (i = 0, p = efi_map_start; p < efi_map_end; ++i, p += efi_desc_size) {
        md = p;
        printk("mem%02u: type=%2u, attr=0x%016lx, range=[0x%016lx-0x%016lx) "
               "(%luMB)\n", i, md->type, md->attribute, md->phys_addr,
               md->phys_addr + (md->num_pages << EFI_PAGE_SHIFT),
               md->num_pages >> (20 - EFI_PAGE_SHIFT));
    }
}

/*
 * These functions are utility functions for getting and
 * testing memory descriptors for allocating the xenheap area.
 */
static efi_memory_desc_t *
efi_get_md (unsigned long phys_addr)
{
    void *efi_map_start, *efi_map_end, *p;
    efi_memory_desc_t *md;
    u64 efi_desc_size;

    efi_map_start = __va(ia64_boot_param->efi_memmap);
    efi_map_end   = efi_map_start + ia64_boot_param->efi_memmap_size;
    efi_desc_size = ia64_boot_param->efi_memdesc_size;

    for (p = efi_map_start; p < efi_map_end; p += efi_desc_size) {
        md = p;
        if (phys_addr - md->phys_addr < (md->num_pages << EFI_PAGE_SHIFT))
            return md;
    }
    return 0;
}

static int
is_xenheap_usable_memory(efi_memory_desc_t *md)
{
    if (!(md->attribute & EFI_MEMORY_WB))
        return 0;

    switch (md->type) {
        case EFI_LOADER_CODE:
        case EFI_LOADER_DATA:
        case EFI_BOOT_SERVICES_CODE:
        case EFI_BOOT_SERVICES_DATA:
        case EFI_CONVENTIONAL_MEMORY:
            return 1;
    }
    return 0;
}

static inline int
md_overlaps(efi_memory_desc_t *md, unsigned long phys_addr)
{
    return (phys_addr - md->phys_addr < (md->num_pages << EFI_PAGE_SHIFT));
}

#define MD_SIZE(md) (md->num_pages << EFI_PAGE_SHIFT)

void start_kernel(void)
{
    char *cmdline;
    unsigned long nr_pages;
    unsigned long dom0_memory_start, dom0_memory_size;
    unsigned long dom0_initrd_start, dom0_initrd_size;
    unsigned long md_end, relo_start, relo_end, relo_size = 0;
    struct domain *idle_domain;
    struct vcpu *dom0_vcpu0;
    efi_memory_desc_t *kern_md, *last_md, *md;
#ifdef CONFIG_SMP
    int i;
#endif

    /* Be sure the struct shared_info size is <= XSI_SIZE.  */
    BUILD_BUG_ON(sizeof(struct shared_info) > XSI_SIZE);

    running_on_sim = is_platform_hp_ski();
    /* Kernel may be relocated by EFI loader */
    xen_pstart = ia64_tpa(KERNEL_START);

    early_setup_arch(&cmdline);

    /* We initialise the serial devices very early so we can get debugging. */
    if (running_on_sim)
        hpsim_serial_init();
    else {
        ns16550_init(0, &ns16550_com1);
        ns16550_init(1, &ns16550_com2);
    }
    serial_init_preirq();

    init_console();
    set_printk_prefix("(XEN) ");

    if (running_on_sim || ia64_boot_param->domain_start == 0 ||
                          ia64_boot_param->domain_size == 0) {
        /* This is possible only with the old elilo, which does not support
           a vmm.  Fix now, and continue without initrd.  */
        printk ("Your elilo is not Xen-aware.  Bootparams fixed\n");
        ia64_boot_param->domain_start = ia64_boot_param->initrd_start;
        ia64_boot_param->domain_size = ia64_boot_param->initrd_size;
        ia64_boot_param->initrd_start = 0;
        ia64_boot_param->initrd_size = 0;
    }

    printk("Xen command line: %s\n", saved_command_line);
    /* xenheap should be in same TR-covered range with xen image */
    xenheap_phys_end = xen_pstart + xenheap_size;
    printk("xen image pstart: 0x%lx, xenheap pend: 0x%lx\n",
           xen_pstart, xenheap_phys_end);

    xen_patch_kernel();

    kern_md = md = efi_get_md(xen_pstart);
    md_end = __pa(ia64_imva(&_end));
    relo_start = xenheap_phys_end;

    /*
     * Scan through the memory descriptors after the kernel
     * image to make sure we have enough room for the xenheap
     * area, pushing out whatever may already be there.
     */
    while (relo_start + relo_size >= md_end) {
        md = efi_get_md(md_end);

        BUG_ON(!md);
        BUG_ON(!is_xenheap_usable_memory(md));

        md_end = md->phys_addr + MD_SIZE(md);
        /*
         * The dom0 kernel or initrd could overlap, reserve space
         * at the end to relocate them later.
         */
        if (md->type == EFI_LOADER_DATA) {
            /* Test for ranges we're not prepared to move */
            BUG_ON(md_overlaps(md, __pa(ia64_boot_param)) ||
                   md_overlaps(md, ia64_boot_param->efi_memmap) ||
                   md_overlaps(md, ia64_boot_param->command_line));

            relo_size += MD_SIZE(md);
            /* If range overlaps the end, push out the relocation start */
            if (md_end > relo_start)
                relo_start = md_end;
        }
    }
    last_md = md;
    relo_end = relo_start + relo_size;

    md_end = __pa(ia64_imva(&_end));
 
    /*
     * Move any relocated data out into the previously found relocation
     * area.  Any extra memory descriptrs are moved out to the end
     * and set to zero pages.
     */
    for (md = efi_get_md(md_end) ;; md = efi_get_md(md_end)) {
        md_end = md->phys_addr + MD_SIZE(md);

        if (md->type == EFI_LOADER_DATA) {
            unsigned long relo_offset;

            if (md_overlaps(md, ia64_boot_param->domain_start)) {
                relo_offset = ia64_boot_param->domain_start - md->phys_addr;
                printk("Moving Dom0 kernel image: 0x%lx -> 0x%lx (%ld KiB)\n",
                       ia64_boot_param->domain_start, relo_start + relo_offset,
                       ia64_boot_param->domain_size >> 10);
                ia64_boot_param->domain_start = relo_start + relo_offset;
            }
            if (ia64_boot_param->initrd_size &&
                md_overlaps(md, ia64_boot_param->initrd_start)) {
                relo_offset = ia64_boot_param->initrd_start - md->phys_addr;
                printk("Moving Dom0 initrd image: 0x%lx -> 0x%lx (%ld KiB)\n",
                       ia64_boot_param->initrd_start, relo_start + relo_offset,
                       ia64_boot_param->initrd_size >> 10);
                ia64_boot_param->initrd_start = relo_start + relo_offset;
            }
            memcpy(__va(relo_start), __va(md->phys_addr), MD_SIZE(md));
            relo_start += MD_SIZE(md);
        }

        if (md == kern_md)
            continue;
        if (md == last_md)
            break;

        md->phys_addr = relo_end;
        md->num_pages = 0;
    }

    /* Trim the last entry */
    md->phys_addr = relo_end;
    md->num_pages = (md_end - relo_end) >> EFI_PAGE_SHIFT;

    /*
     * Expand the new kernel/xenheap (and maybe dom0/initrd) out to
     * the full size.  This range will already be type EFI_LOADER_DATA,
     * therefore the xenheap area is now protected being allocated for
     * use by find_memmap_space() in efi.c
     */
    kern_md->num_pages = (relo_end - kern_md->phys_addr) >> EFI_PAGE_SHIFT;

    reserve_memory();

    /* first find highest page frame number */
    max_page = 0;
    efi_memmap_walk(find_max_pfn, &max_page);
    printk("find_memory: efi_memmap_walk returns max_page=%lx\n",max_page);
    efi_print();

    xen_heap_start = memguard_init(ia64_imva(&_end));
    printk("Before xen_heap_start: %p\n", xen_heap_start);
    xen_heap_start = __va(init_boot_allocator(__pa(xen_heap_start)));
    printk("After xen_heap_start: %p\n", xen_heap_start);

    efi_memmap_walk(filter_rsvd_memory, init_boot_pages);
    efi_memmap_walk(xen_count_pages, &nr_pages);

    printk("System RAM: %luMB (%lukB)\n",
	nr_pages >> (20 - PAGE_SHIFT),
	nr_pages << (PAGE_SHIFT - 10));
    total_pages = nr_pages;

    init_frametable();

    trap_init();

    alloc_dom0();

    end_boot_allocator();

    init_xenheap_pages(__pa(xen_heap_start), xenheap_phys_end);
    printk("Xen heap: %luMB (%lukB)\n",
	(xenheap_phys_end-__pa(xen_heap_start)) >> 20,
	(xenheap_phys_end-__pa(xen_heap_start)) >> 10);

    late_setup_arch(&cmdline);

    scheduler_init();
    idle_vcpu[0] = (struct vcpu*) ia64_r13;
    idle_domain = domain_create(IDLE_DOMAIN_ID, 0, 0);
    if ( (idle_domain == NULL) || (alloc_vcpu(idle_domain, 0, 0) == NULL) )
        BUG();

    alloc_dom_xen_and_dom_io();
    setup_per_cpu_areas();
    mem_init();

    local_irq_disable();
    init_IRQ ();
    init_xen_time(); /* initialise the time */
    timer_init();

    rcu_init();

#ifdef CONFIG_XEN_IA64_TLBFLUSH_CLOCK
    open_softirq(NEW_TLBFLUSH_CLOCK_PERIOD_SOFTIRQ, new_tlbflush_clock_period);
#endif

#ifdef CONFIG_SMP
    if ( opt_nosmp )
    {
        max_cpus = 0;
        smp_num_siblings = 1;
        //boot_cpu_data.x86_num_cores = 1;
    }

    /* A vcpu is created for the idle domain on every physical cpu.
       Limit the number of cpus to the maximum number of vcpus.  */
    if (max_cpus > MAX_VIRT_CPUS)
        max_cpus = MAX_VIRT_CPUS;

    smp_prepare_cpus(max_cpus);

    /* We aren't hotplug-capable yet. */
    for_each_cpu ( i )
        cpu_set(i, cpu_present_map);

    /*  Enable IRQ to receive IPI (needed for ITC sync).  */
    local_irq_enable();

printk("num_online_cpus=%d, max_cpus=%d\n",num_online_cpus(),max_cpus);
    for_each_present_cpu ( i )
    {
        if ( num_online_cpus() >= max_cpus )
            break;
        if ( !cpu_online(i) ) {
            rcu_online_cpu(i);
            __cpu_up(i);
	}
    }

    local_irq_disable();

    printk("Brought up %ld CPUs\n", (long)num_online_cpus());
    smp_cpus_done(max_cpus);
#endif

    initialise_gdb(); /* could be moved earlier */

    do_initcalls();
    sort_main_extable();

    init_rid_allocator ();

    local_irq_enable();

    if (opt_xencons) {
        initialize_keytable();
        if (ns16550_com1_gsi) {
            if (opt_xencons_poll ||
                iosapic_register_intr(ns16550_com1_gsi,
                                      ns16550_com1_polarity,
                                      ns16550_com1_trigger) < 0) {
                ns16550_com1.irq = 0;
                ns16550_init(0, &ns16550_com1);
            }
        }
        serial_init_postirq();

        /* Hide the HCDP table from dom0 */
        efi.hcdp = NULL;
    }

    expose_p2m_init();

    /* Create initial domain 0. */
    dom0 = domain_create(0, 0, DOM0_SSIDREF);
    if (dom0 == NULL)
        panic("Error creating domain 0\n");
    dom0_vcpu0 = alloc_vcpu(dom0, 0, 0);
    if (dom0_vcpu0 == NULL || vcpu_late_initialise(dom0_vcpu0) != 0)
        panic("Cannot allocate dom0 vcpu 0\n");

    dom0->is_privileged = 1;

    /*
     * We're going to setup domain0 using the module(s) that we stashed safely
     * above our heap. The second module, if present, is an initrd ramdisk.
     */
    dom0_memory_start = (unsigned long) __va(ia64_boot_param->domain_start);
    dom0_memory_size = ia64_boot_param->domain_size;
    dom0_initrd_start = (unsigned long) __va(ia64_boot_param->initrd_start);
    dom0_initrd_size = ia64_boot_param->initrd_size;
 
    if ( construct_dom0(dom0, dom0_memory_start, dom0_memory_size,
                        dom0_initrd_start,dom0_initrd_size,
  			0) != 0)
        panic("Could not set up DOM0 guest OS\n");

    if (!running_on_sim)  // slow on ski and pages are pre-initialized to zero
	scrub_heap_pages();

    init_trace_bufs();

    if (opt_xencons) {
        console_endboot();
        serial_endboot();
    }

    domain0_ready = 1;

    domain_unpause_by_systemcontroller(dom0);

    startup_cpu_idle_loop();
}

void arch_get_xen_caps(xen_capabilities_info_t *info)
{
    int major = xen_major_version();
    int minor = xen_minor_version();
    char s[32];

    (*info)[0] = '\0';

    snprintf(s, sizeof(s), "xen-%d.%d-ia64 ", major, minor);
    safe_strcat(*info, s);

    snprintf(s, sizeof(s), "xen-%d.%d-ia64be ", major, minor);
    safe_strcat(*info, s);

    if (vmx_enabled)
    {
        snprintf(s, sizeof(s), "hvm-%d.%d-ia64 ", major, minor);
        safe_strcat(*info, s);
    }
}

