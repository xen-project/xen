/******************************************************************************
 * xensetup.c
 * Copyright (c) 2004-2005  Hewlett-Packard Co
 *         Dan Magenheimer <dan.magenheimer@hp.com>
 */

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/errno.h>
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
#include <xen/vga.h>
#include <asm/meminit.h>
#include <asm/page.h>
#include <asm/setup.h>
#include <asm/vhpt.h>
#include <xen/string.h>
#include <asm/vmx.h>
#include <linux/efi.h>
#include <asm/iosapic.h>
#include <xen/softirq.h>
#include <xen/rcupdate.h>
#include <xsm/acm/acm_hooks.h>
#include <asm/sn/simulator.h>
#include <asm/sal.h>

unsigned long total_pages;

char saved_command_line[COMMAND_LINE_SIZE];
char __initdata dom0_command_line[COMMAND_LINE_SIZE];

cpumask_t cpu_present_map;

extern unsigned long domain0_ready;

int find_max_pfn (unsigned long, unsigned long, void *);

/* FIXME: which header these declarations should be there ? */
extern void early_setup_arch(char **);
extern void late_setup_arch(char **);
extern void hpsim_serial_init(void);
extern void setup_per_cpu_areas(void);
extern void mem_init(void);
extern void init_IRQ(void);
extern void trap_init(void);
extern void xen_patch_kernel(void);

/* nosmp: ignore secondary processors */
static int __initdata opt_nosmp;
boolean_param("nosmp", opt_nosmp);

/* maxcpus: maximum number of CPUs to activate */
static unsigned int __initdata max_cpus = NR_CPUS;
integer_param("maxcpus", max_cpus); 

/* xencons: toggle xenconsole input (and irq).
   Note: you have to disable 8250 serials in domains (to avoid use of the
   same resource).  */
static int __initdata opt_xencons = 1;
integer_param("xencons", opt_xencons);

/* xencons_poll: toggle non-legacy xencons UARTs to run in polling mode */
static int __initdata opt_xencons_poll;
boolean_param("xencons_poll", opt_xencons_poll);

#define XENHEAP_DEFAULT_SIZE    KERNEL_TR_PAGE_SIZE
#define XENHEAP_SIZE_MIN        (16 * 1024 * 1024)      /* 16MBytes */
unsigned long xenheap_size = XENHEAP_DEFAULT_SIZE;
unsigned long xen_pstart;

static int __init
xen_count_pages(u64 start, u64 end, void *arg)
{
    unsigned long *count = arg;

    /* FIXME: do we need consider difference between DMA-usable memory and
     * normal memory? Seems that HV has no requirement to operate DMA which
     * is owned by Dom0? */
    *count += (end - start) >> PAGE_SHIFT;
    return 0;
}

/*
 * IPF loader only supports one command line currently, for
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

void __init early_cmdline_parse(char **cmdline_p)
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
static int __initdata opt_efi_print;
boolean_param("efi_print", opt_efi_print);

/* print EFI memory map: */
static void __init
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
static efi_memory_desc_t * __init
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

static int __init
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

static inline int __init
md_overlaps(const efi_memory_desc_t *md, unsigned long phys_addr)
{
    return (phys_addr - md->phys_addr < (md->num_pages << EFI_PAGE_SHIFT));
}

static inline int __init
md_overlap_with_boot_param(const efi_memory_desc_t *md)
{
    return md_overlaps(md, __pa(ia64_boot_param)) ||
        md_overlaps(md, ia64_boot_param->efi_memmap) ||
        md_overlaps(md, ia64_boot_param->command_line);
}

#define MD_SIZE(md) (md->num_pages << EFI_PAGE_SHIFT)
#define MD_END(md) ((md)->phys_addr + MD_SIZE(md))

static unsigned long __init
efi_get_max_addr (void)
{
    void *efi_map_start, *efi_map_end, *p;
    efi_memory_desc_t *md;
    u64 efi_desc_size;
    unsigned long max_addr = 0;

    efi_map_start = __va(ia64_boot_param->efi_memmap);
    efi_map_end   = efi_map_start + ia64_boot_param->efi_memmap_size;
    efi_desc_size = ia64_boot_param->efi_memdesc_size;

    for (p = efi_map_start; p < efi_map_end; p += efi_desc_size) {
        md = p;
        if (is_xenheap_usable_memory(md) && MD_END(md) > max_addr)
            max_addr = MD_END(md);
    }
    return max_addr;
}

extern char __init_begin[], __init_end[];
static void noinline init_done(void)
{
    memset(__init_begin, 0, __init_end - __init_begin);
    flush_icache_range((unsigned long)__init_begin, (unsigned long)__init_end);
    init_xenheap_pages(__pa(__init_begin), __pa(__init_end));
    printk("Freed %ldkB init memory.\n",
           (long)(__init_end-__init_begin)>>10);
    
    startup_cpu_idle_loop();
}

struct xen_heap_desc {
    void*               xen_heap_start;
    unsigned long       xenheap_phys_end;
    efi_memory_desc_t*  kern_md;
};

static int __init
init_xenheap_mds(unsigned long start, unsigned long end, void *arg)
{
    struct xen_heap_desc *desc = (struct xen_heap_desc*)arg;
    unsigned long md_end = __pa(desc->xen_heap_start);
    efi_memory_desc_t* md;

    start = __pa(start);
    end = __pa(end);
    
    for (md = efi_get_md(md_end);
         md != NULL && md->phys_addr < desc->xenheap_phys_end;
         md = efi_get_md(md_end)) {
        md_end = MD_END(md);

        if (md == desc->kern_md ||
            (md->type == EFI_LOADER_DATA && !md_overlap_with_boot_param(md)) ||
            ((md->attribute & EFI_MEMORY_WB) &&
             is_xenheap_usable_memory(md))) {
            unsigned long s = max(start, max(__pa(desc->xen_heap_start),
                                             md->phys_addr));
            unsigned long e = min(end, min(md_end, desc->xenheap_phys_end));
            init_boot_pages(s, e);
        }
    }

    return 0;
}

int running_on_sim;

static int __init
is_platform_hp_ski(void)
{
    int i;
    long cpuid[6];

    for (i = 0; i < 5; ++i)
        cpuid[i] = ia64_get_cpuid(i);

    if ((cpuid[0] & 0xff) != 'H')
        return 0;
    if ((cpuid[3] & 0xff) != 0x4)
        return 0;
    if (((cpuid[3] >> 8) & 0xff) != 0x0)
        return 0;
    if (((cpuid[3] >> 16) & 0xff) != 0x0)
        return 0;
    if (((cpuid[3] >> 24) & 0x7) != 0x7)
        return 0;

    return 1;
}

#ifdef CONFIG_XEN_IA64_PERVCPU_VHPT
static int __initdata dom0_vhpt_size_log2;
integer_param("dom0_vhpt_size_log2", dom0_vhpt_size_log2);
#endif
unsigned long xen_fixed_mfn_start __read_mostly;
unsigned long xen_fixed_mfn_end __read_mostly;

void __init start_kernel(void)
{
    char *cmdline;
    unsigned long nr_pages;
    unsigned long dom0_memory_start, dom0_memory_size;
    unsigned long dom0_initrd_start, dom0_initrd_size;
    unsigned long md_end, relo_start, relo_end, relo_size = 0;
    struct domain *idle_domain;
    struct vcpu *dom0_vcpu0;
    efi_memory_desc_t *kern_md, *last_md, *md;
    unsigned long xenheap_phys_end;
    void *xen_heap_start;
    struct xen_heap_desc heap_desc;
#ifdef CONFIG_SMP
    int i;
#endif

    /* Be sure the struct shared_info size is <= XSI_SIZE.  */
    BUILD_BUG_ON(sizeof(struct shared_info) > XSI_SIZE);

    /* Kernel may be relocated by EFI loader */
    xen_pstart = ia64_tpa(KERNEL_START);

    running_on_sim = is_platform_hp_ski();

    early_setup_arch(&cmdline);

    /* We initialise the serial devices very early so we can get debugging. */
    if (running_on_sim)
        hpsim_serial_init();
    else {
        ns16550_init(0, &ns16550_com1);
        ns16550_init(1, &ns16550_com2);
    }

#ifdef CONFIG_VGA
    /* Plug in a default VGA mode */
    vga_console_info.video_type = XEN_VGATYPE_TEXT_MODE_3;
    vga_console_info.u.text_mode_3.font_height = 16; /* generic VGA? */
    vga_console_info.u.text_mode_3.cursor_x =
                                        ia64_boot_param->console_info.orig_x;
    vga_console_info.u.text_mode_3.cursor_y =
                                        ia64_boot_param->console_info.orig_y;
    vga_console_info.u.text_mode_3.rows =
                                        ia64_boot_param->console_info.num_rows;
    vga_console_info.u.text_mode_3.columns =
                                        ia64_boot_param->console_info.num_cols;
#endif

    console_init_preirq();

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

    /*
     * Test if the boot allocator bitmap will overflow xenheap_size.  If
     * so, continue to bump it up until we have at least a minimum space
     * for the actual xenheap.
     */
    max_page = efi_get_max_addr() >> PAGE_SHIFT;
    while ((max_page >> 3) > xenheap_size - XENHEAP_SIZE_MIN)
        xenheap_size <<= 1;

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

        if (md == NULL) {
            printk("no room to move loader data. skip moving loader data\n");
            goto skip_move;
        }
        
        md_end = MD_END(md);
        if (relo_start < md->phys_addr)
            relo_start = md->phys_addr;
        
        if (!is_xenheap_usable_memory(md)) {
            /* Skip this area */
            if (md_end > relo_start)
                relo_start = md_end;
            continue;
        }

        /*
         * The dom0 kernel or initrd could overlap, reserve space
         * at the end to relocate them later.
         */
        if (md->type == EFI_LOADER_DATA) {
            /* Test for ranges we're not prepared to move */
            if (!md_overlap_with_boot_param(md))
                relo_size += MD_SIZE(md);

            /* If range overlaps the end, push out the relocation start */
            if (md_end > relo_start)
                relo_start = md_end;
        }
    }
    last_md = md;
    relo_start = md_end - relo_size;
    relo_end = relo_start + relo_size;

    md_end = __pa(ia64_imva(&_end));
 
    /*
     * Move any relocated data out into the previously found relocation
     * area.  Any extra memory descriptrs are moved out to the end
     * and set to zero pages.
     */
    for (md = efi_get_md(md_end) ;; md = efi_get_md(md_end)) {
        md_end = MD_END(md);

        if (md->type == EFI_LOADER_DATA && !md_overlap_with_boot_param(md)) {
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

        if (md == last_md)
            break;
    }

    /* Trim the last entry */
    md->num_pages -= (relo_size >> EFI_PAGE_SHIFT);

skip_move:
    reserve_memory();

    /* first find highest page frame number */
    max_page = 0;
    efi_memmap_walk(find_max_pfn, &max_page);
    printk("find_memory: efi_memmap_walk returns max_page=%lx\n",max_page);
    efi_print();
    
    xen_heap_start = memguard_init(ia64_imva(&_end));
    printk("xen_heap_start: %p\n", xen_heap_start);

    efi_memmap_walk(filter_rsvd_memory, init_boot_pages);
    efi_memmap_walk(xen_count_pages, &nr_pages);

    printk("System RAM: %luMB (%lukB)\n",
	nr_pages >> (20 - PAGE_SHIFT),
	nr_pages << (PAGE_SHIFT - 10));
    total_pages = nr_pages;

    init_frametable();

    trap_init();

    /* process SAL system table */
    /* must be before any pal/sal call */
    BUG_ON(efi.sal_systab == EFI_INVALID_TABLE_ADDR);
    ia64_sal_init(__va(efi.sal_systab));

    /* early_setup_arch() maps PAL code. */
    identify_vmx_feature();
    /* If vmx feature is on, do necessary initialization for vmx */
    if (vmx_enabled)
        xen_heap_start = vmx_init_env(xen_heap_start, xenheap_phys_end);

    /* allocate memory for percpu area
     * per_cpu_init() called from late_set_arch() is called after
     * end_boot_allocate(). It's too late to allocate memory in
     * xenva.
     */
    xen_heap_start = per_cpu_allocate(xen_heap_start, xenheap_phys_end);

    heap_desc.xen_heap_start   = xen_heap_start;
    heap_desc.xenheap_phys_end = xenheap_phys_end;
    heap_desc.kern_md          = kern_md;
    efi_memmap_walk(&init_xenheap_mds, &heap_desc);

    printk("Xen heap: %luMB (%lukB)\n",
           (xenheap_phys_end-__pa(xen_heap_start)) >> 20,
           (xenheap_phys_end-__pa(xen_heap_start)) >> 10);

    /* for is_xen_fixed_mfn() */
    xen_fixed_mfn_start = virt_to_mfn(&_start);
    xen_fixed_mfn_end = virt_to_mfn(xen_heap_start);

    end_boot_allocator();

    softirq_init();
    tasklet_subsys_init();

    late_setup_arch(&cmdline);

    scheduler_init();
    idle_vcpu[0] = (struct vcpu*) ia64_r13;
    idle_domain = domain_create(IDLE_DOMAIN_ID, 0, 0);
    if ( idle_domain == NULL )
        BUG();
    idle_domain->vcpu = idle_vcpu;
    idle_domain->max_vcpus = NR_CPUS;
    if ( alloc_vcpu(idle_domain, 0, 0) == NULL )
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
    cpus_or(cpu_present_map, cpu_present_map, cpu_possible_map);

    /*  Enable IRQ to receive IPI (needed for ITC sync).  */
    local_irq_enable();

    do_presmp_initcalls();

printk("num_online_cpus=%d, max_cpus=%d\n",num_online_cpus(),max_cpus);
    for_each_present_cpu ( i )
    {
        if ( num_online_cpus() >= max_cpus )
            break;
        if ( !cpu_online(i) )
            cpu_up(i);
    }

    local_irq_disable();

    printk("Brought up %ld CPUs\n", (long)num_online_cpus());
    smp_cpus_done(max_cpus);
#endif

    iommu_setup();    /* setup iommu if available */

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
        console_init_postirq();
    }

    expose_p2m_init();

    /* Create initial domain 0. */
    dom0 = domain_create(0, 0, DOM0_SSIDREF);
    if (dom0 == NULL)
        panic("Error creating domain 0\n");
    domain_set_vhpt_size(dom0, dom0_vhpt_size_log2);
    dom0_vcpu0 = alloc_dom0_vcpu0();
    if (dom0_vcpu0 == NULL || vcpu_late_initialise(dom0_vcpu0) != 0)
        panic("Cannot allocate dom0 vcpu 0\n");

    dom0->is_privileged = 1;
    dom0->target = NULL;

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

    if (!running_on_sim && !IS_MEDUSA())  // slow on ski and pages are pre-initialized to zero
	scrub_heap_pages();

    init_trace_bufs();

    if (opt_xencons) {
        console_endboot();
        serial_endboot();
    }

    domain0_ready = 1;

    domain_unpause_by_systemcontroller(dom0);

    init_done();
}

void arch_get_xen_caps(xen_capabilities_info_t *info)
{
    /* Interface name is always xen-3.0-* for Xen-3.x. */
    int major = 3, minor = 0;
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

        snprintf(s, sizeof(s), "hvm-%d.%d-ia64-sioemu ", major, minor);
        safe_strcat(*info, s);
    }
}

int xen_in_range(paddr_t start, paddr_t end)
{
    paddr_t xs = __pa(&_start);
    paddr_t xe = __pa(&_end);

    return (start < xe) && (end > xs);
}
