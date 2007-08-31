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
#include <xen/vga.h>
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
#include <asm/edd.h>
#include <xsm/xsm.h>

#if defined(CONFIG_X86_64)
#define BOOTSTRAP_DIRECTMAP_END (1UL << 32) /* 4GB */
#define maddr_to_bootstrap_virt(m) maddr_to_virt(m)
#else
#define BOOTSTRAP_DIRECTMAP_END (1UL << 30) /* 1GB */
#define maddr_to_bootstrap_virt(m) ((void *)(long)(m))
#endif

extern void dmi_scan_machine(void);
extern void generic_apic_probe(void);
extern void numa_initmem_init(unsigned long start_pfn, unsigned long end_pfn);

extern u16 boot_edid_caps;
extern u8 boot_edid_info[128];
extern struct boot_video_info boot_vid_info;

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

unsigned long xen_phys_start;

/* Limits of Xen heap, used to initialise the allocator. */
unsigned long xenheap_phys_start, xenheap_phys_end;

extern void arch_init_memory(void);
extern void init_IRQ(void);
extern void trap_init(void);
extern void early_time_init(void);
extern void early_cpu_init(void);
extern void vesa_init(void);
extern void vesa_mtrr_init(void);

struct tss_struct init_tss[NR_CPUS];

char __attribute__ ((__section__(".bss.stack_aligned"))) cpu0_stack[STACK_SIZE];

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
static void __init parse_acpi_param(char *s)
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

#define EARLY_FAIL(f, a...) do {                \
    printk( f , ## a );                         \
    for ( ; ; ) __asm__ __volatile__ ( "hlt" ); \
} while (0)

static unsigned long __initdata initial_images_start, initial_images_end;

unsigned long __init initial_images_nrpages(void)
{
    ASSERT(!(initial_images_start & ~PAGE_MASK));
    ASSERT(!(initial_images_end   & ~PAGE_MASK));
    return ((initial_images_end >> PAGE_SHIFT) -
            (initial_images_start >> PAGE_SHIFT));
}

void __init discard_initial_images(void)
{
    init_domheap_pages(initial_images_start, initial_images_end);
}

extern char __per_cpu_start[], __per_cpu_data_end[], __per_cpu_end[];

static void __init percpu_init_areas(void)
{
    unsigned int i, data_size = __per_cpu_data_end - __per_cpu_start;
    unsigned int first_unused;

    BUG_ON(data_size > PERCPU_SIZE);

    /* Initialise per-cpu data area for all possible secondary CPUs. */
    for ( i = 1; (i < NR_CPUS) && cpu_possible(i); i++ )
        memcpy(__per_cpu_start + (i << PERCPU_SHIFT),
               __per_cpu_start,
               data_size);
    first_unused = i;

    /* Check that there are no holes in cpu_possible_map. */
    for ( ; i < NR_CPUS; i++ )
        BUG_ON(cpu_possible(i));

#ifndef MEMORY_GUARD
    init_xenheap_pages(__pa(__per_cpu_start) + (first_unused << PERCPU_SHIFT),
                       __pa(__per_cpu_end));
#endif
    memguard_guard_range(&__per_cpu_start[first_unused << PERCPU_SHIFT],
                         (NR_CPUS - first_unused) << PERCPU_SHIFT);
#if defined(CONFIG_X86_64)
    /* Also zap the mapping in the 1:1 area. */
    memguard_guard_range(__va(__pa(__per_cpu_start)) +
                         (first_unused << PERCPU_SHIFT),
                         (NR_CPUS - first_unused) << PERCPU_SHIFT);
#endif
}

/* Fetch acm policy module from multiboot modules. */
static void __init extract_acm_policy(
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
        policy_start = maddr_to_bootstrap_virt(start);
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

static void __init srat_detect_node(int cpu)
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

/*
 * Ensure a given physical memory range is present in the bootstrap mappings.
 * Use superpage mappings to ensure that pagetable memory needn't be allocated.
 */
static void __init bootstrap_map(unsigned long start, unsigned long end)
{
    unsigned long mask = (1UL << L2_PAGETABLE_SHIFT) - 1;
    start = start & ~mask;
    end   = (end + mask) & ~mask;
    if ( end > BOOTSTRAP_DIRECTMAP_END )
        panic("Cannot access memory beyond end of "
              "bootstrap direct-map area\n");
    map_pages_to_xen(
        (unsigned long)maddr_to_bootstrap_virt(start),
        start >> PAGE_SHIFT, (end-start) >> PAGE_SHIFT, PAGE_HYPERVISOR);
}

static void __init move_memory(
    unsigned long dst, unsigned long src_start, unsigned long src_end)
{
    bootstrap_map(src_start, src_end);
    bootstrap_map(dst, dst + src_end - src_start);
    memmove(maddr_to_bootstrap_virt(dst),
            maddr_to_bootstrap_virt(src_start),
            src_end - src_start);
}

/* A temporary copy of the e820 map that we can mess with during bootstrap. */
static struct e820map __initdata boot_e820;

/* Reserve area (@s,@e) in the temporary bootstrap e820 map. */
static int __init reserve_in_boot_e820(unsigned long s, unsigned long e)
{
    uint64_t rs, re;
    int i;

    for ( i = 0; i < boot_e820.nr_map; i++ )
    {
        /* Have we found the e820 region that includes the specified range? */
        rs = boot_e820.map[i].addr;
        re = rs + boot_e820.map[i].size;
        if ( (s >= rs) && (e <= re) )
            goto found;
    }

    return 0;

 found:
    /* Start fragment. */
    boot_e820.map[i].size = s - rs;

    /* End fragment. */
    if ( e < re )
    {
        memmove(&boot_e820.map[i+1], &boot_e820.map[i],
                (boot_e820.nr_map-i) * sizeof(boot_e820.map[0]));
        boot_e820.nr_map++;
        i++;
        boot_e820.map[i].addr = e;
        boot_e820.map[i].size = re - e;
    }

    return 1;
}

struct boot_video_info {
    u8  orig_x;             /* 0x00 */
    u8  orig_y;             /* 0x01 */
    u8  orig_video_mode;    /* 0x02 */
    u8  orig_video_cols;    /* 0x03 */
    u8  orig_video_lines;   /* 0x04 */
    u8  orig_video_isVGA;   /* 0x05 */
    u16 orig_video_points;  /* 0x06 */

    /* VESA graphic mode -- linear frame buffer */
    u32 capabilities;       /* 0x08 */
    u16 lfb_linelength;     /* 0x0c */
    u16 lfb_width;          /* 0x0e */
    u16 lfb_height;         /* 0x10 */
    u16 lfb_depth;          /* 0x12 */
    u32 lfb_base;           /* 0x14 */
    u32 lfb_size;           /* 0x18 */
    u8  red_size;           /* 0x1c */
    u8  red_pos;            /* 0x1d */
    u8  green_size;         /* 0x1e */
    u8  green_pos;          /* 0x1f */
    u8  blue_size;          /* 0x20 */
    u8  blue_pos;           /* 0x21 */
    u8  rsvd_size;          /* 0x22 */
    u8  rsvd_pos;           /* 0x23 */
    u16 vesapm_seg;         /* 0x24 */
    u16 vesapm_off;         /* 0x26 */
};

static void __init parse_video_info(void)
{
    struct boot_video_info *bvi = &bootsym(boot_vid_info);

    if ( (bvi->orig_video_isVGA == 1) && (bvi->orig_video_mode == 3) )
    {
        vga_console_info.video_type = XEN_VGATYPE_TEXT_MODE_3;
        vga_console_info.u.text_mode_3.font_height = bvi->orig_video_points;
        vga_console_info.u.text_mode_3.cursor_x = bvi->orig_x;
        vga_console_info.u.text_mode_3.cursor_y = bvi->orig_y;
        vga_console_info.u.text_mode_3.rows = bvi->orig_video_lines;
        vga_console_info.u.text_mode_3.columns = bvi->orig_video_cols;
    }
    else if ( bvi->orig_video_isVGA == 0x23 )
    {
        vga_console_info.video_type = XEN_VGATYPE_VESA_LFB;
        vga_console_info.u.vesa_lfb.width = bvi->lfb_width;
        vga_console_info.u.vesa_lfb.height = bvi->lfb_height;
        vga_console_info.u.vesa_lfb.bytes_per_line = bvi->lfb_linelength;
        vga_console_info.u.vesa_lfb.bits_per_pixel = bvi->lfb_depth;
        vga_console_info.u.vesa_lfb.lfb_base = bvi->lfb_base;
        vga_console_info.u.vesa_lfb.lfb_size = bvi->lfb_size;
        vga_console_info.u.vesa_lfb.red_pos = bvi->red_pos;
        vga_console_info.u.vesa_lfb.red_size = bvi->red_size;
        vga_console_info.u.vesa_lfb.green_pos = bvi->green_pos;
        vga_console_info.u.vesa_lfb.green_size = bvi->green_size;
        vga_console_info.u.vesa_lfb.blue_pos = bvi->blue_pos;
        vga_console_info.u.vesa_lfb.blue_size = bvi->blue_size;
        vga_console_info.u.vesa_lfb.rsvd_pos = bvi->rsvd_pos;
        vga_console_info.u.vesa_lfb.rsvd_size = bvi->rsvd_size;
    }
}

void init_done(void)
{
    extern char __init_begin[], __init_end[];

    /* Free (or page-protect) the init areas. */
#ifndef MEMORY_GUARD
    init_xenheap_pages(__pa(__init_begin), __pa(__init_end));
#endif
    memguard_guard_range(__init_begin, __init_end - __init_begin);
#if defined(CONFIG_X86_64)
    /* Also zap the mapping in the 1:1 area. */
    memguard_guard_range(__va(__pa(__init_begin)), __init_end - __init_begin);
#endif
    printk("Freed %ldkB init memory.\n", (long)(__init_end-__init_begin)>>10);

    startup_cpu_idle_loop();
}

static char * __init cmdline_cook(char *p)
{
    p = p ? : "";
    while ( *p == ' ' )
        p++;
    while ( (*p != ' ') && (*p != '\0') )
        p++;
    while ( *p == ' ' )
        p++;
    return p;
}

void __init __start_xen(unsigned long mbi_p)
{
    char *memmap_type = NULL;
    char *cmdline, *kextra;
    unsigned long _initrd_start = 0, _initrd_len = 0;
    unsigned int initrdidx = 1;
    char *_policy_start = NULL;
    unsigned long _policy_len = 0;
    multiboot_info_t *mbi = __va(mbi_p);
    module_t *mod = (module_t *)__va(mbi->mods_addr);
    unsigned long nr_pages, modules_length;
    int i, e820_warn = 0, bytes = 0;
    struct ns16550_defaults ns16550 = {
        .data_bits = 8,
        .parity    = 'n',
        .stop_bits = 1
    };

    extern void early_page_fault(void);
    set_intr_gate(TRAP_page_fault, &early_page_fault);

    /* Parse the command-line options. */
    cmdline = cmdline_cook((mbi->flags & MBI_CMDLINE) ?
                           __va(mbi->cmdline) : NULL);
    if ( (kextra = strstr(cmdline, " -- ")) != NULL )
    {
        /*
         * Options after ' -- ' separator belong to dom0.
         *  1. Orphan dom0's options from Xen's command line.
         *  2. Skip all but final leading space from dom0's options.
         */
        *kextra = '\0';
        kextra += 3;
        while ( kextra[1] == ' ' ) kextra++;
    }
    cmdline_parse(cmdline);

    parse_video_info();

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

    printk("Video information:\n");

    /* Print VGA display mode information. */
    switch ( vga_console_info.video_type )
    {
    case XEN_VGATYPE_TEXT_MODE_3:
        printk(" VGA is text mode %dx%d, font 8x%d\n",
               vga_console_info.u.text_mode_3.columns,
               vga_console_info.u.text_mode_3.rows,
               vga_console_info.u.text_mode_3.font_height);
        break;
    case XEN_VGATYPE_VESA_LFB:
        printk(" VGA is graphics mode %dx%d, %d bpp\n",
               vga_console_info.u.vesa_lfb.width,
               vga_console_info.u.vesa_lfb.height,
               vga_console_info.u.vesa_lfb.bits_per_pixel);
        break;
    default:
        printk(" No VGA detected\n");
        break;
    }

    /* Print VBE/DDC EDID information. */
    if ( bootsym(boot_edid_caps) != 0x1313 )
    {
        u16 caps = bootsym(boot_edid_caps);
        printk(" VBE/DDC methods:%s%s%s; ",
               (caps & 1) ? " V1" : "",
               (caps & 2) ? " V2" : "",
               !(caps & 3) ? " none" : "");
        printk("EDID transfer time: %d seconds\n", caps >> 8);
        if ( *(u32 *)bootsym(boot_edid_info) == 0x13131313 )
        {
            printk(" EDID info not retrieved because ");
            if ( !(caps & 3) )
                printk("no DDC retrieval method detected\n");
            else if ( (caps >> 8) > 5 )
                printk("takes longer than 5 seconds\n");
            else
                printk("of reasons unknown\n");
        }
    }

    printk("Disc information:\n");
    printk(" Found %d MBR signatures\n",
           bootsym(boot_mbr_signature_nr));
    printk(" Found %d EDD information structures\n",
           bootsym(boot_edd_info_nr));

    /* Check that we have at least one Multiboot module. */
    if ( !(mbi->flags & MBI_MODULES) || (mbi->mods_count == 0) )
        EARLY_FAIL("dom0 kernel not specified. "
                   "Check bootloader configuration.\n");

    if ( ((unsigned long)cpu0_stack & (STACK_SIZE-1)) != 0 )
        EARLY_FAIL("Misaligned CPU0 stack.\n");

    /*
     * Since there are some stubs getting built on the stacks which use
     * direct calls/jumps, the heap must be confined to the lower 2G so
     * that those branches can reach their targets.
     */
    if ( opt_xenheap_megabytes > 2048 )
        opt_xenheap_megabytes = 2048;

    if ( e820_raw_nr != 0 )
    {
        memmap_type = "Xen-e820";
    }
    else if ( bootsym(lowmem_kb) )
    {
        memmap_type = "Xen-e801";
        e820_raw[0].addr = 0;
        e820_raw[0].size = bootsym(lowmem_kb) << 10;
        e820_raw[0].type = E820_RAM;
        e820_raw[1].addr = 0x100000;
        e820_raw[1].size = bootsym(highmem_kb) << 10;
        e820_raw[1].type = E820_RAM;
        e820_raw_nr = 2;
    }
    else if ( mbi->flags & MBI_MEMMAP )
    {
        memmap_type = "Multiboot-e820";
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
                if ( !e820_warn )
                {
                    printk("WARNING: Buggy e820 map detected and fixed "
                           "(truncated length fields).\n");
                    e820_warn = 1;
                }
                map->length_high = 0;
            }

            e820_raw[e820_raw_nr].addr = 
                ((u64)map->base_addr_high << 32) | (u64)map->base_addr_low;
            e820_raw[e820_raw_nr].size = 
                ((u64)map->length_high << 32) | (u64)map->length_low;
            e820_raw[e820_raw_nr].type = map->type;
            e820_raw_nr++;

            bytes += map->size + 4;
        }
    }
    else if ( mbi->flags & MBI_MEMLIMITS )
    {
        memmap_type = "Multiboot-e801";
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
        EARLY_FAIL("Bootloader provided no memory information.\n");
    }

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
    max_page = init_e820(memmap_type, e820_raw, &e820_raw_nr);

    /*
     * Create a temporary copy of the E820 map. Truncate it to above 16MB
     * as anything below that is already mapped and has a statically-allocated
     * purpose.
     */
    memcpy(&boot_e820, &e820, sizeof(e820));
    for ( i = 0; i < boot_e820.nr_map; i++ )
    {
        uint64_t s, e, min = 16 << 20; /* 16MB */
        s = boot_e820.map[i].addr;
        e = boot_e820.map[i].addr + boot_e820.map[i].size;
        if ( s >= min )
            continue;
        if ( e > min )
        {
            boot_e820.map[i].addr = min;
            boot_e820.map[i].size = e - min;
        }
        else
            boot_e820.map[i].type = E820_RESERVED;
    }

    /*
     * Iterate backwards over all superpage-aligned RAM regions.
     * 
     * We require superpage alignment because the boot allocator is not yet
     * initialised. Hence we can only map superpages in the address range
     * 0 to BOOTSTRAP_DIRECTMAP_END, as this is guaranteed not to require
     * dynamic allocation of pagetables.
     * 
     * As well as mapping superpages in that range, in preparation for
     * initialising the boot allocator, we also look for a region to which
     * we can relocate the dom0 kernel and other multiboot modules. Also, on
     * x86/64, we relocate Xen to higher memory.
     */
    modules_length = mod[mbi->mods_count-1].mod_end - mod[0].mod_start;
    for ( i = boot_e820.nr_map-1; i >= 0; i-- )
    {
        uint64_t s, e, mask = (1UL << L2_PAGETABLE_SHIFT) - 1;

        /* Superpage-aligned chunks up to BOOTSTRAP_DIRECTMAP_END, please. */
        s = (boot_e820.map[i].addr + mask) & ~mask;
        e = (boot_e820.map[i].addr + boot_e820.map[i].size) & ~mask;
        e = min_t(uint64_t, e, BOOTSTRAP_DIRECTMAP_END);
        if ( (boot_e820.map[i].type != E820_RAM) || (s >= e) )
            continue;

        /* Map the chunk. No memory will need to be allocated to do this. */
        map_pages_to_xen(
            (unsigned long)maddr_to_bootstrap_virt(s),
            s >> PAGE_SHIFT, (e-s) >> PAGE_SHIFT, PAGE_HYPERVISOR);

#if defined(CONFIG_X86_64)
        /* Is the region suitable for relocating Xen? */
        if ( !xen_phys_start && (((e-s) >> 20) >= opt_xenheap_megabytes) )
        {
            extern l2_pgentry_t l2_xenmap[];
            l4_pgentry_t *pl4e;
            l3_pgentry_t *pl3e;
            l2_pgentry_t *pl2e;
            int i, j;

            /* Select relocation address. */
            e = (e - (opt_xenheap_megabytes << 20)) & ~mask;
            xen_phys_start = e;
            bootsym(trampoline_xen_phys_start) = e;

            /*
             * Perform relocation to new physical address.
             * Before doing so we must sync static/global data with main memory
             * with a barrier(). After this we must *not* modify static/global
             * data until after we have switched to the relocated pagetables!
             */
            barrier();
            move_memory(e, 0, __pa(&_end) - xen_phys_start);

            /* Poison low 1MB to detect stray pointers to physical 0-1MB. */
            memset(maddr_to_bootstrap_virt(e), 0x55, 1U<<20);

            /* Walk initial pagetables, relocating page directory entries. */
            pl4e = __va(__pa(idle_pg_table));
            for ( i = 0 ; i < L4_PAGETABLE_ENTRIES; i++, pl4e++ )
            {
                if ( !(l4e_get_flags(*pl4e) & _PAGE_PRESENT) )
                    continue;
                *pl4e = l4e_from_intpte(l4e_get_intpte(*pl4e) +
                                        xen_phys_start);
                pl3e = l4e_to_l3e(*pl4e);
                for ( j = 0; j < L3_PAGETABLE_ENTRIES; j++, pl3e++ )
                {
                    /* Not present or already relocated? */
                    if ( !(l3e_get_flags(*pl3e) & _PAGE_PRESENT) ||
                         (l3e_get_pfn(*pl3e) > 0x1000) )
                        continue;
                    *pl3e = l3e_from_intpte(l3e_get_intpte(*pl3e) +
                                            xen_phys_start);
                }
            }

            /* The only data mappings to be relocated are in the Xen area. */
            pl2e = __va(__pa(l2_xenmap));
            for ( i = 0; i < L2_PAGETABLE_ENTRIES; i++, pl2e++ )
            {
                if ( !(l2e_get_flags(*pl2e) & _PAGE_PRESENT) )
                    continue;
                *pl2e = l2e_from_intpte(l2e_get_intpte(*pl2e) +
                                        xen_phys_start);
            }

            /* Re-sync the stack and then switch to relocated pagetables. */
            asm volatile (
                "rep movsb        ; " /* re-sync the stack */
                "movq %%cr4,%%rsi ; "
                "andb $0x7f,%%sil ; "
                "movq %%rsi,%%cr4 ; " /* CR4.PGE == 0 */
                "movq %0,%%cr3    ; " /* CR3 == new pagetables */
                "orb $0x80,%%sil  ; "
                "movq %%rsi,%%cr4   " /* CR4.PGE == 1 */
                : : "r" (__pa(idle_pg_table)), "S" (cpu0_stack),
                "D" (__va(__pa(cpu0_stack))), "c" (STACK_SIZE) : "memory" );
        }
#endif

        /* Is the region suitable for relocating the multiboot modules? */
        if ( !initial_images_start && (s < e) && ((e-s) >= modules_length) )
        {
            initial_images_end = e;
            e = (e - modules_length) & PAGE_MASK;
            initial_images_start = e;
            move_memory(initial_images_start, 
                        mod[0].mod_start, mod[mbi->mods_count-1].mod_end);
        }

        if ( !kexec_crash_area.start && (s < e) &&
             ((e-s) >= kexec_crash_area.size) )
        {
            e = (e - kexec_crash_area.size) & PAGE_MASK;
            kexec_crash_area.start = e;
        }
    }

    if ( !initial_images_start )
        EARLY_FAIL("Not enough memory to relocate the dom0 kernel image.\n");
    reserve_in_boot_e820(initial_images_start, initial_images_end);

    /*
     * With modules (and Xen itself, on x86/64) relocated out of the way, we
     * can now initialise the boot allocator with some memory.
     */
    xenheap_phys_start = init_boot_allocator(__pa(&_end));
    xenheap_phys_end   = opt_xenheap_megabytes << 20;
#if defined(CONFIG_X86_64)
    if ( !xen_phys_start )
        EARLY_FAIL("Not enough memory to relocate Xen.\n");
    xenheap_phys_end += xen_phys_start;
    reserve_in_boot_e820(xen_phys_start,
                         xen_phys_start + (opt_xenheap_megabytes<<20));
    init_boot_pages(1<<20, 16<<20); /* Initial seed: 15MB */
#else
    init_boot_pages(xenheap_phys_end, 16<<20); /* Initial seed: 4MB */
#endif

    if ( kexec_crash_area.size != 0 )
    {
        unsigned long kdump_start = kexec_crash_area.start;
        unsigned long kdump_size  = kexec_crash_area.size;

        kdump_size = (kdump_size + PAGE_SIZE - 1) & PAGE_MASK;

        if ( !reserve_in_boot_e820(kdump_start, kdump_size) )
        {
            printk("Kdump: DISABLED (failed to reserve %luMB (%lukB) at 0x%lx)"
                   "\n", kdump_size >> 20, kdump_size >> 10, kdump_start);
            kexec_crash_area.start = kexec_crash_area.size = 0;
        }
        else
        {
            printk("Kdump: %luMB (%lukB) at 0x%lx\n",
                   kdump_size >> 20, kdump_size >> 10, kdump_start);
        }
    }

    /*
     * With the boot allocator now seeded, we can walk every RAM region and
     * map it in its entirety (on x86/64, at least) and notify it to the
     * boot allocator.
     */
    for ( i = 0; i < boot_e820.nr_map; i++ )
    {
        uint64_t s, e, map_e, mask = PAGE_SIZE - 1;

        /* Only page alignment required now. */
        s = (boot_e820.map[i].addr + mask) & ~mask;
        e = (boot_e820.map[i].addr + boot_e820.map[i].size) & ~mask;
        if ( (boot_e820.map[i].type != E820_RAM) || (s >= e) )
            continue;

        /* Perform the mapping (truncated in 32-bit mode). */
        map_e = e;
#if defined(CONFIG_X86_32)
        map_e = min_t(uint64_t, map_e, BOOTSTRAP_DIRECTMAP_END);
#endif
        if ( s < map_e )
            map_pages_to_xen(
                (unsigned long)maddr_to_bootstrap_virt(s),
                s >> PAGE_SHIFT, (map_e-s) >> PAGE_SHIFT, PAGE_HYPERVISOR);

        init_boot_pages(s, e);
    }

    memguard_init();

    nr_pages = 0;
    for ( i = 0; i < e820.nr_map; i++ )
        if ( e820.map[i].type == E820_RAM )
            nr_pages += e820.map[i].size >> PAGE_SHIFT;
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
    init_xenheap_pages(xenheap_phys_start, xenheap_phys_end);
    nr_pages = (xenheap_phys_end - xenheap_phys_start) >> PAGE_SHIFT;
#ifdef __x86_64__
    init_xenheap_pages(xen_phys_start, __pa(&_start));
    nr_pages += (__pa(&_start) - xen_phys_start) >> PAGE_SHIFT;
    vesa_init();
#endif
    xenheap_phys_start = xen_phys_start;
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

    dmi_scan_machine();

    generic_apic_probe();

    acpi_boot_init();

    init_cpu_to_node();

    if ( smp_found_config )
        get_smp_config();

#ifdef CONFIG_X86_64
    /* Low mappings were only needed for some BIOS table parsing. */
    zap_low_mappings();
#endif

    init_apic_mappings();

    init_IRQ();

    percpu_init_areas();

    xsm_init(&initrdidx, mbi, initial_images_start);

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
#ifdef CONFIG_X86_64
    vesa_mtrr_init();
#endif

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
    if ( (cmdline != NULL) || (kextra != NULL) )
    {
        static char dom0_cmdline[MAX_GUEST_CMDLINE];

        cmdline = cmdline_cook(cmdline);
        safe_strcpy(dom0_cmdline, cmdline);

        if ( kextra != NULL )
            /* kextra always includes exactly one leading space. */
            safe_strcat(dom0_cmdline, kextra);

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

    reset_stack_and_jump(init_done);
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
