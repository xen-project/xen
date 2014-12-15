#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/err.h>
#include <xen/sched.h>
#include <xen/sched-if.h>
#include <xen/domain.h>
#include <xen/serial.h>
#include <xen/softirq.h>
#include <xen/acpi.h>
#include <xen/efi.h>
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
#include <xen/dmi.h>
#include <xen/pfn.h>
#include <xen/nodemask.h>
#include <xen/tmem_xen.h> /* for opt_tmem only */
#include <xen/watchdog.h>
#include <public/version.h>
#include <compat/platform.h>
#include <compat/xen.h>
#include <xen/bitops.h>
#include <asm/smp.h>
#include <asm/processor.h>
#include <asm/mpspec.h>
#include <asm/apic.h>
#include <asm/msi.h>
#include <asm/desc.h>
#include <asm/paging.h>
#include <asm/e820.h>
#include <xen/kexec.h>
#include <asm/edd.h>
#include <xsm/xsm.h>
#include <asm/tboot.h>
#include <asm/bzimage.h> /* for bzimage_headroom */
#include <asm/mach-generic/mach_apic.h> /* for generic_apic_probe */
#include <asm/setup.h>
#include <xen/cpu.h>
#include <asm/nmi.h>
#include <asm/alternative.h>

/* opt_nosmp: If true, secondary processors are ignored. */
static bool_t __initdata opt_nosmp;
boolean_param("nosmp", opt_nosmp);

/* maxcpus: maximum number of CPUs to activate. */
static unsigned int __initdata max_cpus;
integer_param("maxcpus", max_cpus);

/* smep: Enable/disable Supervisor Mode Execution Protection (default on). */
static bool_t __initdata disable_smep;
invbool_param("smep", disable_smep);

/* smap: Enable/disable Supervisor Mode Access Prevention (default on). */
static bool_t __initdata disable_smap;
invbool_param("smap", disable_smap);

/* Boot dom0 in pvh mode */
static bool_t __initdata opt_dom0pvh;
boolean_param("dom0pvh", opt_dom0pvh);

/* **** Linux config option: propagated to domain0. */
/* "acpi=off":    Sisables both ACPI table parsing and interpreter. */
/* "acpi=force":  Override the disable blacklist.                   */
/* "acpi=ht":     Limit ACPI just to boot-time to enable HT.        */
/* "acpi=noirq":  Disables ACPI interrupt routing.                  */
static void parse_acpi_param(char *s);
custom_param("acpi", parse_acpi_param);

/* **** Linux config option: propagated to domain0. */
/* noapic: Disable IOAPIC setup. */
boolean_param("noapic", skip_ioapic_setup);

/* **** Linux config option: propagated to domain0. */
/* xen_cpuidle: xen control cstate. */
s8 __read_mostly xen_cpuidle = -1;
boolean_param("cpuidle", xen_cpuidle);

#ifndef NDEBUG
unsigned long __initdata highmem_start;
size_param("highmem-start", highmem_start);
#endif

cpumask_t __read_mostly cpu_present_map;

unsigned long __read_mostly xen_phys_start;

unsigned long __read_mostly xen_virt_end;

DEFINE_PER_CPU(struct tss_struct, init_tss);

char __attribute__ ((__section__(".bss.stack_aligned"))) cpu0_stack[STACK_SIZE];

struct cpuinfo_x86 __read_mostly boot_cpu_data = { 0, 0, 0, 0, -1 };

unsigned long __read_mostly mmu_cr4_features = XEN_MINIMAL_CR4;

bool_t __initdata acpi_disabled;
bool_t __initdata acpi_force;
static char __initdata acpi_param[10] = "";
static void __init parse_acpi_param(char *s)
{
    /* Save the parameter so it can be propagated to domain0. */
    safe_strcpy(acpi_param, s);

    /* Interpret the parameter for use within Xen. */
    if ( !parse_bool(s) )
    {
        disable_acpi();
    }
    else if ( !strcmp(s, "force") )
    {
        acpi_force = 1;
        acpi_ht = 1;
        acpi_disabled = 0;
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

static const module_t *__initdata initial_images;
static unsigned int __initdata nr_initial_images;

unsigned long __init initial_images_nrpages(void)
{
    unsigned long nr;
    unsigned int i;

    for ( nr = i = 0; i < nr_initial_images; ++i )
        nr += PFN_UP(initial_images[i].mod_end);

    return nr;
}

void __init discard_initial_images(void)
{
    unsigned int i;

    for ( i = 0; i < nr_initial_images; ++i )
    {
        uint64_t start = (uint64_t)initial_images[i].mod_start << PAGE_SHIFT;

        init_domheap_pages(start,
                           start + PAGE_ALIGN(initial_images[i].mod_end));
    }

    nr_initial_images = 0;
    initial_images = NULL;
}

static void free_xen_data(char *s, char *e)
{
#ifndef MEMORY_GUARD
    init_xenheap_pages(__pa(s), __pa(e));
#endif
    memguard_guard_range(s, e-s);
    /* Also zap the mapping in the 1:1 area. */
    memguard_guard_range(__va(__pa(s)), e-s);
}

extern char __init_begin[], __init_end[], __bss_start[];

static void __init init_idle_domain(void)
{
    scheduler_init();
    set_current(idle_vcpu[0]);
    this_cpu(curr_vcpu) = current;
}

void __devinit srat_detect_node(int cpu)
{
    unsigned node;
    u32 apicid = x86_cpu_to_apicid[cpu];

    node = apicid_to_node[apicid];
    if ( node == NUMA_NO_NODE )
        node = 0;

    node_set_online(node);
    numa_set_node(cpu, node);

    if ( opt_cpu_info && acpi_numa > 0 )
        printk("CPU %d APIC %d -> Node %d\n", cpu, apicid, node);
}

/*
 * Sort CPUs by <node,package,core,thread> tuple. Fortunately this hierarchy is
 * reflected in the structure of modern APIC identifiers, so we sort based on
 * those. This is slightly complicated by the fact that the BSP must remain
 * CPU 0. Hence we do a variation on longest-prefix matching to do the best we
 * can while keeping CPU 0 static.
 */
static void __init normalise_cpu_order(void)
{
    unsigned int i, j, min_cpu;
    uint32_t apicid, diff, min_diff;

    for_each_present_cpu ( i )
    {
        apicid = x86_cpu_to_apicid[i];
        min_diff = min_cpu = ~0u;

        /*
         * Find remaining CPU with longest-prefix match on APIC ID.
         * Among identical longest-prefix matches, pick the smallest APIC ID.
         */
        for ( j = cpumask_next(i, &cpu_present_map);
              j < nr_cpu_ids;
              j = cpumask_next(j, &cpu_present_map) )
        {
            diff = x86_cpu_to_apicid[j] ^ apicid;
            while ( diff & (diff-1) )
                diff &= diff-1;
            if ( (diff < min_diff) ||
                 ((diff == min_diff) &&
                  (x86_cpu_to_apicid[j] < x86_cpu_to_apicid[min_cpu])) )
            {
                min_diff = diff;
                min_cpu = j;
            }
        }

        /* If no match then there must be no CPUs remaining to consider. */
        if ( min_cpu >= nr_cpu_ids )
        {
            BUG_ON(cpumask_next(i, &cpu_present_map) < nr_cpu_ids);
            break;
        }

        /* Switch the best-matching CPU with the next CPU in logical order. */
        j = cpumask_next(i, &cpu_present_map);
        apicid = x86_cpu_to_apicid[min_cpu];
        x86_cpu_to_apicid[min_cpu] = x86_cpu_to_apicid[j];
        x86_cpu_to_apicid[j] = apicid;
    }
}

#define BOOTSTRAP_MAP_BASE  (16UL << 20)
#define BOOTSTRAP_MAP_LIMIT (1UL << L3_PAGETABLE_SHIFT)

/*
 * Ensure a given physical memory range is present in the bootstrap mappings.
 * Use superpage mappings to ensure that pagetable memory needn't be allocated.
 */
static void *__init bootstrap_map(const module_t *mod)
{
    static unsigned long __initdata map_cur = BOOTSTRAP_MAP_BASE;
    uint64_t start, end, mask = (1L << L2_PAGETABLE_SHIFT) - 1;
    void *ret;

    if ( system_state != SYS_STATE_early_boot )
        return mod ? mfn_to_virt(mod->mod_start) : NULL;

    if ( !mod )
    {
        destroy_xen_mappings(BOOTSTRAP_MAP_BASE, BOOTSTRAP_MAP_LIMIT);
        map_cur = BOOTSTRAP_MAP_BASE;
        return NULL;
    }

    start = (uint64_t)mod->mod_start << PAGE_SHIFT;
    end = start + mod->mod_end;
    if ( start >= end )
        return NULL;

    if ( end <= BOOTSTRAP_MAP_BASE )
        return (void *)(unsigned long)start;

    ret = (void *)(map_cur + (unsigned long)(start & mask));
    start &= ~mask;
    end = (end + mask) & ~mask;
    if ( end - start > BOOTSTRAP_MAP_LIMIT - map_cur )
        return NULL;

    map_pages_to_xen(map_cur, start >> PAGE_SHIFT,
                     (end - start) >> PAGE_SHIFT, PAGE_HYPERVISOR);
    map_cur += end - start;
    return ret;
}

static void *__init move_memory(
    uint64_t dst, uint64_t src, unsigned int size, bool_t keep)
{
    unsigned int blksz = BOOTSTRAP_MAP_LIMIT - BOOTSTRAP_MAP_BASE;
    unsigned int mask = (1L << L2_PAGETABLE_SHIFT) - 1;

    if ( src + size > BOOTSTRAP_MAP_BASE )
        blksz >>= 1;

    while ( size )
    {
        module_t mod;
        unsigned int soffs = src & mask;
        unsigned int doffs = dst & mask;
        unsigned int sz;
        void *d, *s;

        mod.mod_start = (src - soffs) >> PAGE_SHIFT;
        mod.mod_end = soffs + size;
        if ( mod.mod_end > blksz )
            mod.mod_end = blksz;
        sz = mod.mod_end - soffs;
        s = bootstrap_map(&mod);

        mod.mod_start = (dst - doffs) >> PAGE_SHIFT;
        mod.mod_end = doffs + size;
        if ( mod.mod_end > blksz )
            mod.mod_end = blksz;
        if ( sz > mod.mod_end - doffs )
            sz = mod.mod_end - doffs;
        d = bootstrap_map(&mod);

        memmove(d + doffs, s + soffs, sz);

        dst += sz;
        src += sz;
        size -= sz;

        if ( keep )
            return size ? NULL : d + doffs;

        bootstrap_map(NULL);
    }

    return NULL;
}

static uint64_t __init consider_modules(
    uint64_t s, uint64_t e, uint32_t size, const module_t *mod,
    unsigned int nr_mods, unsigned int this_mod)
{
    unsigned int i;

    if ( s > e || e - s < size )
        return 0;

    for ( i = 0; i < nr_mods ; ++i )
    {
        uint64_t start = (uint64_t)mod[i].mod_start << PAGE_SHIFT;
        uint64_t end = start + PAGE_ALIGN(mod[i].mod_end);

        if ( i == this_mod )
            continue;

        if ( s < end && start < e )
        {
            end = consider_modules(end, e, size, mod + i + 1,
                                   nr_mods - i - 1, this_mod - i - 1);
            if ( end )
                return end;

            return consider_modules(s, start, size, mod + i + 1,
                                    nr_mods - i - 1, this_mod - i - 1);
        }
    }

    return e;
}

static void __init setup_max_pdx(unsigned long top_page)
{
    max_pdx = pfn_to_pdx(top_page - 1) + 1;

    if ( max_pdx > (DIRECTMAP_SIZE >> PAGE_SHIFT) )
        max_pdx = DIRECTMAP_SIZE >> PAGE_SHIFT;

    if ( max_pdx > FRAMETABLE_NR )
        max_pdx = FRAMETABLE_NR;

    if ( max_pdx >= PAGE_LIST_NULL )
        max_pdx = PAGE_LIST_NULL - 1;

    max_page = pdx_to_pfn(max_pdx - 1) + 1;
}

/* A temporary copy of the e820 map that we can mess with during bootstrap. */
static struct e820map __initdata boot_e820;

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
    u16 vesa_attrib;        /* 0x28 */
};
extern struct boot_video_info boot_vid_info;

static void __init parse_video_info(void)
{
    struct boot_video_info *bvi = &bootsym(boot_vid_info);

    /* The EFI loader fills vga_console_info directly. */
    if ( efi_enabled )
        return;

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
        vga_console_info.u.vesa_lfb.gbl_caps = bvi->capabilities;
        vga_console_info.u.vesa_lfb.mode_attrs = bvi->vesa_attrib;
    }
}

static void __init kexec_reserve_area(struct e820map *e820)
{
    unsigned long kdump_start = kexec_crash_area.start;
    unsigned long kdump_size  = kexec_crash_area.size;
    static bool_t __initdata is_reserved = 0;

    kdump_size = (kdump_size + PAGE_SIZE - 1) & PAGE_MASK;

    if ( (kdump_start == 0) || (kdump_size == 0) || is_reserved )
        return;

    is_reserved = 1;

    if ( !reserve_e820_ram(e820, kdump_start, kdump_start + kdump_size) )
    {
        printk("Kdump: DISABLED (failed to reserve %luMB (%lukB) at %#lx)"
               "\n", kdump_size >> 20, kdump_size >> 10, kdump_start);
        kexec_crash_area.start = kexec_crash_area.size = 0;
    }
    else
    {
        printk("Kdump: %luMB (%lukB) at %#lx\n",
               kdump_size >> 20, kdump_size >> 10, kdump_start);
    }
}

static void noinline init_done(void)
{
    /* Free (or page-protect) the init areas. */
    memset(__init_begin, 0xcc, __init_end - __init_begin); /* int3 poison */
    free_xen_data(__init_begin, __init_end);
    printk("Freed %ldkB init memory.\n", (long)(__init_end-__init_begin)>>10);

    startup_cpu_idle_loop();
}

static bool_t __init loader_is_grub2(const char *loader_name)
{
    /* GRUB1="GNU GRUB 0.xx"; GRUB2="GRUB 1.xx" */
    const char *p = strstr(loader_name, "GRUB ");
    return (p != NULL) && (p[5] != '0');
}

static char * __init cmdline_cook(char *p, const char *loader_name)
{
    p = p ? : "";

    /* Strip leading whitespace. */
    while ( *p == ' ' )
        p++;

    /* GRUB2 does not include image name as first item on command line. */
    if ( loader_is_grub2(loader_name) )
        return p;

    /* Strip image name plus whitespace. */
    while ( (*p != ' ') && (*p != '\0') )
        p++;
    while ( *p == ' ' )
        p++;

    return p;
}

void __init noreturn __start_xen(unsigned long mbi_p)
{
    char *memmap_type = NULL;
    char *cmdline, *kextra, *loader;
    unsigned int initrdidx, domcr_flags = DOMCRF_s3_integrity;
    multiboot_info_t *mbi = __va(mbi_p);
    module_t *mod = (module_t *)__va(mbi->mods_addr);
    unsigned long nr_pages, raw_max_page, modules_headroom, *module_map;
    int i, j, e820_warn = 0, bytes = 0;
    bool_t acpi_boot_table_init_done = 0;
    struct domain *dom0;
    struct ns16550_defaults ns16550 = {
        .data_bits = 8,
        .parity    = 'n',
        .stop_bits = 1
    };

    /* Critical region without IDT or TSS.  Any fault is deadly! */

    set_processor_id(0);
    set_current((struct vcpu *)0xfffff000); /* debug sanity. */
    idle_vcpu[0] = current;

    percpu_init_areas();

    init_idt_traps();
    load_system_tables();

    smp_prepare_boot_cpu();
    sort_exception_tables();

    /* Full exception support from here on in. */

    loader = (mbi->flags & MBI_LOADERNAME)
        ? (char *)__va(mbi->boot_loader_name) : "unknown";

    /* Parse the command-line options. */
    cmdline = cmdline_cook((mbi->flags & MBI_CMDLINE) ?
                           __va(mbi->cmdline) : NULL,
                           loader);
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

    /* Must be after command line argument parsing and before
     * allocing any xenheap structures wanted in lower memory. */
    kexec_early_calculations();

    parse_video_info();

    if ( cpu_has_efer )
        rdmsrl(MSR_EFER, this_cpu(efer));
    asm volatile ( "mov %%cr4,%0" : "=r" (this_cpu(cr4)) );

    /* We initialise the serial devices very early so we can get debugging. */
    ns16550.io_base = 0x3f8;
    ns16550.irq     = 4;
    ns16550_init(0, &ns16550);
    ns16550.io_base = 0x2f8;
    ns16550.irq     = 3;
    ns16550_init(1, &ns16550);
    ehci_dbgp_init();
    console_init_preirq();

    printk("Bootloader: %s\n", loader);

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
    case XEN_VGATYPE_EFI_LFB:
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
        panic("dom0 kernel not specified. Check bootloader configuration.");

    if ( ((unsigned long)cpu0_stack & (STACK_SIZE-1)) != 0 )
        panic("Misaligned CPU0 stack.");

    if ( efi_enabled )
    {
        set_pdx_range(xen_phys_start >> PAGE_SHIFT,
                      (xen_phys_start + BOOTSTRAP_MAP_BASE) >> PAGE_SHIFT);

        /* Clean up boot loader identity mappings. */
        destroy_xen_mappings(xen_phys_start,
                             xen_phys_start + BOOTSTRAP_MAP_BASE);

        /* Make boot page tables match non-EFI boot. */
        l3_bootmap[l3_table_offset(BOOTSTRAP_MAP_BASE)] =
            l3e_from_paddr(__pa(l2_bootmap), __PAGE_HYPERVISOR);

        memmap_type = loader;
    }
    else if ( e820_raw_nr != 0 )
    {
        memmap_type = "Xen-e820";
    }
    else if ( mbi->flags & MBI_MEMMAP )
    {
        memmap_type = "Multiboot-e820";
        while ( (bytes < mbi->mmap_length) && (e820_raw_nr < E820MAX) )
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
        panic("Bootloader provided no memory information.");

    /* Sanitise the raw E820 map to produce a final clean version. */
    max_page = raw_max_page = init_e820(memmap_type, e820_raw, &e820_raw_nr);

    /* Create a temporary copy of the E820 map. */
    memcpy(&boot_e820, &e820, sizeof(e820));

    /* Early kexec reservation (explicit static start address). */
    nr_pages = 0;
    for ( i = 0; i < e820.nr_map; i++ )
        if ( e820.map[i].type == E820_RAM )
            nr_pages += e820.map[i].size >> PAGE_SHIFT;
    set_kexec_crash_area_size((u64)nr_pages << PAGE_SHIFT);
    kexec_reserve_area(&boot_e820);

    initial_images = mod;
    nr_initial_images = mbi->mods_count;

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
    for ( i = 0; !efi_enabled && i < mbi->mods_count; i++ )
    {
        if ( mod[i].mod_start & (PAGE_SIZE - 1) )
            panic("Bootloader didn't honor module alignment request.");
        mod[i].mod_end -= mod[i].mod_start;
        mod[i].mod_start >>= PAGE_SHIFT;
        mod[i].reserved = 0;
    }

    modules_headroom = bzimage_headroom(bootstrap_map(mod), mod->mod_end);
    bootstrap_map(NULL);

#ifndef highmem_start
    /* Don't allow split below 4Gb. */
    if ( highmem_start < GB(4) )
        highmem_start = 0;
    else /* align to L3 entry boundary */
        highmem_start &= ~((1UL << L3_PAGETABLE_SHIFT) - 1);
#endif

    for ( i = boot_e820.nr_map-1; i >= 0; i-- )
    {
        uint64_t s, e, mask = (1UL << L2_PAGETABLE_SHIFT) - 1;
        uint64_t end, limit = ARRAY_SIZE(l2_identmap) << L2_PAGETABLE_SHIFT;

        /* Superpage-aligned chunks from BOOTSTRAP_MAP_BASE. */
        s = (boot_e820.map[i].addr + mask) & ~mask;
        e = (boot_e820.map[i].addr + boot_e820.map[i].size) & ~mask;
        s = max_t(uint64_t, s, BOOTSTRAP_MAP_BASE);
        if ( (boot_e820.map[i].type != E820_RAM) || (s >= e) )
            continue;

        if ( s < limit )
        {
            end = min(e, limit);
            set_pdx_range(s >> PAGE_SHIFT, end >> PAGE_SHIFT);
            map_pages_to_xen((unsigned long)__va(s), s >> PAGE_SHIFT,
                             (end - s) >> PAGE_SHIFT, PAGE_HYPERVISOR);
        }

        if ( e > min(HYPERVISOR_VIRT_END - DIRECTMAP_VIRT_START,
                     1UL << (PAGE_SHIFT + 32)) )
            e = min(HYPERVISOR_VIRT_END - DIRECTMAP_VIRT_START,
                    1UL << (PAGE_SHIFT + 32));
#define reloc_size ((__pa(&_end) + mask) & ~mask)
        /* Is the region suitable for relocating Xen? */
        if ( !xen_phys_start && e <= limit )
        {
            /* Don't overlap with modules. */
            end = consider_modules(s, e, reloc_size + mask,
                                   mod, mbi->mods_count, -1);
            end &= ~mask;
        }
        else
            end = 0;
        if ( end > s )
        {
            l4_pgentry_t *pl4e;
            l3_pgentry_t *pl3e;
            l2_pgentry_t *pl2e;
            uint64_t load_start;
            int i, j, k;

            /* Select relocation address. */
            e = end - reloc_size;
            xen_phys_start = e;
            bootsym(trampoline_xen_phys_start) = e;

            /*
             * Perform relocation to new physical address.
             * Before doing so we must sync static/global data with main memory
             * with a barrier(). After this we must *not* modify static/global
             * data until after we have switched to the relocated pagetables!
             */
            load_start = (unsigned long)_start - XEN_VIRT_START;
            barrier();
            move_memory(e + load_start, load_start, _end - _start, 1);

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
                    /* Not present, 1GB mapping, or already relocated? */
                    if ( !(l3e_get_flags(*pl3e) & _PAGE_PRESENT) ||
                         (l3e_get_flags(*pl3e) & _PAGE_PSE) ||
                         (l3e_get_pfn(*pl3e) > 0x1000) )
                        continue;
                    *pl3e = l3e_from_intpte(l3e_get_intpte(*pl3e) +
                                            xen_phys_start);
                    pl2e = l3e_to_l2e(*pl3e);
                    for ( k = 0; k < L2_PAGETABLE_ENTRIES; k++, pl2e++ )
                    {
                        /* Not present, PSE, or already relocated? */
                        if ( !(l2e_get_flags(*pl2e) & _PAGE_PRESENT) ||
                             (l2e_get_flags(*pl2e) & _PAGE_PSE) ||
                             (l2e_get_pfn(*pl2e) > 0x1000) )
                            continue;
                        *pl2e = l2e_from_intpte(l2e_get_intpte(*pl2e) +
                                                xen_phys_start);
                    }
                }
            }

            /* The only data mappings to be relocated are in the Xen area. */
            pl2e = __va(__pa(l2_xenmap));
            *pl2e++ = l2e_from_pfn(xen_phys_start >> PAGE_SHIFT,
                                   PAGE_HYPERVISOR | _PAGE_PSE);
            for ( i = 1; i < L2_PAGETABLE_ENTRIES; i++, pl2e++ )
            {
                if ( !(l2e_get_flags(*pl2e) & _PAGE_PRESENT) )
                    continue;
                *pl2e = l2e_from_intpte(l2e_get_intpte(*pl2e) +
                                        xen_phys_start);
            }

            /* Re-sync the stack and then switch to relocated pagetables. */
            asm volatile (
                "rep movsq        ; " /* re-sync the stack */
                "movq %%cr4,%%rsi ; "
                "andb $0x7f,%%sil ; "
                "movq %%rsi,%%cr4 ; " /* CR4.PGE == 0 */
                "movq %[pg],%%cr3 ; " /* CR3 == new pagetables */
                "orb $0x80,%%sil  ; "
                "movq %%rsi,%%cr4   " /* CR4.PGE == 1 */
                : "=&S" (i), "=&D" (i), "=&c" (i) /* All outputs discarded. */
                :  [pg] "r" (__pa(idle_pg_table)), "0" (cpu0_stack),
                   "1" (__va(__pa(cpu0_stack))), "2" (STACK_SIZE / 8)
                : "memory" );

            bootstrap_map(NULL);
        }

        /* Is the region suitable for relocating the multiboot modules? */
        for ( j = mbi->mods_count - 1; j >= 0; j-- )
        {
            unsigned long headroom = j ? 0 : modules_headroom;
            unsigned long size = PAGE_ALIGN(headroom + mod[j].mod_end);

            if ( mod[j].reserved )
                continue;

            /* Don't overlap with other modules. */
            end = consider_modules(s, e, size, mod, mbi->mods_count, j);

            if ( highmem_start && end > highmem_start )
                continue;

            if ( s < end &&
                 (headroom ||
                  ((end - size) >> PAGE_SHIFT) > mod[j].mod_start) )
            {
                move_memory(end - size + headroom,
                            (uint64_t)mod[j].mod_start << PAGE_SHIFT,
                            mod[j].mod_end, 0);
                mod[j].mod_start = (end - size) >> PAGE_SHIFT;
                mod[j].mod_end += headroom;
                mod[j].reserved = 1;
            }
        }

        /* Don't overlap with modules. */
        e = consider_modules(s, e, PAGE_ALIGN(kexec_crash_area.size),
                             mod, mbi->mods_count, -1);
        if ( !kexec_crash_area.start && (s < e) )
        {
            e = (e - kexec_crash_area.size) & PAGE_MASK;
            kexec_crash_area.start = e;
        }
    }

    if ( modules_headroom && !mod->reserved )
        panic("Not enough memory to relocate the dom0 kernel image.");
    for ( i = 0; i < mbi->mods_count; ++i )
    {
        uint64_t s = (uint64_t)mod[i].mod_start << PAGE_SHIFT;

        reserve_e820_ram(&boot_e820, s, s + PAGE_ALIGN(mod[i].mod_end));
    }

    if ( !xen_phys_start )
        panic("Not enough memory to relocate Xen.");
    reserve_e820_ram(&boot_e820, efi_enabled ? mbi->mem_upper : __pa(&_start),
                     __pa(&_end));

    /* Late kexec reservation (dynamic start address). */
    kexec_reserve_area(&boot_e820);

    setup_max_pdx(raw_max_page);
    if ( highmem_start )
        xenheap_max_mfn(PFN_DOWN(highmem_start));

    /*
     * Walk every RAM region and map it in its entirety (on x86/64, at least)
     * and notify it to the boot allocator.
     */
    for ( i = 0; i < boot_e820.nr_map; i++ )
    {
        uint64_t s, e, mask = PAGE_SIZE - 1;
        uint64_t map_s, map_e;

        /* Only page alignment required now. */
        s = (boot_e820.map[i].addr + mask) & ~mask;
        e = (boot_e820.map[i].addr + boot_e820.map[i].size) & ~mask;
        s = max_t(uint64_t, s, 1<<20);
        if ( (boot_e820.map[i].type != E820_RAM) || (s >= e) )
            continue;

        if ( !acpi_boot_table_init_done &&
             s >= (1ULL << 32) &&
             !acpi_boot_table_init() )
        {
            acpi_boot_table_init_done = 1;
            srat_parse_regions(s);
            setup_max_pdx(raw_max_page);
        }

        if ( pfn_to_pdx((e - 1) >> PAGE_SHIFT) >= max_pdx )
        {
            if ( pfn_to_pdx(s >> PAGE_SHIFT) >= max_pdx )
            {
                for ( j = i - 1; ; --j )
                {
                    if ( boot_e820.map[j].type == E820_RAM )
                        break;
                    ASSERT(j);
                }
                map_e = boot_e820.map[j].addr + boot_e820.map[j].size;
                for ( j = 0; j < mbi->mods_count; ++j )
                {
                    uint64_t end = pfn_to_paddr(mod[j].mod_start) +
                                   mod[j].mod_end;

                    if ( map_e < end )
                        map_e = end;
                }
                if ( PFN_UP(map_e) < max_page )
                {
                    max_page = PFN_UP(map_e);
                    max_pdx = pfn_to_pdx(max_page - 1) + 1;
                }
                printk(XENLOG_WARNING "Ignoring inaccessible memory range"
                                      " %013"PRIx64"-%013"PRIx64"\n",
                       s, e);
                continue;
            }
            map_e = e;
            e = (pdx_to_pfn(max_pdx - 1) + 1ULL) << PAGE_SHIFT;
            printk(XENLOG_WARNING "Ignoring inaccessible memory range"
                                  " %013"PRIx64"-%013"PRIx64"\n",
                   e, map_e);
        }

        set_pdx_range(s >> PAGE_SHIFT, e >> PAGE_SHIFT);

        /* Need to create mappings above BOOTSTRAP_MAP_BASE. */
        map_s = max_t(uint64_t, s, BOOTSTRAP_MAP_BASE);
        map_e = min_t(uint64_t, e,
                      ARRAY_SIZE(l2_identmap) << L2_PAGETABLE_SHIFT);

        /* Pass mapped memory to allocator /before/ creating new mappings. */
        init_boot_pages(s, min(map_s, e));
        s = map_s;
        if ( s < map_e )
        {
            uint64_t mask = (1UL << L2_PAGETABLE_SHIFT) - 1;

            map_s = (s + mask) & ~mask;
            map_e &= ~mask;
            init_boot_pages(map_s, map_e);
        }

        if ( map_s > map_e )
            map_s = map_e = s;

        /* Create new mappings /before/ passing memory to the allocator. */
        if ( map_e < e )
        {
            uint64_t limit = __pa(HYPERVISOR_VIRT_END - 1) + 1;
            uint64_t end = min(e, limit);

            if ( map_e < end )
            {
                map_pages_to_xen((unsigned long)__va(map_e), PFN_DOWN(map_e),
                                 PFN_DOWN(end - map_e), PAGE_HYPERVISOR);
                init_boot_pages(map_e, end);
                map_e = end;
            }
        }
        if ( map_e < e )
        {
            /* This range must not be passed to the boot allocator and
             * must also not be mapped with _PAGE_GLOBAL. */
            map_pages_to_xen((unsigned long)__va(map_e), PFN_DOWN(map_e),
                             PFN_DOWN(e - map_e), __PAGE_HYPERVISOR);
        }
        if ( s < map_s )
        {
            map_pages_to_xen((unsigned long)__va(s), s >> PAGE_SHIFT,
                             (map_s - s) >> PAGE_SHIFT, PAGE_HYPERVISOR);
            init_boot_pages(s, map_s);
        }
    }

    for ( i = 0; i < mbi->mods_count; ++i )
    {
        set_pdx_range(mod[i].mod_start,
                      mod[i].mod_start + PFN_UP(mod[i].mod_end));
        map_pages_to_xen((unsigned long)mfn_to_virt(mod[i].mod_start),
                         mod[i].mod_start,
                         PFN_UP(mod[i].mod_end), PAGE_HYPERVISOR);
    }

    if ( kexec_crash_area.size )
    {
        unsigned long s = PFN_DOWN(kexec_crash_area.start);
        unsigned long e = min(s + PFN_UP(kexec_crash_area.size),
                              PFN_UP(__pa(HYPERVISOR_VIRT_END - 1)));

        if ( e > s ) 
            map_pages_to_xen((unsigned long)__va(kexec_crash_area.start),
                             s, e - s, PAGE_HYPERVISOR);
    }

    xen_virt_end = ((unsigned long)_end + (1UL << L2_PAGETABLE_SHIFT) - 1) &
                   ~((1UL << L2_PAGETABLE_SHIFT) - 1);
    destroy_xen_mappings(xen_virt_end, XEN_VIRT_START + BOOTSTRAP_MAP_BASE);

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

    BUILD_BUG_ON(sizeof(((struct compat_platform_op *)0)->u) !=
                 sizeof(((struct compat_platform_op *)0)->u.pad));
    BUILD_BUG_ON(sizeof(start_info_compat_t) > PAGE_SIZE);
    BUILD_BUG_ON(sizeof(struct compat_vcpu_info) != 64);

    /* Check definitions in public headers match internal defs. */
    BUILD_BUG_ON(__HYPERVISOR_VIRT_START != HYPERVISOR_VIRT_START);
    BUILD_BUG_ON(__HYPERVISOR_VIRT_END   != HYPERVISOR_VIRT_END);
    BUILD_BUG_ON(MACH2PHYS_VIRT_START != RO_MPT_VIRT_START);
    BUILD_BUG_ON(MACH2PHYS_VIRT_END   != RO_MPT_VIRT_END);

    init_frametable();

    if ( !acpi_boot_table_init_done )
        acpi_boot_table_init();

    acpi_numa_init();

    numa_initmem_init(0, raw_max_page);

    end_boot_allocator();
    system_state = SYS_STATE_boot;

    if ( max_page - 1 > virt_to_mfn(HYPERVISOR_VIRT_END - 1) )
    {
        unsigned long limit = virt_to_mfn(HYPERVISOR_VIRT_END - 1);
        uint64_t mask = PAGE_SIZE - 1;

        if ( !highmem_start )
            xenheap_max_mfn(limit);

        /* Pass the remaining memory to the allocator. */
        for ( i = 0; i < boot_e820.nr_map; i++ )
        {
            uint64_t s, e;

            if ( boot_e820.map[i].type != E820_RAM )
                continue;
            s = (boot_e820.map[i].addr + mask) & ~mask;
            e = (boot_e820.map[i].addr + boot_e820.map[i].size) & ~mask;
            if ( PFN_DOWN(e) <= limit )
                continue;
            if ( PFN_DOWN(s) <= limit )
                s = pfn_to_paddr(limit + 1);
            init_domheap_pages(s, e);
        }

        if ( opt_tmem )
        {
           printk(XENLOG_WARNING
                  "TMEM physical RAM limit exceeded, disabling TMEM\n");
           opt_tmem = 0;
        }
    }

    vm_init();
    console_init_ring();
    vesa_init();

    softirq_init();
    tasklet_subsys_init();

    early_cpu_init();

    paging_init();

    tboot_probe();

    /* Unmap the first page of CPU0's stack. */
    memguard_guard_stack(cpu0_stack);

    open_softirq(NEW_TLBFLUSH_CLOCK_PERIOD_SOFTIRQ, new_tlbflush_clock_period);

    if ( opt_watchdog ) 
        nmi_watchdog = NMI_LOCAL_APIC;

    find_smp_config();

    dmi_scan_machine();

    generic_apic_probe();

    acpi_boot_init();

    if ( smp_found_config )
        get_smp_config();

    if ( opt_nosmp )
    {
        max_cpus = 0;
        set_nr_cpu_ids(1);
    }
    else
    {
        set_nr_cpu_ids(max_cpus);
        max_cpus = nr_cpu_ids;
    }

    /* Low mappings were only needed for some BIOS table parsing. */
    zap_low_mappings();

    mmio_ro_ranges = rangeset_new(NULL, "r/o mmio ranges",
                                  RANGESETF_prettyprint_hex);

    init_apic_mappings();

    normalise_cpu_order();

    init_cpu_to_node();

    x2apic_bsp_setup();

    init_IRQ();

    module_map = xmalloc_array(unsigned long, BITS_TO_LONGS(mbi->mods_count));
    bitmap_fill(module_map, mbi->mods_count);
    __clear_bit(0, module_map); /* Dom0 kernel is always first */

    xsm_multiboot_init(module_map, mbi, bootstrap_map);

    microcode_grab_module(module_map, mbi, bootstrap_map);

    timer_init();

    init_idle_domain();

    trap_init();

    rcu_init();
    
    early_time_init();

    arch_init_memory();

    identify_cpu(&boot_cpu_data);

    if ( cpu_has_fxsr )
        set_in_cr4(X86_CR4_OSFXSR);
    if ( cpu_has_xmm )
        set_in_cr4(X86_CR4_OSXMMEXCPT);

    if ( disable_smep )
        setup_clear_cpu_cap(X86_FEATURE_SMEP);
    if ( cpu_has_smep )
        set_in_cr4(X86_CR4_SMEP);

    if ( disable_smap )
        setup_clear_cpu_cap(X86_FEATURE_SMAP);
    if ( cpu_has_smap )
        set_in_cr4(X86_CR4_SMAP);

    if ( cpu_has_fsgsbase )
        set_in_cr4(X86_CR4_FSGSBASE);

    alternative_instructions();

    local_irq_enable();

    pt_pci_init();

    vesa_mtrr_init();

    acpi_mmcfg_init();

    early_msi_init();

    iommu_setup();    /* setup iommu if available */

    smp_prepare_cpus(max_cpus);

    spin_debug_enable();

    /*
     * Initialise higher-level timer functions. We do this fairly late
     * (after interrupts got enabled) because the time bases and scale
     * factors need to be updated regularly.
     */
    init_xen_time();

    initialize_keytable();

    console_init_postirq();

    system_state = SYS_STATE_smp_boot;

    do_presmp_initcalls();

    for_each_present_cpu ( i )
    {
        /* Set up cpu_to_node[]. */
        srat_detect_node(i);
        /* Set up node_to_cpumask based on cpu_to_node[]. */
        numa_add_cpu(i);        

        if ( (num_online_cpus() < max_cpus) && !cpu_online(i) )
        {
            int ret = cpu_up(i);
            if ( ret != 0 )
                printk("Failed to bring up CPU %u (error %d)\n", i, ret);
        }
    }

    printk("Brought up %ld CPUs\n", (long)num_online_cpus());
    smp_cpus_done();

    do_initcalls();

    if ( opt_watchdog ) 
        watchdog_setup();

    if ( !tboot_protect_mem_regions() )
        panic("Could not protect TXT memory regions");

    if ( opt_dom0pvh )
        domcr_flags |= DOMCRF_pvh | DOMCRF_hap;

    /* Create initial domain 0. */
    dom0 = domain_create(0, domcr_flags, 0);
    if ( IS_ERR(dom0) || (alloc_dom0_vcpu0(dom0) == NULL) )
        panic("Error creating domain 0");

    dom0->is_privileged = 1;
    dom0->target = NULL;

    /* Grab the DOM0 command line. */
    cmdline = (char *)(mod[0].string ? __va(mod[0].string) : NULL);
    if ( (cmdline != NULL) || (kextra != NULL) )
    {
        static char __initdata dom0_cmdline[MAX_GUEST_CMDLINE];

        cmdline = cmdline_cook(cmdline, loader);
        safe_strcpy(dom0_cmdline, cmdline);

        if ( kextra != NULL )
            /* kextra always includes exactly one leading space. */
            safe_strcat(dom0_cmdline, kextra);

        /* Append any extra parameters. */
        if ( skip_ioapic_setup && !strstr(dom0_cmdline, "noapic") )
            safe_strcat(dom0_cmdline, " noapic");
        if ( (strlen(acpi_param) == 0) && acpi_disabled )
        {
            printk("ACPI is disabled, notifying Domain 0 (acpi=off)\n");
            safe_strcpy(acpi_param, "off");
        }
        if ( (strlen(acpi_param) != 0) && !strstr(dom0_cmdline, "acpi=") )
        {
            safe_strcat(dom0_cmdline, " acpi=");
            safe_strcat(dom0_cmdline, acpi_param);
        }

        cmdline = dom0_cmdline;
    }

    if ( xen_cpuidle )
        xen_processor_pmbits |= XEN_PROCESSOR_PM_CX;

    initrdidx = find_first_bit(module_map, mbi->mods_count);
    if ( bitmap_weight(module_map, mbi->mods_count) > 1 )
        printk(XENLOG_WARNING
               "Multiple initrd candidates, picking module #%u\n",
               initrdidx);

    /*
     * Temporarily clear SMAP in CR4 to allow user-accesses in construct_dom0().
     * This saves a large number of corner cases interactions with
     * copy_from_user().
     */
    if ( cpu_has_smap )
        write_cr4(read_cr4() & ~X86_CR4_SMAP);

    /*
     * We're going to setup domain0 using the module(s) that we stashed safely
     * above our heap. The second module, if present, is an initrd ramdisk.
     */
    if ( construct_dom0(dom0, mod, modules_headroom,
                        (initrdidx > 0) && (initrdidx < mbi->mods_count)
                        ? mod + initrdidx : NULL,
                        bootstrap_map, cmdline) != 0)
        panic("Could not set up DOM0 guest OS");

    if ( cpu_has_smap )
        write_cr4(read_cr4() | X86_CR4_SMAP);

    /* Scrub RAM that is still free and so may go to an unprivileged domain. */
    scrub_heap_pages();

    init_trace_bufs();

    init_constructors();

    console_endboot();

    /* Hide UART from DOM0 if we're using it */
    serial_endboot();

    dmi_end_boot();

    system_state = SYS_STATE_active;

    domain_unpause_by_systemcontroller(dom0);

    reset_stack_and_jump(init_done);
}

void arch_get_xen_caps(xen_capabilities_info_t *info)
{
    /* Interface name is always xen-3.0-* for Xen-3.x. */
    int major = 3, minor = 0;
    char s[32];

    (*info)[0] = '\0';

    snprintf(s, sizeof(s), "xen-%d.%d-x86_64 ", major, minor);
    safe_strcat(*info, s);
    snprintf(s, sizeof(s), "xen-%d.%d-x86_32p ", major, minor);
    safe_strcat(*info, s);
    if ( hvm_enabled )
    {
        snprintf(s, sizeof(s), "hvm-%d.%d-x86_32 ", major, minor);
        safe_strcat(*info, s);
        snprintf(s, sizeof(s), "hvm-%d.%d-x86_32p ", major, minor);
        safe_strcat(*info, s);
        snprintf(s, sizeof(s), "hvm-%d.%d-x86_64 ", major, minor);
        safe_strcat(*info, s);
    }
}

int __hwdom_init xen_in_range(unsigned long mfn)
{
    paddr_t start, end;
    int i;

    enum { region_s3, region_text, region_bss, nr_regions };
    static struct {
        paddr_t s, e;
    } xen_regions[nr_regions] __hwdom_initdata;

    /* initialize first time */
    if ( !xen_regions[0].s )
    {
        /* S3 resume code (and other real mode trampoline code) */
        xen_regions[region_s3].s = bootsym_phys(trampoline_start);
        xen_regions[region_s3].e = bootsym_phys(trampoline_end);
        /* hypervisor code + data */
        xen_regions[region_text].s =__pa(&_stext);
        xen_regions[region_text].e = __pa(&__init_begin);
        /* bss */
        xen_regions[region_bss].s = __pa(&__bss_start);
        xen_regions[region_bss].e = __pa(&_end);
    }

    start = (paddr_t)mfn << PAGE_SHIFT;
    end = start + PAGE_SIZE;
    for ( i = 0; i < nr_regions; i++ )
        if ( (start < xen_regions[i].e) && (end > xen_regions[i].s) )
            return 1;

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
