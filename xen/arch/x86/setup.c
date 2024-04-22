#include <xen/init.h>
#include <xen/lib.h>
#include <xen/err.h>
#include <xen/grant_table.h>
#include <xen/param.h>
#include <xen/sched.h>
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
#include <xen/hypercall.h>
#include <xen/keyhandler.h>
#include <xen/numa.h>
#include <xen/rcupdate.h>
#include <xen/vga.h>
#include <xen/dmi.h>
#include <xen/pfn.h>
#include <xen/nodemask.h>
#include <xen/virtual_region.h>
#include <xen/watchdog.h>
#include <public/version.h>
#ifdef CONFIG_COMPAT
#include <compat/platform.h>
#include <compat/xen.h>
#endif
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
#include <xen/cpuidle.h>
#include <asm/nmi.h>
#include <asm/alternative.h>
#include <asm/mc146818rtc.h>
#include <asm/cpu-policy.h>
#include <asm/invpcid.h>
#include <asm/spec_ctrl.h>
#include <asm/guest.h>
#include <asm/microcode.h>
#include <asm/prot-key.h>
#include <asm/pv/domain.h>

/* opt_nosmp: If true, secondary processors are ignored. */
static bool __initdata opt_nosmp;
boolean_param("nosmp", opt_nosmp);

/* maxcpus: maximum number of CPUs to activate. */
static unsigned int __initdata max_cpus;
integer_param("maxcpus", max_cpus);

int8_t __read_mostly opt_smt = -1;
boolean_param("smt", opt_smt);

/* opt_invpcid: If false, don't use INVPCID instruction even if available. */
static bool __initdata opt_invpcid = true;
boolean_param("invpcid", opt_invpcid);
bool __read_mostly use_invpcid;

/* Only used in asm code and within this source file */
unsigned long asmlinkage __read_mostly cr4_pv32_mask;

/* **** Linux config option: propagated to domain0. */
/* "acpi=off":    Sisables both ACPI table parsing and interpreter. */
/* "acpi=force":  Override the disable blacklist.                   */
/* "acpi=ht":     Limit ACPI just to boot-time to enable HT.        */
/* "acpi=noirq":  Disables ACPI interrupt routing.                  */
/* "acpi=verbose": Enables more verbose ACPI boot time logging.     */

/* **** Linux config option: propagated to domain0. */
/* noapic: Disable IOAPIC setup. */
boolean_param("noapic", skip_ioapic_setup);

/* **** Linux config option: propagated to domain0. */
/* xen_cpuidle: xen control cstate. */
int8_t __read_mostly xen_cpuidle = -1;
boolean_param("cpuidle", xen_cpuidle);

#ifndef NDEBUG
unsigned long __initdata highmem_start;
size_param("highmem-start", highmem_start);
#endif

static int8_t __initdata opt_xen_shstk = -IS_ENABLED(CONFIG_XEN_SHSTK);

#ifdef CONFIG_XEN_IBT
static bool __initdata opt_xen_ibt = true;
#else
#define opt_xen_ibt false
#endif

static int __init cf_check parse_cet(const char *s)
{
    const char *ss;
    int val, rc = 0;

    do {
        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        if ( (val = parse_boolean("shstk", s, ss)) >= 0 )
        {
#ifdef CONFIG_XEN_SHSTK
            opt_xen_shstk = val;
#else
            no_config_param("XEN_SHSTK", "cet", s, ss);
#endif
        }
        else if ( (val = parse_boolean("ibt", s, ss)) >= 0 )
        {
#ifdef CONFIG_XEN_IBT
            opt_xen_ibt = val;
#else
            no_config_param("XEN_IBT", "cet", s, ss);
#endif
        }
        else
            rc = -EINVAL;

        s = ss + 1;
    } while ( *ss );

    return rc;
}
custom_param("cet", parse_cet);

cpumask_t __read_mostly cpu_present_map;

unsigned long __read_mostly xen_phys_start;

/* Only used in asm code and within this source file */
char asmlinkage __section(".init.bss.stack_aligned") __aligned(STACK_SIZE)
    cpu0_stack[STACK_SIZE];

/* Used by the BSP/AP paths to find the higher half stack mapping to use. */
void *stack_start = cpu0_stack + STACK_SIZE - sizeof(struct cpu_info);

/* Used by the boot asm to stash the relocated multiboot info pointer. */
unsigned int asmlinkage __initdata multiboot_ptr;

struct cpuinfo_x86 __read_mostly boot_cpu_data = { 0, 0, 0, 0, -1 };

unsigned long __read_mostly mmu_cr4_features = XEN_MINIMAL_CR4;

/* smep: Enable/disable Supervisor Mode Execution Protection */
#define SMEP_HVM_ONLY (-2)
static s8 __initdata opt_smep = -1;

/*
 * Initial domain place holder. Needs to be global so it can be created in
 * __start_xen and unpaused in init_done.
 */
static struct domain *__initdata dom0;

static int __init cf_check parse_smep_param(const char *s)
{
    if ( !*s )
    {
        opt_smep = 1;
        return 0;
    }

    switch ( parse_bool(s, NULL) )
    {
    case 0:
        opt_smep = 0;
        return 0;
    case 1:
        opt_smep = 1;
        return 0;
    }

    if ( !strcmp(s, "hvm") )
        opt_smep = SMEP_HVM_ONLY;
    else
        return -EINVAL;

    return 0;
}
custom_param("smep", parse_smep_param);

/* smap: Enable/disable Supervisor Mode Access Prevention */
#define SMAP_HVM_ONLY (-2)
static s8 __initdata opt_smap = -1;

static int __init cf_check parse_smap_param(const char *s)
{
    if ( !*s )
    {
        opt_smap = 1;
        return 0;
    }

    switch ( parse_bool(s, NULL) )
    {
    case 0:
        opt_smap = 0;
        return 0;
    case 1:
        opt_smap = 1;
        return 0;
    }

    if ( !strcmp(s, "hvm") )
        opt_smap = SMAP_HVM_ONLY;
    else
        return -EINVAL;

    return 0;
}
custom_param("smap", parse_smap_param);

bool __read_mostly acpi_disabled;
bool __initdata acpi_force;
static char __initdata acpi_param[10] = "";

static int __init cf_check parse_acpi_param(const char *s)
{
    /* Interpret the parameter for use within Xen. */
    if ( !parse_bool(s, NULL) )
    {
        disable_acpi();
    }
    else if ( !strcmp(s, "force") )
    {
        acpi_force = true;
        acpi_ht = 1;
        acpi_disabled = false;
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
    else if ( !strcmp(s, "verbose") )
    {
        opt_acpi_verbose = true;
        return 0;
    }
    else
        return -EINVAL;

    /* Save the parameter so it can be propagated to domain0. */
    safe_strcpy(acpi_param, s);

    return 0;
}
custom_param("acpi", parse_acpi_param);

static const module_t *__initdata initial_images;
static unsigned int __initdata nr_initial_images;

unsigned long __init initial_images_nrpages(nodeid_t node)
{
    unsigned long node_start = node_start_pfn(node);
    unsigned long node_end = node_end_pfn(node);
    unsigned long nr;
    unsigned int i;

    for ( nr = i = 0; i < nr_initial_images; ++i )
    {
        unsigned long start = initial_images[i].mod_start;
        unsigned long end = start + PFN_UP(initial_images[i].mod_end);

        if ( end > node_start && node_end > start )
            nr += min(node_end, end) - max(node_start, start);
    }

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

extern unsigned char __init_begin[], __init_end[];

static void __init init_idle_domain(void)
{
    scheduler_init();
    set_current(idle_vcpu[0]);
    this_cpu(curr_vcpu) = current;
}

void srat_detect_node(int cpu)
{
    nodeid_t node;
    u32 apicid = x86_cpu_to_apicid[cpu];

    node = apicid < MAX_LOCAL_APIC ? apicid_to_node[apicid] : NUMA_NO_NODE;
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
void *__init bootstrap_map(const module_t *mod)
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

    ret = (void *)(map_cur + (unsigned long)(start & mask));
    start &= ~mask;
    end = (end + mask) & ~mask;
    if ( end - start > BOOTSTRAP_MAP_LIMIT - map_cur )
        return NULL;

    map_pages_to_xen(map_cur, maddr_to_mfn(start),
                     PFN_DOWN(end - start), PAGE_HYPERVISOR);
    map_cur += end - start;
    return ret;
}

static void __init move_memory(
    uint64_t dst, uint64_t src, unsigned int size)
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

        bootstrap_map(NULL);
    }
}

static void __init noinline move_xen(void)
{
    l4_pgentry_t *pl4e;
    l3_pgentry_t *pl3e;
    l2_pgentry_t *pl2e;
    unsigned long tmp;
    unsigned int i, j, k;

    /*
     * The caller has selected xen_phys_start, ensuring that the old and new
     * locations do not overlap, and mapped the new location into the
     * directmap.
     *
     * Prevent the compiler from reordering anything across this point.  Such
     * things will end badly.
     */
    barrier();

    /*
     * Copy out of the current alias, into the directmap at the new location.
     * This includes a snapshot of the current stack.
     */
    memcpy(__va(__pa(_start)), _start, _end - _start);

    /*
     * We are now in a critical region.  Any write modifying global state
     * inside the main Xen image via the current alias will get lost when we
     * switch to the new pagetables.
     *
     * This puts printk()'s in a weird position.  Xen's record of the printk()
     * will get lost (e.g. from the console ring), but messages which properly
     * escape the system (e.g. through the UART) may be of some use for
     * debugging purposes.
     *
     * Walk the soon-to-be-used pagetables in the new location, relocating all
     * intermediate (non-leaf) entries to point to their new-location
     * equivalents.  All writes are via the directmap alias.
     */
    pl4e = __va(__pa(idle_pg_table));
    for ( i = 0 ; i < L4_PAGETABLE_ENTRIES; i++, pl4e++ )
    {
        if ( !(l4e_get_flags(*pl4e) & _PAGE_PRESENT) )
            continue;

        *pl4e = l4e_from_intpte(l4e_get_intpte(*pl4e) + xen_phys_start);
        pl3e = __va(l4e_get_paddr(*pl4e));
        for ( j = 0; j < L3_PAGETABLE_ENTRIES; j++, pl3e++ )
        {
            if ( !(l3e_get_flags(*pl3e) & _PAGE_PRESENT) ||
                 (l3e_get_flags(*pl3e) & _PAGE_PSE) )
                continue;

            *pl3e = l3e_from_intpte(l3e_get_intpte(*pl3e) + xen_phys_start);
            pl2e = __va(l3e_get_paddr(*pl3e));
            for ( k = 0; k < L2_PAGETABLE_ENTRIES; k++, pl2e++ )
            {
                if ( !(l2e_get_flags(*pl2e) & _PAGE_PRESENT) ||
                     (l2e_get_flags(*pl2e) & _PAGE_PSE) )
                    continue;

                *pl2e = l2e_from_intpte(l2e_get_intpte(*pl2e) + xen_phys_start);
            }
        }
    }

    /*
     * Walk the soon-to-be-used l2_xenmap[], relocating all the leaf superpage
     * mappings so text/data/bss etc refer to the new location in memory.
     * Non-leaf mappings, e.g. fixmap_x, were relocated above.
     */
    pl2e = __va(__pa(l2_xenmap));
    for ( i = 0; i < L2_PAGETABLE_ENTRIES; i++, pl2e++ )
    {
        if ( !(l2e_get_flags(*pl2e) & _PAGE_PRESENT) ||
             !(l2e_get_flags(*pl2e) & _PAGE_PSE) )
            continue;

        *pl2e = l2e_from_intpte(l2e_get_intpte(*pl2e) + xen_phys_start);
    }

    asm volatile (
        /*
         * Resync the local stack frame.  The compiler expects any spilled
         * expression to retain its value.  This is usually only a few words.
         */
        "mov    %%rsp, %%rsi\n\t"       /* SRC = %rsp */
        "mov    %%esp, %k[tmp]\n\t"
        "and    %[mask], %k[tmp]\n\t"
        "add    %[tmp], %%rdi\n\t"      /* DST = cpu0_stack + (%rsp & 0x7fff) */
        "sub    %%esp, %%ecx\n\t"       /* NR  = frame - %rsp */
        "rep movsb\n\t"

        /*
         * Switch to the relocated pagetables, shooting down global mappings.
         */
        "mov    %%cr4, %[tmp]\n\t"
        "andb   $~%c[pge], %b[tmp]\n\t"
        "mov    %[tmp], %%cr4\n\t"     /* CR4.PGE = 0 */
        "mov    %[cr3], %%cr3\n\t"     /* CR3 = new pagetables */
        "orb    %[pge], %b[tmp]\n\t"
        "mov    %[tmp], %%cr4\n\t"     /* CR4.PGE = 1 */
        : [tmp]     "=&a" (tmp), /* Could be "r", but "a" makes better asm */
          [dst]     "=&D" (tmp),
          [frame]   "=&c" (tmp),
                    "=&S" (tmp)
        : [cr3]     "r"   (__pa(idle_pg_table)),
          [pge]     "i"   (X86_CR4_PGE),
          [mask]    "i"   (STACK_SIZE - 1),
          "[dst]"         (__va(__pa(cpu0_stack))),
          "[frame]"       (__builtin_frame_address(0))
        : "memory" );

    /*
     * End of the critical region.  Updates to globals now work as expected.
     */
    printk("New Xen image base address: %#lx\n", xen_phys_start);
}

#undef BOOTSTRAP_MAP_LIMIT

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

    if ( max_pdx > MPT_VIRT_SIZE / sizeof(unsigned long) )
        max_pdx = MPT_VIRT_SIZE / sizeof(unsigned long);

#ifdef PAGE_LIST_NULL
    if ( max_pdx >= PAGE_LIST_NULL )
        max_pdx = PAGE_LIST_NULL - 1;
#endif

    max_page = pdx_to_pfn(max_pdx - 1) + 1;
}

/* A temporary copy of the e820 map that we can mess with during bootstrap. */
static struct e820map __initdata boot_e820;

#ifdef CONFIG_VIDEO
# include "boot/video.h"
#endif

static void __init parse_video_info(void)
{
#ifdef CONFIG_VIDEO
    struct boot_video_info *bvi = &bootsym(boot_vid_info);

    /* vga_console_info is filled directly on EFI platform. */
    if ( efi_enabled(EFI_BOOT) )
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
#endif
}

static void __init kexec_reserve_area(void)
{
#ifdef CONFIG_KEXEC
    unsigned long kdump_start = kexec_crash_area.start;
    unsigned long kdump_size  = kexec_crash_area.size;
    static bool __initdata is_reserved = false;

    kdump_size = (kdump_size + PAGE_SIZE - 1) & PAGE_MASK;

    if ( (kdump_start == 0) || (kdump_size == 0) || is_reserved )
        return;

    is_reserved = true;

    if ( !reserve_e820_ram(&boot_e820, kdump_start, kdump_start + kdump_size) )
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
#endif
}

static inline bool using_2M_mapping(void)
{
    return !l1_table_offset((unsigned long)__2M_text_end) &&
           !l1_table_offset((unsigned long)__2M_rodata_start) &&
           !l1_table_offset((unsigned long)__2M_rodata_end) &&
           !l1_table_offset((unsigned long)__2M_init_start) &&
           !l1_table_offset((unsigned long)__2M_init_end) &&
           !l1_table_offset((unsigned long)__2M_rwdata_start) &&
           !l1_table_offset((unsigned long)__2M_rwdata_end);
}

static void noreturn init_done(void)
{
    void *va;
    unsigned long start, end;
    int err;

    if ( (err = xsm_set_system_active()) != 0 )
        panic("xsm: unable to switch to SYSTEM_ACTIVE privilege: %d\n", err);

    system_state = SYS_STATE_active;

    /* Re-run stub recovery self-tests with CET-SS active. */
    if ( IS_ENABLED(CONFIG_DEBUG) && cpu_has_xen_shstk )
        stub_selftest();

    domain_unpause_by_systemcontroller(dom0);

    /* MUST be done prior to removing .init data. */
    unregister_init_virtual_region();

    /* Zero the .init code and data. */
    for ( va = __init_begin; va < _p(__init_end); va += PAGE_SIZE )
        clear_page(va);

    /* Destroy Xen's mappings, and reuse the pages. */
    if ( using_2M_mapping() )
    {
        start = (unsigned long)&__2M_init_start,
        end   = (unsigned long)&__2M_init_end;
    }
    else
    {
        start = (unsigned long)&__init_begin;
        end   = (unsigned long)&__init_end;
    }

    destroy_xen_mappings(start, end);
    init_xenheap_pages(__pa(start), __pa(end));
    printk("Freed %lukB init memory\n", (end - start) >> 10);

    /* Mark .rodata/ro_after_init as RO.  Maybe reform the superpage. */
    modify_xen_mappings((unsigned long)&__2M_rodata_start,
                        (unsigned long)&__2M_rodata_end,
                        PAGE_HYPERVISOR_RO);

    startup_cpu_idle_loop();
}

#if defined(CONFIG_XEN_SHSTK) || defined(CONFIG_XEN_IBT)
/*
 * Used by AP and S3 asm code to calcualte the appropriate MSR_S_CET setting.
 * Do not use on the BSP before reinit_bsp_stack(), or it may turn SHSTK on
 * too early.
 */
unsigned int xen_msr_s_cet_value(void)
{
    return ((cpu_has_xen_shstk ? CET_SHSTK_EN | CET_WRSS_EN : 0) |
            (cpu_has_xen_ibt   ? CET_ENDBR_EN : 0));
}
#else
unsigned int xen_msr_s_cet_value(void); /* To avoid ifdefary */
#endif

/* Reinitalise all state referring to the old virtual address of the stack. */
static void __init noreturn reinit_bsp_stack(void)
{
    unsigned long *stack = (void*)(get_stack_bottom() & ~(STACK_SIZE - 1));
    int rc;

    /* Update TSS and ISTs */
    load_system_tables();

    /* Update SYSCALL trampolines */
    percpu_traps_init();

    stack_base[0] = stack;

    rc = setup_cpu_root_pgt(0);
    if ( rc )
        panic("Error %d setting up PV root page table\n", rc);

    if ( cpu_has_xen_shstk )
    {
        wrmsrl(MSR_PL0_SSP,
               (unsigned long)stack + (PRIMARY_SHSTK_SLOT + 1) * PAGE_SIZE - 8);
        wrmsrl(MSR_S_CET, xen_msr_s_cet_value());
        asm volatile ("setssbsy" ::: "memory");
    }

    reset_stack_and_jump(init_done);
}

/*
 * x86 early command line parsing in xen/arch/x86/boot/cmdline.c
 * has options that are only used during the very initial boot process,
 * so they can be ignored now.
 */
ignore_param("real-mode");
ignore_param("edd");
ignore_param("edid");

/*
 * Some scripts add "placeholder" to work around a grub error where it ate the
 * first parameter.
 */
ignore_param("placeholder");

static bool __init loader_is_grub2(const char *loader_name)
{
    /* GRUB1="GNU GRUB 0.xx"; GRUB2="GRUB 1.xx" */
    const char *p = strstr(loader_name, "GRUB ");
    return (p != NULL) && (p[5] != '0');
}

/*
 * Clean up a command line string passed to us by a bootloader.  Strip leading
 * whitespace, and optionally strip the first parameter if our divination of
 * the bootloader suggests that it prepended the image name.
 *
 * Always returns a pointer within @p.
 */
static const char *__init cmdline_cook(const char *p, const char *loader_name)
{
    /* Strip leading whitespace. */
    while ( *p == ' ' )
        p++;

    /*
     * PVH, our EFI loader, and GRUB2 don't include image name as first
     * item on command line.
     */
    if ( xen_guest || efi_enabled(EFI_LOADER) || loader_is_grub2(loader_name) )
        return p;

    /* Strip image name plus whitespace. */
    while ( (*p != ' ') && (*p != '\0') )
        p++;
    while ( *p == ' ' )
        p++;

    return p;
}

static unsigned int __init copy_bios_e820(struct e820entry *map, unsigned int limit)
{
    unsigned int n = min(bootsym(bios_e820nr), limit);

    if ( n )
        memcpy(map, bootsym(bios_e820map), sizeof(*map) * n);

    return n;
}

static struct domain *__init create_dom0(const module_t *image,
                                         unsigned long headroom,
                                         module_t *initrd, const char *kextra,
                                         const char *loader)
{
    static char __initdata cmdline[MAX_GUEST_CMDLINE];

    struct xen_domctl_createdomain dom0_cfg = {
        .flags = IS_ENABLED(CONFIG_TBOOT) ? XEN_DOMCTL_CDF_s3_integrity : 0,
        .max_evtchn_port = -1,
        .max_grant_frames = -1,
        .max_maptrack_frames = -1,
        .grant_opts = XEN_DOMCTL_GRANT_version(opt_gnttab_max_version),
        .max_vcpus = dom0_max_vcpus(),
        .arch = {
            .misc_flags = opt_dom0_msr_relaxed ? XEN_X86_MSR_RELAXED : 0,
        },
    };
    struct domain *d;
    domid_t domid;

    if ( opt_dom0_pvh )
    {
        dom0_cfg.flags |= (XEN_DOMCTL_CDF_hvm |
                           ((hvm_hap_supported() && !opt_dom0_shadow) ?
                            XEN_DOMCTL_CDF_hap : 0));

        dom0_cfg.arch.emulation_flags |=
            XEN_X86_EMU_LAPIC | XEN_X86_EMU_IOAPIC | XEN_X86_EMU_VPCI;
    }

    if ( iommu_enabled )
        dom0_cfg.flags |= XEN_DOMCTL_CDF_iommu;

    /* Create initial domain.  Not d0 for pvshim. */
    domid = get_initial_domain_id();
    d = domain_create(domid, &dom0_cfg, pv_shim ? 0 : CDF_privileged);
    if ( IS_ERR(d) )
        panic("Error creating d%u: %ld\n", domid, PTR_ERR(d));

    init_dom0_cpuid_policy(d);

    if ( alloc_dom0_vcpu0(d) == NULL )
        panic("Error creating d%uv0\n", domid);

    /* Grab the DOM0 command line. */
    if ( image->string || kextra )
    {
        if ( image->string )
            safe_strcpy(cmdline, cmdline_cook(__va(image->string), loader));

        if ( kextra )
            /* kextra always includes exactly one leading space. */
            safe_strcat(cmdline, kextra);

        /* Append any extra parameters. */
        if ( skip_ioapic_setup && !strstr(cmdline, "noapic") )
            safe_strcat(cmdline, " noapic");

        if ( (strlen(acpi_param) == 0) && acpi_disabled )
        {
            printk("ACPI is disabled, notifying Domain 0 (acpi=off)\n");
            safe_strcpy(acpi_param, "off");
        }

        if ( (strlen(acpi_param) != 0) && !strstr(cmdline, "acpi=") )
        {
            safe_strcat(cmdline, " acpi=");
            safe_strcat(cmdline, acpi_param);
        }
    }

    /*
     * Temporarily clear SMAP in CR4 to allow user-accesses in construct_dom0().
     * This saves a large number of corner cases interactions with
     * copy_from_user().
     */
    if ( cpu_has_smap )
    {
        cr4_pv32_mask &= ~X86_CR4_SMAP;
        write_cr4(read_cr4() & ~X86_CR4_SMAP);
    }

    if ( construct_dom0(d, image, headroom, initrd, cmdline) != 0 )
        panic("Could not construct domain 0\n");

    if ( cpu_has_smap )
    {
        write_cr4(read_cr4() | X86_CR4_SMAP);
        cr4_pv32_mask |= X86_CR4_SMAP;
    }

    return d;
}

/* How much of the directmap is prebuilt at compile time. */
#define PREBUILT_MAP_LIMIT (1 << L2_PAGETABLE_SHIFT)

void asmlinkage __init noreturn __start_xen(unsigned long mbi_p)
{
    const char *memmap_type = NULL, *loader, *cmdline = "";
    char *kextra;
    void *bsp_stack;
    struct cpu_info *info = get_cpu_info(), *bsp_info;
    unsigned int initrdidx, num_parked = 0;
    multiboot_info_t *mbi;
    module_t *mod;
    unsigned long nr_pages, raw_max_page, modules_headroom, module_map[1];
    int i, j, e820_warn = 0, bytes = 0;
    unsigned long eb_start, eb_end;
    bool acpi_boot_table_init_done = false, relocated = false;
    bool vm_init_done = false;
    int ret;
    struct ns16550_defaults ns16550 = {
        .data_bits = 8,
        .parity    = 'n',
        .stop_bits = 1
    };
    const char *hypervisor_name;

    /* Critical region without IDT or TSS.  Any fault is deadly! */

    init_shadow_spec_ctrl_state();

    percpu_init_areas();

    init_idt_traps();
    load_system_tables();

    smp_prepare_boot_cpu();
    sort_exception_tables();

    /* Full exception support from here on in. */

    rdmsrl(MSR_EFER, this_cpu(efer));
    asm volatile ( "mov %%cr4,%0" : "=r" (info->cr4) );

    /* Enable NMIs.  Our loader (e.g. Tboot) may have left them disabled. */
    enable_nmis();

    if ( pvh_boot )
    {
        ASSERT(mbi_p == 0);
        pvh_init(&mbi, &mod);
    }
    else
    {
        mbi = __va(mbi_p);
        mod = __va(mbi->mods_addr);
    }

    loader = (mbi->flags & MBI_LOADERNAME) ? __va(mbi->boot_loader_name)
                                           : "unknown";

    /* Parse the command-line options. */
    if ( mbi->flags & MBI_CMDLINE )
        cmdline = cmdline_cook(__va(mbi->cmdline), loader);

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

    /*
     * The probing has to be done _before_ initialising console,
     * otherwise we couldn't set up Xen's PV console correctly.
     */
    hypervisor_name = hypervisor_probe();

    parse_video_info();

    /* We initialise the serial devices very early so we can get debugging. */
    ns16550.io_base = 0x3f8;
    ns16550.irq     = 4;
    ns16550_init(0, &ns16550);
    ns16550.io_base = 0x2f8;
    ns16550.irq     = 3;
    ns16550_init(1, &ns16550);
    ehci_dbgp_init();
    xhci_dbc_uart_init();
    console_init_preirq();

    if ( pvh_boot )
        pvh_print_info();

    printk("Bootloader: %s\n", loader);

    printk("Command line: %s\n", cmdline);

    printk("Xen image load base address: %#lx\n", xen_phys_start);
    if ( hypervisor_name )
        printk("Running on %s\n", hypervisor_name);

#ifdef CONFIG_VIDEO
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
#endif

    printk("Disc information:\n");
    printk(" Found %d MBR signatures\n",
           bootsym(boot_mbr_signature_nr));
    printk(" Found %d EDD information structures\n",
           bootsym(boot_edd_info_nr));

    /* Check that we have at least one Multiboot module. */
    if ( !(mbi->flags & MBI_MODULES) || (mbi->mods_count == 0) )
        panic("dom0 kernel not specified. Check bootloader configuration\n");

    /* Check that we don't have a silly number of modules. */
    if ( mbi->mods_count > sizeof(module_map) * 8 )
    {
        mbi->mods_count = sizeof(module_map) * 8;
        printk("Excessive multiboot modules - using the first %u only\n",
               mbi->mods_count);
    }

    bitmap_fill(module_map, mbi->mods_count);
    __clear_bit(0, module_map); /* Dom0 kernel is always first */

    if ( pvh_boot )
    {
        /* pvh_init() already filled in e820_raw */
        memmap_type = "PVH-e820";
    }
    else if ( efi_enabled(EFI_LOADER) )
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
    else if ( efi_enabled(EFI_BOOT) )
        memmap_type = "EFI";
    else if ( (e820_raw.nr_map = 
                   copy_bios_e820(e820_raw.map,
                                  ARRAY_SIZE(e820_raw.map))) != 0 )
    {
        memmap_type = "Xen-e820";
    }
    else if ( mbi->flags & MBI_MEMMAP )
    {
        memmap_type = "Multiboot-e820";
        while ( bytes < mbi->mmap_length &&
                e820_raw.nr_map < ARRAY_SIZE(e820_raw.map) )
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

            e820_raw.map[e820_raw.nr_map].addr =
                ((u64)map->base_addr_high << 32) | (u64)map->base_addr_low;
            e820_raw.map[e820_raw.nr_map].size =
                ((u64)map->length_high << 32) | (u64)map->length_low;
            e820_raw.map[e820_raw.nr_map].type = map->type;
            e820_raw.nr_map++;

            bytes += map->size + 4;
        }
    }
    else
        panic("Bootloader provided no memory information\n");

    /* This must come before e820 code because it sets paddr_bits. */
    early_cpu_init(true);

    /* Choose shadow stack early, to set infrastructure up appropriately. */
    if ( !boot_cpu_has(X86_FEATURE_CET_SS) )
        opt_xen_shstk = 0;

    if ( opt_xen_shstk )
    {
        /*
         * Some CPUs suffer from Shadow Stack Fracturing, an issue whereby a
         * fault/VMExit/etc between setting a Supervisor Busy bit and the
         * event delivery completing renders the operation non-restartable.
         * On restart, event delivery will find the Busy bit already set.
         *
         * This is a problem on bare metal, but outside of synthetic cases or
         * a very badly timed #MC, it's not believed to be a problem.  It is a
         * much bigger problem under virt, because we can VMExit for a number
         * of legitimate reasons and tickle this bug.
         *
         * CPUs with this addressed enumerate CET-SSS to indicate that
         * supervisor shadow stacks are now safe to use.
         */
        bool cpu_has_bug_shstk_fracture =
            boot_cpu_data.x86_vendor == X86_VENDOR_INTEL &&
            !boot_cpu_has(X86_FEATURE_CET_SSS);

        /*
         * On bare metal, assume that Xen won't be impacted by shstk
         * fracturing problems.  Under virt, be more conservative and disable
         * shstk by default.
         */
        if ( opt_xen_shstk == -1 )
            opt_xen_shstk =
                cpu_has_hypervisor ? !cpu_has_bug_shstk_fracture
                                   : true;

        if ( opt_xen_shstk )
        {
            printk("Enabling Supervisor Shadow Stacks\n");

            setup_force_cpu_cap(X86_FEATURE_XEN_SHSTK);
        }
    }

    if ( opt_xen_ibt && boot_cpu_has(X86_FEATURE_CET_IBT) )
    {
        printk("Enabling Indirect Branch Tracking\n");

        setup_force_cpu_cap(X86_FEATURE_XEN_IBT);

        if ( efi_enabled(EFI_RS) )
            printk("  - IBT disabled in UEFI Runtime Services\n");

        /*
         * Enable IBT now.  Only require the endbr64 on callees, which is
         * entirely build-time arrangements.
         */
        wrmsrl(MSR_S_CET, CET_ENDBR_EN);
    }

    if ( cpu_has_xen_shstk || cpu_has_xen_ibt )
    {
        set_in_cr4(X86_CR4_CET);

#ifdef CONFIG_PV32
        if ( opt_pv32 )
        {
            opt_pv32 = 0;
            printk("  - Disabling PV32 due to CET\n");
        }
#endif
    }

    /* Sanitise the raw E820 map to produce a final clean version. */
    max_page = raw_max_page = init_e820(memmap_type, &e820_raw);

    if ( !efi_enabled(EFI_BOOT) && e820_raw.nr_map >= 1 )
    {
        /*
         * Supplement the heuristics in l1tf_calculations() by assuming that
         * anything referenced in the E820 may be cacheable.
         */
        l1tf_safe_maddr =
            max(l1tf_safe_maddr,
                ROUNDUP(e820_raw.map[e820_raw.nr_map - 1].addr +
                        e820_raw.map[e820_raw.nr_map - 1].size, PAGE_SIZE));
    }

    /* Create a temporary copy of the E820 map. */
    memcpy(&boot_e820, &e820, sizeof(e820));

    /* Early kexec reservation (explicit static start address). */
    nr_pages = 0;
    for ( i = 0; i < e820.nr_map; i++ )
        if ( e820.map[i].type == E820_RAM )
            nr_pages += e820.map[i].size >> PAGE_SHIFT;
    set_kexec_crash_area_size((u64)nr_pages << PAGE_SHIFT);
    kexec_reserve_area();

    initial_images = mod;
    nr_initial_images = mbi->mods_count;

    for ( i = 0; !efi_enabled(EFI_LOADER) && i < mbi->mods_count; i++ )
    {
        if ( mod[i].mod_start & (PAGE_SIZE - 1) )
            panic("Bootloader didn't honor module alignment request\n");
        mod[i].mod_end -= mod[i].mod_start;
        mod[i].mod_start >>= PAGE_SHIFT;
        mod[i].reserved = 0;
    }

    /*
     * TODO: load ucode earlier once multiboot modules become accessible
     * at an earlier stage.
     */
    early_microcode_init(module_map, mbi);

    if ( xen_phys_start )
    {
        relocated = true;

        /*
         * This needs to remain in sync with remove_xen_ranges() and the
         * respective reserve_e820_ram() invocation below. No need to
         * query efi_boot_mem_unused() here, though.
         */
        mod[mbi->mods_count].mod_start = virt_to_mfn(_stext);
        mod[mbi->mods_count].mod_end = __2M_rwdata_end - _stext;
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

    /*
     * Iterate backwards over all superpage-aligned RAM regions.
     *
     * We require superpage alignment because the boot allocator is
     * not yet initialised. Hence we can only map superpages in the
     * address range PREBUILT_MAP_LIMIT to 4GB, as this is guaranteed
     * not to require dynamic allocation of pagetables.
     *
     * As well as mapping superpages in that range, in preparation for
     * initialising the boot allocator, we also look for a region to which
     * we can relocate the dom0 kernel and other multiboot modules. Also, on
     * x86/64, we relocate Xen to higher memory.
     */
    for ( i = boot_e820.nr_map-1; i >= 0; i-- )
    {
        uint64_t s, e, mask = (1UL << L2_PAGETABLE_SHIFT) - 1;
        uint64_t end, limit = ARRAY_SIZE(l2_directmap) << L2_PAGETABLE_SHIFT;

        if ( boot_e820.map[i].type != E820_RAM )
            continue;

        /* Superpage-aligned chunks from PREBUILT_MAP_LIMIT. */
        s = (boot_e820.map[i].addr + mask) & ~mask;
        e = (boot_e820.map[i].addr + boot_e820.map[i].size) & ~mask;
        s = max_t(uint64_t, s, PREBUILT_MAP_LIMIT);
        if ( s >= e )
            continue;

        if ( s < limit )
        {
            end = min(e, limit);
            set_pdx_range(s >> PAGE_SHIFT, end >> PAGE_SHIFT);
            map_pages_to_xen((unsigned long)__va(s), maddr_to_mfn(s),
                             PFN_DOWN(end - s), PAGE_HYPERVISOR);
        }

        if ( e > min(HYPERVISOR_VIRT_END - DIRECTMAP_VIRT_START,
                     1UL << (PAGE_SHIFT + 32)) )
            e = min(HYPERVISOR_VIRT_END - DIRECTMAP_VIRT_START,
                    1UL << (PAGE_SHIFT + 32));
#define reloc_size ((__pa(__2M_rwdata_end) + mask) & ~mask)
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

        /*
         * Is the region size greater than zero and does it begin
         * at or above the end of current Xen image placement?
         */
        if ( (end > s) && (end - reloc_size + XEN_IMG_OFFSET >= __pa(_end)) )
        {
            /* Select relocation address. */
            xen_phys_start = end - reloc_size;
            e = xen_phys_start + XEN_IMG_OFFSET;
            bootsym(trampoline_xen_phys_start) = xen_phys_start;

            move_xen();
        }

        /* Is the region suitable for relocating the multiboot modules? */
        for ( j = mbi->mods_count - 1; j >= 0; j-- )
        {
            unsigned long headroom = j ? 0 : modules_headroom;
            unsigned long size = PAGE_ALIGN(headroom + mod[j].mod_end);

            if ( mod[j].reserved )
                continue;

            /* Don't overlap with other modules (or Xen itself). */
            end = consider_modules(s, e, size, mod,
                                   mbi->mods_count + relocated, j);

            if ( highmem_start && end > highmem_start )
                continue;

            if ( s < end &&
                 (headroom ||
                  ((end - size) >> PAGE_SHIFT) > mod[j].mod_start) )
            {
                move_memory(end - size + headroom,
                            (uint64_t)mod[j].mod_start << PAGE_SHIFT,
                            mod[j].mod_end);
                mod[j].mod_start = (end - size) >> PAGE_SHIFT;
                mod[j].mod_end += headroom;
                mod[j].reserved = 1;
            }
        }

#ifdef CONFIG_KEXEC
        /*
         * Looking backwards from the crash area limit, find a large
         * enough range that does not overlap with modules.
         */
        while ( !kexec_crash_area.start )
        {
            /* Don't overlap with modules (or Xen itself). */
            e = consider_modules(s, e, PAGE_ALIGN(kexec_crash_area.size), mod,
                                 mbi->mods_count + relocated, -1);
            if ( s >= e )
                break;
            if ( e > kexec_crash_area_limit )
            {
                e = kexec_crash_area_limit & PAGE_MASK;
                continue;
            }
            kexec_crash_area.start = (e - kexec_crash_area.size) & PAGE_MASK;
        }
#endif
    }

    if ( modules_headroom && !mod->reserved )
        panic("Not enough memory to relocate the dom0 kernel image\n");
    for ( i = 0; i < mbi->mods_count; ++i )
    {
        uint64_t s = (uint64_t)mod[i].mod_start << PAGE_SHIFT;

        reserve_e820_ram(&boot_e820, s, s + PAGE_ALIGN(mod[i].mod_end));
    }

    if ( !xen_phys_start )
        panic("Not enough memory to relocate Xen\n");

    /* FIXME: Putting a hole in .bss would shatter the large page mapping. */
    if ( using_2M_mapping() )
        efi_boot_mem_unused(NULL, NULL);

    /* This needs to remain in sync with remove_xen_ranges(). */
    if ( efi_boot_mem_unused(&eb_start, &eb_end) )
    {
        reserve_e820_ram(&boot_e820, __pa(_stext), __pa(eb_start));
        reserve_e820_ram(&boot_e820, __pa(eb_end), __pa(__2M_rwdata_end));
    }
    else
        reserve_e820_ram(&boot_e820, __pa(_stext), __pa(__2M_rwdata_end));

    /* Late kexec reservation (dynamic start address). */
    kexec_reserve_area();

    setup_max_pdx(raw_max_page);
    if ( highmem_start )
        xenheap_max_mfn(PFN_DOWN(highmem_start - 1));

    /*
     * Walk every RAM region and map it in its entirety (on x86/64, at least)
     * and notify it to the boot allocator.
     */
    for ( i = 0; i < boot_e820.nr_map; i++ )
    {
        uint64_t s, e, mask = PAGE_SIZE - 1;
        uint64_t map_s, map_e;

        if ( boot_e820.map[i].type != E820_RAM )
            continue;

        /* Only page alignment required now. */
        s = (boot_e820.map[i].addr + mask) & ~mask;
        e = (boot_e820.map[i].addr + boot_e820.map[i].size) & ~mask;
        s = max_t(uint64_t, s, 1<<20);
        if ( s >= e )
            continue;

        if ( !acpi_boot_table_init_done &&
             s >= (1ULL << 32) )
        {
            /*
             * We only initialise vmap and acpi after going through the bottom
             * 4GiB, so that we have enough pages in the boot allocator.
             */
            if ( !vm_init_done )
            {
                vm_init();
                vm_init_done = true;
            }
            if ( !acpi_boot_table_init() )
            {
                acpi_boot_table_init_done = true;
                srat_parse_regions(s);
                setup_max_pdx(raw_max_page);
            }
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
            e = pfn_to_paddr(max_page);
            printk(XENLOG_WARNING "Ignoring inaccessible memory range"
                                  " %013"PRIx64"-%013"PRIx64"\n",
                   e, map_e);
        }

        set_pdx_range(s >> PAGE_SHIFT, e >> PAGE_SHIFT);

        /* Need to create mappings above PREBUILT_MAP_LIMIT. */
        map_s = max_t(uint64_t, s, PREBUILT_MAP_LIMIT);
        map_e = min_t(uint64_t, e,
                      ARRAY_SIZE(l2_directmap) << L2_PAGETABLE_SHIFT);

        /* Pass mapped memory to allocator /before/ creating new mappings. */
        init_boot_pages(s, min(map_s, e));
        s = map_s;
        if ( s < map_e )
        {
            mask = (1UL << L2_PAGETABLE_SHIFT) - 1;
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
                map_pages_to_xen((unsigned long)__va(map_e), maddr_to_mfn(map_e),
                                 PFN_DOWN(end - map_e), PAGE_HYPERVISOR);
                init_boot_pages(map_e, end);
                map_e = end;
            }
        }
        if ( map_e < e )
        {
            /* This range must not be passed to the boot allocator and
             * must also not be mapped with _PAGE_GLOBAL. */
            map_pages_to_xen((unsigned long)__va(map_e), maddr_to_mfn(map_e),
                             PFN_DOWN(e - map_e), __PAGE_HYPERVISOR_RW);
        }
        if ( s < map_s )
        {
            map_pages_to_xen((unsigned long)__va(s), maddr_to_mfn(s),
                             PFN_DOWN(map_s - s), PAGE_HYPERVISOR);
            init_boot_pages(s, map_s);
        }
    }

    for ( i = 0; i < mbi->mods_count; ++i )
    {
        set_pdx_range(mod[i].mod_start,
                      mod[i].mod_start + PFN_UP(mod[i].mod_end));
        map_pages_to_xen((unsigned long)mfn_to_virt(mod[i].mod_start),
                         _mfn(mod[i].mod_start),
                         PFN_UP(mod[i].mod_end), PAGE_HYPERVISOR);
    }

#ifdef CONFIG_KEXEC
    if ( kexec_crash_area.size )
    {
        unsigned long s = PFN_DOWN(kexec_crash_area.start);
        unsigned long e = min(s + PFN_UP(kexec_crash_area.size),
                              PFN_UP(__pa(HYPERVISOR_VIRT_END - 1)));

        if ( e > s ) 
            map_pages_to_xen((unsigned long)__va(kexec_crash_area.start),
                             _mfn(s), e - s, PAGE_HYPERVISOR);
    }
#endif

    /*
     * All Xen mappings are currently RWX 2M superpages.  Restrict to:
     *   text          - RX
     *   ro_after_init - RW for now, RO later
     *   rodata        - RO
     *   init          - keep RWX, discarded entirely later
     *   data/bss      - RW
     */
    modify_xen_mappings((unsigned long)&_start,
                        (unsigned long)&__2M_text_end,
                        PAGE_HYPERVISOR_RX);

    modify_xen_mappings((unsigned long)&__ro_after_init_start,
                        (unsigned long)&__ro_after_init_end,
                        PAGE_HYPERVISOR_RW);

    modify_xen_mappings((unsigned long)&__ro_after_init_end,
                        (unsigned long)&__2M_rodata_end,
                        PAGE_HYPERVISOR_RO);

    modify_xen_mappings((unsigned long)&__2M_rwdata_start,
                        (unsigned long)&__2M_rwdata_end,
                        PAGE_HYPERVISOR_RW);

    if ( !using_2M_mapping() )
        /* Drop the remaining mappings in the shattered superpage. */
        destroy_xen_mappings((unsigned long)&__2M_rwdata_end,
                             ROUNDUP((unsigned long)&__2M_rwdata_end, MB(2)));

    /*
     * Mark all of .text and .rodata as RO in the directmap - we don't want
     * these sections writeable via any alias.  The compile-time allocated
     * pagetables are written via their directmap alias, so data/bss needs to
     * remain writeable.
     */
    modify_xen_mappings((unsigned long)__va(__pa(_start)),
                        (unsigned long)__va(__pa(__2M_rodata_end)),
                        PAGE_HYPERVISOR_RO);

    nr_pages = 0;
    for ( i = 0; i < e820.nr_map; i++ )
        if ( e820.map[i].type == E820_RAM )
            nr_pages += e820.map[i].size >> PAGE_SHIFT;
    printk("System RAM: %luMB (%lukB)\n",
           nr_pages >> (20 - PAGE_SHIFT),
           nr_pages << (PAGE_SHIFT - 10));
    total_pages = nr_pages;

    /* Sanity check for unwanted bloat of certain hypercall structures. */
    BUILD_BUG_ON(sizeof_field(struct xen_platform_op, u) !=
                 sizeof_field(struct xen_platform_op, u.pad));
    BUILD_BUG_ON(sizeof_field(struct xen_domctl, u) !=
                 sizeof_field(struct xen_domctl, u.pad));
    BUILD_BUG_ON(sizeof_field(struct xen_sysctl, u) !=
                 sizeof_field(struct xen_sysctl, u.pad));

    BUILD_BUG_ON(sizeof(start_info_t) > PAGE_SIZE);
    BUILD_BUG_ON(sizeof(shared_info_t) > PAGE_SIZE);
    BUILD_BUG_ON(sizeof(struct vcpu_info) != 64);

#ifdef CONFIG_COMPAT
    BUILD_BUG_ON(sizeof_field(struct compat_platform_op, u) !=
                 sizeof_field(struct compat_platform_op, u.pad));
    BUILD_BUG_ON(sizeof(start_info_compat_t) > PAGE_SIZE);
    BUILD_BUG_ON(sizeof(struct compat_vcpu_info) != 64);
#endif

    /* Check definitions in public headers match internal defs. */
    BUILD_BUG_ON(__HYPERVISOR_VIRT_START != HYPERVISOR_VIRT_START);
    BUILD_BUG_ON(__HYPERVISOR_VIRT_END   != HYPERVISOR_VIRT_END);
    BUILD_BUG_ON(MACH2PHYS_VIRT_START != RO_MPT_VIRT_START);
    BUILD_BUG_ON(MACH2PHYS_VIRT_END   != RO_MPT_VIRT_END);

    init_frametable();

    if ( !vm_init_done )
        vm_init();

    if ( !acpi_boot_table_init_done )
        acpi_boot_table_init();

    acpi_numa_init();

    numa_initmem_init(0, raw_max_page);

    if ( max_page - 1 > virt_to_mfn(HYPERVISOR_VIRT_END - 1) )
    {
        unsigned long lo = virt_to_mfn(HYPERVISOR_VIRT_END - 1);
        uint64_t mask = PAGE_SIZE - 1;

        if ( !highmem_start )
            xenheap_max_mfn(lo);

        end_boot_allocator();

        /* Pass the remaining memory in (lo, max_page) to the allocator. */
        for ( i = 0; i < boot_e820.nr_map; i++ )
        {
            uint64_t s, e;

            if ( boot_e820.map[i].type != E820_RAM )
                continue;
            s = (boot_e820.map[i].addr + mask) & ~mask;
            e = (boot_e820.map[i].addr + boot_e820.map[i].size) & ~mask;
            if ( PFN_DOWN(e) <= lo || PFN_DOWN(s) >= max_page )
                continue;
            if ( PFN_DOWN(s) <= lo )
                s = pfn_to_paddr(lo + 1);
            if ( PFN_DOWN(e) > max_page )
                e = pfn_to_paddr(max_page);
            init_domheap_pages(s, e);
        }
    }
    else
        end_boot_allocator();

    system_state = SYS_STATE_boot;

    bsp_stack = cpu_alloc_stack(0);
    if ( !bsp_stack )
        panic("No memory for BSP stack\n");

    console_init_ring();
    vesa_init();

    tasklet_subsys_init();

    paging_init();

    tboot_probe();

    open_softirq(NEW_TLBFLUSH_CLOCK_PERIOD_SOFTIRQ, new_tlbflush_clock_period);

    if ( opt_watchdog ) 
        nmi_watchdog = NMI_LOCAL_APIC;

    find_smp_config();

    dmi_scan_machine();

    mmio_ro_ranges = rangeset_new(NULL, "r/o mmio ranges",
                                  RANGESETF_prettyprint_hex);

    xsm_multiboot_init(module_map, mbi);

    /*
     * IOMMU-related ACPI table parsing may require some of the system domains
     * to be usable, e.g. for pci_hide_device()'s use of dom_xen.
     */
    setup_system_domains();

    /*
     * IOMMU-related ACPI table parsing has to happen before APIC probing, for
     * check_x2apic_preenabled() to be able to observe respective findings, in
     * particular iommu_intremap having got turned off.
     */
    acpi_iommu_init();

    /*
     * APIC probing needs to happen before general ACPI table parsing, as e.g.
     * generic_bigsmp_probe() may occur only afterwards.
     */
    generic_apic_probe();

    acpi_boot_init();

    if ( smp_found_config )
        get_smp_config();

    /*
     * In the shim case, the number of CPUs should be solely controlled by the
     * guest configuration file.
     */
    if ( pv_shim )
    {
        opt_nosmp = false;
        max_cpus = 0;
    }
    if ( opt_nosmp )
    {
        max_cpus = 0;
        set_nr_cpu_ids(1);
    }
    else
    {
        set_nr_cpu_ids(max_cpus);
        if ( !max_cpus )
            max_cpus = nr_cpu_ids;
    }

    if ( hypervisor_name )
        hypervisor_setup();

    /* Low mappings were only needed for some BIOS table parsing. */
    zap_low_mappings();

    init_apic_mappings();

    normalise_cpu_order();

    init_cpu_to_node();

    x2apic_bsp_setup();

    ret = init_irq_data();
    if ( ret < 0 )
        panic("Error %d setting up IRQ data\n", ret);

    console_init_irq();

    init_IRQ();

    timer_init();

    microcode_init_cache(module_map, mbi); /* Needs xmalloc() */

    tsx_init(); /* Needs microcode.  May change HLE/RTM feature bits. */

    identify_cpu(&boot_cpu_data);

    set_in_cr4(X86_CR4_OSFXSR | X86_CR4_OSXMMEXCPT);

    /* Do not enable SMEP/SMAP in PV shim on AMD and Hygon by default */
    if ( opt_smep == -1 )
        opt_smep = !pv_shim || !(boot_cpu_data.x86_vendor &
                                 (X86_VENDOR_AMD | X86_VENDOR_HYGON));
    if ( opt_smap == -1 )
        opt_smap = !pv_shim || !(boot_cpu_data.x86_vendor &
                                 (X86_VENDOR_AMD | X86_VENDOR_HYGON));

    if ( !opt_smep )
        setup_clear_cpu_cap(X86_FEATURE_SMEP);
    if ( cpu_has_smep && opt_smep != SMEP_HVM_ONLY )
        setup_force_cpu_cap(X86_FEATURE_XEN_SMEP);
    if ( boot_cpu_has(X86_FEATURE_XEN_SMEP) )
        set_in_cr4(X86_CR4_SMEP);

    if ( !opt_smap )
        setup_clear_cpu_cap(X86_FEATURE_SMAP);
    if ( cpu_has_smap && opt_smap != SMAP_HVM_ONLY )
        setup_force_cpu_cap(X86_FEATURE_XEN_SMAP);
    if ( boot_cpu_has(X86_FEATURE_XEN_SMAP) )
        set_in_cr4(X86_CR4_SMAP);

    cr4_pv32_mask = mmu_cr4_features & XEN_CR4_PV32_BITS;

    if ( boot_cpu_has(X86_FEATURE_FSGSBASE) )
        set_in_cr4(X86_CR4_FSGSBASE);

    if ( cpu_has_pku )
        set_in_cr4(X86_CR4_PKE);

    if ( opt_invpcid && cpu_has_invpcid )
        use_invpcid = true;

    if ( cpu_has_pks )
        wrpkrs_and_cache(0); /* Must be before setting CR4.PKS */

    init_speculation_mitigations();

    init_idle_domain();

    this_cpu(stubs.addr) = alloc_stub_page(smp_processor_id(),
                                           &this_cpu(stubs).mfn);
    BUG_ON(!this_cpu(stubs.addr));

    trap_init();

    rcu_init();

    early_time_init();

    arch_init_memory();

    alternative_instructions();

    local_irq_enable();

    early_msi_init();

    iommu_setup();    /* setup iommu if available */

    smp_prepare_cpus();

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

    alternative_branches();

    /*
     * NB: when running as a PV shim VCPUOP_up/down is wired to the shim
     * physical cpu_add/remove functions, so launch the guest with only
     * the BSP online and let it bring up the other CPUs as required.
     */
    if ( !pv_shim )
    {
        for_each_present_cpu ( i )
        {
            /* Set up cpu_to_node[]. */
            srat_detect_node(i);
            /* Set up node_to_cpumask based on cpu_to_node[]. */
            numa_add_cpu(i);

            if ( (park_offline_cpus || num_online_cpus() < max_cpus) &&
                 !cpu_online(i) )
            {
                ret = cpu_up(i);
                if ( ret != 0 )
                    printk("Failed to bring up CPU %u (error %d)\n", i, ret);
                else if ( num_online_cpus() > max_cpus ||
                          (!opt_smt &&
                           cpu_data[i].compute_unit_id == INVALID_CUID &&
                           cpumask_weight(per_cpu(cpu_sibling_mask, i)) > 1) )
                {
                    ret = cpu_down(i);
                    if ( !ret )
                        ++num_parked;
                    else
                        printk("Could not re-offline CPU%u (%d)\n", i, ret);
                }
            }
        }
    }

    printk("Brought up %ld CPUs\n", (long)num_online_cpus());
    if ( num_parked )
        printk(XENLOG_INFO "Parked %u CPUs\n", num_parked);
    smp_cpus_done();

    do_initcalls();

    if ( opt_watchdog ) 
        watchdog_setup();

    if ( !tboot_protect_mem_regions() )
        panic("Could not protect TXT memory regions\n");

    init_guest_cpu_policies();

    if ( xen_cpuidle )
        xen_processor_pmbits |= XEN_PROCESSOR_PM_CX;

    printk("%sNX (Execute Disable) protection %sactive\n",
           cpu_has_nx ? XENLOG_INFO : XENLOG_WARNING "Warning: ",
           cpu_has_nx ? "" : "not ");

    initrdidx = find_first_bit(module_map, mbi->mods_count);
    if ( bitmap_weight(module_map, mbi->mods_count) > 1 )
        printk(XENLOG_WARNING
               "Multiple initrd candidates, picking module #%u\n",
               initrdidx);

    /*
     * We're going to setup domain0 using the module(s) that we stashed safely
     * above our heap. The second module, if present, is an initrd ramdisk.
     */
    dom0 = create_dom0(mod, modules_headroom,
                       initrdidx < mbi->mods_count ? mod + initrdidx : NULL,
                       kextra, loader);
    if ( !dom0 )
        panic("Could not set up DOM0 guest OS\n");

    heap_init_late();

    init_trace_bufs();

    init_constructors();

    console_endboot();

    /* Hide UART from DOM0 if we're using it */
    serial_endboot();

    dmi_end_boot();

    setup_io_bitmap(dom0);

    if ( bsp_delay_spec_ctrl )
    {
        info->scf &= ~SCF_use_shadow;
        barrier();
        wrmsrl(MSR_SPEC_CTRL, default_xen_spec_ctrl);
        info->last_spec_ctrl = default_xen_spec_ctrl;
    }

    /* Copy the cpu info block, and move onto the BSP stack. */
    bsp_info = get_cpu_info_from_stack((unsigned long)bsp_stack);
    *bsp_info = *info;

    asm volatile ("mov %[stk], %%rsp; jmp %c[fn]" ::
                  [stk] "g" (&bsp_info->guest_cpu_user_regs),
                  [fn] "i" (reinit_bsp_stack) : "memory");
    unreachable();
}

void arch_get_xen_caps(xen_capabilities_info_t *info)
{
    /* Interface name is always xen-3.0-* for Xen-3.x. */
    int major = 3, minor = 0;
    char s[32];

    (*info)[0] = '\0';

    if ( IS_ENABLED(CONFIG_PV) )
    {
        snprintf(s, sizeof(s), "xen-%d.%d-x86_64 ", major, minor);
        safe_strcat(*info, s);

        if ( opt_pv32 )
        {
            snprintf(s, sizeof(s), "xen-%d.%d-x86_32p ", major, minor);
            safe_strcat(*info, s);
        }
    }
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

int __hwdom_init remove_xen_ranges(struct rangeset *r)
{
    paddr_t start, end;
    int rc;

    /* S3 resume code (and other real mode trampoline code) */
    rc = rangeset_remove_range(r, PFN_DOWN(bootsym_phys(trampoline_start)),
                               PFN_DOWN(bootsym_phys(trampoline_end) - 1));
    if ( rc )
        return rc;

    /*
     * This needs to remain in sync with the uses of the same symbols in
     * - __start_xen()
     * - is_xen_fixed_mfn()
     * - tboot_shutdown()
     */
    /* hypervisor .text + .rodata */
    rc = rangeset_remove_range(r, PFN_DOWN(__pa(&_stext)),
                               PFN_DOWN(__pa(&__2M_rodata_end) - 1));
    if ( rc )
        return rc;

    /* hypervisor .data + .bss */
    if ( efi_boot_mem_unused(&start, &end) )
    {
        ASSERT(__pa(start) >= __pa(&__2M_rwdata_start));
        rc = rangeset_remove_range(r, PFN_DOWN(__pa(&__2M_rwdata_start)),
                                   PFN_DOWN(__pa(start) - 1));
        if ( rc )
            return rc;
        ASSERT(__pa(end) <= __pa(&__2M_rwdata_end));
        rc = rangeset_remove_range(r, PFN_DOWN(__pa(end)),
                                   PFN_DOWN(__pa(&__2M_rwdata_end) - 1));
        if ( rc )
            return rc;
    }
    else
    {
        rc = rangeset_remove_range(r, PFN_DOWN(__pa(&__2M_rwdata_start)),
                                   PFN_DOWN(__pa(&__2M_rwdata_end) - 1));
        if ( rc )
            return rc;
    }

    return 0;
}

static int __hwdom_init cf_check io_bitmap_cb(
    unsigned long s, unsigned long e, void *ctx)
{
    const struct domain *d = ctx;
    unsigned int i;

    ASSERT(e <= INT_MAX);
    for ( i = s; i <= e; i++ )
        /*
         * Accesses to RTC ports also need to be trapped in order to keep
         * consistency with hypervisor accesses.
         */
        if ( !is_cmos_port(i, 1, d) )
            __clear_bit(i, d->arch.hvm.io_bitmap);

    return 0;
}

void __hwdom_init setup_io_bitmap(struct domain *d)
{
    if ( !is_hvm_domain(d) )
        return;

    bitmap_fill(d->arch.hvm.io_bitmap, 0x10000);
    if ( rangeset_report_ranges(d->arch.ioport_caps, 0, 0x10000,
                                io_bitmap_cb, d) )
        BUG();

    /*
     * We need to trap 4-byte accesses to 0xcf8 (see admin_io_okay(),
     * guest_io_read(), and guest_io_write()).
     */
    __set_bit(0xcf8, d->arch.hvm.io_bitmap);
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
