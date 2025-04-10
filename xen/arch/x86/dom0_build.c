/******************************************************************************
 * dom0_build.c
 * 
 * Copyright (c) 2002-2005, K A Fraser
 */

#include <xen/init.h>
#include <xen/iocap.h>
#include <xen/libelf.h>
#include <xen/param.h>
#include <xen/pfn.h>
#include <xen/sched.h>
#include <xen/softirq.h>

#include <asm/amd.h>
#include <asm/bootinfo.h>
#include <asm/dom0_build.h>
#include <asm/guest.h>
#include <asm/hpet.h>
#include <asm/hvm/emulate.h>
#include <asm/io-ports.h>
#include <asm/io_apic.h>
#include <asm/p2m.h>
#include <asm/setup.h>
#include <asm/spec_ctrl.h>

struct memsize {
    long nr_pages;
    unsigned int percent;
    bool minus;
};

static struct memsize __initdata dom0_size;
static struct memsize __initdata dom0_min_size;
static struct memsize __initdata dom0_max_size = { .nr_pages = LONG_MAX };
static bool __initdata dom0_mem_set;

static bool __init memsize_gt_zero(const struct memsize *sz)
{
    return !sz->minus && sz->nr_pages;
}

static unsigned long __init get_memsize(const struct memsize *sz,
                                        unsigned long avail)
{
    unsigned long pages;

    pages = sz->nr_pages + sz->percent * avail / 100;
    return sz->minus ? avail - pages : pages;
}

/*
 * dom0_mem=[min:<min_amt>,][max:<max_amt>,][<amt>]
 *
 * <min_amt>: The minimum amount of memory which should be allocated for dom0.
 * <max_amt>: The maximum amount of memory which should be allocated for dom0.
 * <amt>:     The precise amount of memory to allocate for dom0.
 *
 * The format of <min_amt>, <max_amt> and <amt> is as follows:
 * <size> | <frac>% | <size>+<frac>%
 * <size> is a size value like 1G (1 GByte), <frac> is percentage of host
 * memory (so 1G+10% means 10 percent of host memory + 1 GByte).
 *
 * Notes:
 *  1. <amt> is clamped from below by <min_amt> and from above by available
 *     memory and <max_amt>
 *  2. <min_amt> is clamped from above by available memory and <max_amt>
 *  3. <min_amt> is ignored if it is greater than <max_amt>
 *  4. If <amt> is not specified, it is calculated as follows:
 *     "All of memory is allocated to domain 0, minus 1/16th which is reserved
 *      for uses such as DMA buffers (the reservation is clamped to 128MB)."
 *
 * Each value can be specified as positive or negative:
 *  If +ve: The specified amount is an absolute value.
 *  If -ve: The specified amount is subtracted from total available memory.
 */
static int __init parse_amt(const char *s, const char **ps, struct memsize *sz)
{
    unsigned long val;
    struct memsize tmp = { };
    unsigned int items = 0;

    tmp.minus = (*s == '-');
    if ( tmp.minus )
        s++;

    do
    {
        if ( !isdigit(*s) )
            return -EINVAL;

        val = parse_size_and_unit(s, ps);
        s = *ps;
        if ( *s == '%' )
        {
            if ( val >= 100 )
                return -EINVAL;
            tmp.percent = val;
            s++;
            items++; /* No other item allowed. */
        }
        else
        {
            /* <size> item must be first one. */
            if ( items )
                return -EINVAL;
            tmp.nr_pages = val >> PAGE_SHIFT;
        }
        items++;
    } while ( *s++ == '+' && items < 2 );

    *ps = --s;
    if ( *s && *s != ',' )
        return -EINVAL;

    *sz = tmp;

    return 0;
}

static int __init cf_check parse_dom0_mem(const char *s)
{
    int ret;

    dom0_mem_set = true;

    /* xen-shim uses shim_mem parameter instead of dom0_mem */
    if ( pv_shim )
    {
        printk("Ignoring dom0_mem param in pv-shim mode\n");
        return 0;
    }

    do {
        if ( !strncmp(s, "min:", 4) )
            ret = parse_amt(s + 4, &s, &dom0_min_size);
        else if ( !strncmp(s, "max:", 4) )
            ret = parse_amt(s + 4, &s, &dom0_max_size);
        else
            ret = parse_amt(s, &s, &dom0_size);
    } while ( *s++ == ',' && !ret );

    return s[-1] ? -EINVAL : ret;
}
custom_param("dom0_mem", parse_dom0_mem);

static unsigned int __initdata opt_dom0_max_vcpus_min = 1;
static unsigned int __initdata opt_dom0_max_vcpus_max = UINT_MAX;

static int __init cf_check parse_dom0_max_vcpus(const char *s)
{
    if ( *s == '-' )                   /* -M */
        opt_dom0_max_vcpus_max = simple_strtoul(s + 1, &s, 0);
    else                               /* N, N-, or N-M */
    {
        opt_dom0_max_vcpus_min = simple_strtoul(s, &s, 0);
        if ( opt_dom0_max_vcpus_min == 0 )
            opt_dom0_max_vcpus_min = 1;
        if ( !*s )                    /* N */
            opt_dom0_max_vcpus_max = opt_dom0_max_vcpus_min;
        else if ( *s++ == '-' && *s ) /* N-M */
            opt_dom0_max_vcpus_max = simple_strtoul(s, &s, 0);
    }

    return *s ? -EINVAL : 0;
}
custom_param("dom0_max_vcpus", parse_dom0_max_vcpus);

static __initdata unsigned int dom0_nr_pxms;
static __initdata unsigned int dom0_pxms[MAX_NUMNODES] =
    { [0 ... MAX_NUMNODES - 1] = ~0 };
bool __initdata dom0_affinity_relaxed;

static int __init cf_check parse_dom0_nodes(const char *s)
{
    const char *ss;
    int rc = 0;

    do {
        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        if ( isdigit(*s) )
        {
            const char *endp;

            if ( dom0_nr_pxms >= ARRAY_SIZE(dom0_pxms) )
                rc = -E2BIG;
            else if ( (dom0_pxms[dom0_nr_pxms] = simple_strtoul(s, &endp, 0),
                       endp != ss) )
                rc = -EINVAL;
            else
                dom0_nr_pxms++;
        }
        else if ( !cmdline_strcmp(s, "relaxed") )
            dom0_affinity_relaxed = true;
        else if ( !cmdline_strcmp(s, "strict") )
            dom0_affinity_relaxed = false;
        else
            rc = -EINVAL;

        s = ss + 1;
    } while ( *ss );

    return rc;
}
custom_param("dom0_nodes", parse_dom0_nodes);

cpumask_t __initdata dom0_cpus;
static nodemask_t __initdata dom0_nodes;

unsigned int __init dom0_max_vcpus(void)
{
    unsigned int i, max_vcpus, limit;
    nodeid_t node;

    if ( pv_shim )
    {
        nodes_setall(dom0_nodes);

        /*
         * When booting in shim mode APs are not started until the guest brings
         * other vCPUs up.
         */
        cpumask_set_cpu(0, &dom0_cpus);

        /* On PV shim mode allow the guest to have as many CPUs as available. */
        return nr_cpu_ids;
    }


    for ( i = 0; i < dom0_nr_pxms; ++i )
        if ( (node = pxm_to_node(dom0_pxms[i])) != NUMA_NO_NODE )
            node_set(node, dom0_nodes);
    nodes_and(dom0_nodes, dom0_nodes, node_online_map);
    if ( nodes_empty(dom0_nodes) )
        dom0_nodes = node_online_map;
    for_each_node_mask ( node, dom0_nodes )
        cpumask_or(&dom0_cpus, &dom0_cpus, &node_to_cpumask(node));
    cpumask_and(&dom0_cpus, &dom0_cpus, cpupool_valid_cpus(cpupool0));
    if ( cpumask_empty(&dom0_cpus) )
        cpumask_copy(&dom0_cpus, cpupool_valid_cpus(cpupool0));

    max_vcpus = cpumask_weight(&dom0_cpus);
    if ( opt_dom0_max_vcpus_min > max_vcpus )
        max_vcpus = opt_dom0_max_vcpus_min;
    if ( opt_dom0_max_vcpus_max < max_vcpus )
        max_vcpus = opt_dom0_max_vcpus_max;
    limit = opt_dom0_pvh ? HVM_MAX_VCPUS : MAX_VIRT_CPUS;
    if ( max_vcpus > limit )
        max_vcpus = limit;

    return max_vcpus;
}

struct vcpu *__init alloc_dom0_vcpu0(struct domain *dom0)
{
    dom0->node_affinity = dom0_nodes;
    dom0->auto_node_affinity = !dom0_nr_pxms;

    return vcpu_create(dom0, 0);
}

#ifdef CONFIG_SHADOW_PAGING
bool __initdata opt_dom0_shadow;
#endif
bool __initdata opt_dom0_pvh = !IS_ENABLED(CONFIG_PV);
bool __initdata opt_dom0_verbose = IS_ENABLED(CONFIG_VERBOSE_DEBUG);
bool __initdata opt_dom0_msr_relaxed;

int __init parse_arch_dom0_param(const char *s, const char *e)
{
    int val;

    if ( IS_ENABLED(CONFIG_PV) && !cmdline_strcmp(s, "pv") )
        opt_dom0_pvh = false;
    else if ( IS_ENABLED(CONFIG_HVM) && !cmdline_strcmp(s, "pvh") )
        opt_dom0_pvh = true;
#ifdef CONFIG_SHADOW_PAGING
    else if ( (val = parse_boolean("shadow", s, e)) >= 0 )
        opt_dom0_shadow = val;
#endif
    else if ( (val = parse_boolean("verbose", s, e)) >= 0 )
        opt_dom0_verbose = val;
    else if ( IS_ENABLED(CONFIG_PV) &&
              (val = parse_boolean("cpuid-faulting", s, e)) >= 0 )
        opt_dom0_cpuid_faulting = val;
    else if ( (val = parse_boolean("msr-relaxed", s, e)) >= 0 )
        opt_dom0_msr_relaxed = val;
#ifdef CONFIG_HVM
    else if ( (val = parse_boolean("pf-fixup", s, e)) >= 0 )
        opt_dom0_pf_fixup = val;
#endif
    else
        return -EINVAL;

    return 0;
}

static char __initdata opt_dom0_ioports_disable[200] = "";
string_param("dom0_ioports_disable", opt_dom0_ioports_disable);

static bool __initdata ro_hpet = true;
boolean_param("ro-hpet", ro_hpet);

unsigned int __initdata dom0_memflags = MEMF_no_dma|MEMF_exact_node;

unsigned long __init dom0_paging_pages(const struct domain *d,
                                       unsigned long nr_pages)
{
    /* Keep in sync with libxl__get_required_paging_memory(). */
    unsigned long memkb = nr_pages * (PAGE_SIZE / 1024);

    memkb = 4 * (256 * d->max_vcpus +
                 (is_pv_domain(d) ? opt_dom0_shadow || opt_pv_l1tf_hwdom
                                  : 1 + opt_dom0_shadow) *
                 (memkb / 1024));

    return DIV_ROUND_UP(memkb, 1024) << (20 - PAGE_SHIFT);
}


/*
 * If allocation isn't specified, reserve 1/16th of available memory for
 * things like DMA buffers. This reservation is clamped to a maximum of 128MB.
 */
static unsigned long __init default_nr_pages(unsigned long avail)
{
    return avail - (pv_shim ? pv_shim_mem(avail)
                            : min(avail / 16, 128UL << (20 - PAGE_SHIFT)));
}

unsigned long __init dom0_compute_nr_pages(
    struct domain *d, struct elf_dom_parms *parms, unsigned long initrd_len)
{
    nodeid_t node;
    unsigned long avail = 0, nr_pages, min_pages, max_pages, iommu_pages = 0;

    /* The ordering of operands is to work around a clang5 issue. */
    if ( CONFIG_DOM0_MEM[0] && !dom0_mem_set )
        parse_dom0_mem(CONFIG_DOM0_MEM);

    for_each_node_mask ( node, dom0_nodes )
        avail += avail_domheap_pages_region(node, 0, 0) +
                 initial_images_nrpages(node);

    /* Reserve memory for further dom0 vcpu-struct allocations... */
    avail -= (d->max_vcpus - 1UL)
             << get_order_from_bytes(sizeof(struct vcpu));
    /* ...and compat_l4's, if needed. */
    if ( is_pv_32bit_domain(d) )
        avail -= d->max_vcpus - 1;

    /* Reserve memory for iommu_dom0_init() (rough estimate). */
    if ( is_iommu_enabled(d) && !iommu_hwdom_passthrough )
    {
        unsigned int s;

        for ( s = 9; s < BITS_PER_LONG; s += 9 )
            iommu_pages += max_pdx >> s;

        avail -= iommu_pages;
    }

    if ( paging_mode_enabled(d) || opt_dom0_shadow || opt_pv_l1tf_hwdom )
    {
        unsigned long cpu_pages;

        nr_pages = get_memsize(&dom0_size, avail) ?: default_nr_pages(avail);

        /*
         * Clamp according to min/max limits and available memory
         * (preliminary).
         */
        nr_pages = max(nr_pages, get_memsize(&dom0_min_size, avail));
        nr_pages = min(nr_pages, get_memsize(&dom0_max_size, avail));
        nr_pages = min(nr_pages, avail);

        cpu_pages = dom0_paging_pages(d, nr_pages);

        if ( !iommu_use_hap_pt(d) )
            avail -= cpu_pages;
        else if ( cpu_pages > iommu_pages )
            avail -= cpu_pages - iommu_pages;
    }

    nr_pages = get_memsize(&dom0_size, avail) ?: default_nr_pages(avail);
    min_pages = get_memsize(&dom0_min_size, avail);
    max_pages = get_memsize(&dom0_max_size, avail);

    /* Clamp according to min/max limits and available memory (final). */
    nr_pages = max(nr_pages, min_pages);
    nr_pages = min(nr_pages, max_pages);
    nr_pages = min(nr_pages, avail);

    if ( is_pv_domain(d) &&
         (parms->p2m_base == UNSET_ADDR) && !memsize_gt_zero(&dom0_size) &&
         (!memsize_gt_zero(&dom0_min_size) || (nr_pages > min_pages)) )
    {
        /*
         * Legacy Linux kernels (i.e. such without a XEN_ELFNOTE_INIT_P2M
         * note) require that there is enough virtual space beyond the initial
         * allocation to set up their initial page tables. This space is
         * roughly the same size as the p2m table, so make sure the initial
         * allocation doesn't consume more than about half the space that's
         * available between params.virt_base and the address space end.
         */
        unsigned long vstart, vend, end;
        size_t sizeof_long = is_pv_32bit_domain(d) ? sizeof(int) : sizeof(long);

        vstart = parms->virt_base;
        vend = round_pgup(parms->virt_kend);
        if ( !parms->unmapped_initrd )
            vend += round_pgup(initrd_len);
        end = vend + nr_pages * sizeof_long;

        if ( end > vstart )
            end += end - vstart;
        if ( end <= vstart ||
             (sizeof_long < sizeof(end) && end > (1UL << (8 * sizeof_long))) )
        {
            end = sizeof_long >= sizeof(end) ? 0 : 1UL << (8 * sizeof_long);
            nr_pages = (end - vend) / (2 * sizeof_long);
            if ( memsize_gt_zero(&dom0_min_size) && nr_pages < min_pages )
                nr_pages = min_pages;
            printk("Dom0 memory clipped to %lu pages\n", nr_pages);
        }
    }

    d->max_pages = min_t(unsigned long, max_pages, UINT_MAX);

    return nr_pages;
}

static void __init process_dom0_ioports_disable(struct domain *dom0)
{
    unsigned long io_from, io_to;
    char *t, *s = opt_dom0_ioports_disable;
    const char *u;

    if ( *s == '\0' )
        return;

    while ( (t = strsep(&s, ",")) != NULL )
    {
        io_from = simple_strtoul(t, &u, 16);
        if ( u == t )
        {
        parse_error:
            printk("Invalid ioport range <%s> "
                   "in dom0_ioports_disable, skipping\n", t);
            continue;
        }

        if ( *u == '\0' )
            io_to = io_from;
        else if ( *u == '-' )
            io_to = simple_strtoul(u + 1, &u, 16);
        else
            goto parse_error;

        if ( (*u != '\0') || (io_to < io_from) || (io_to >= 65536) )
            goto parse_error;

        printk("Disabling dom0 access to ioport range %04lx-%04lx\n",
            io_from, io_to);

        if ( ioports_deny_access(dom0, io_from, io_to) != 0 )
            BUG();
    }
}

int __init dom0_setup_permissions(struct domain *d)
{
    unsigned long mfn;
    unsigned int i, offs;
    int rc;

    if ( pv_shim )
        return 0;

    /* The hardware domain is initially permitted full I/O capabilities. */
    rc = ioports_permit_access(d, 0, 0xFFFF);
    rc |= iomem_permit_access(d, 0UL,
                              PFN_DOWN(1UL << domain_max_paddr_bits(d)) - 1);
    rc |= irqs_permit_access(d, 1, nr_irqs_gsi - 1);

    /* Modify I/O port access permissions. */

    for ( offs = 0, i = ISOLATE_LSB(i8259A_alias_mask) ?: 2;
          offs <= i8259A_alias_mask; offs += i )
    {
        if ( offs & ~i8259A_alias_mask )
            continue;
        /* Master Interrupt Controller (PIC). */
        rc |= ioports_deny_access(d, 0x20 + offs, 0x21 + offs);
        /* Slave Interrupt Controller (PIC). */
        rc |= ioports_deny_access(d, 0xA0 + offs, 0xA1 + offs);
    }

    /* ELCR of both PICs. */
    rc |= ioports_deny_access(d, 0x4D0, 0x4D1);

    /* Interval Timer (PIT). */
    for ( offs = 0, i = ISOLATE_LSB(pit_alias_mask) ?: 4;
          offs <= pit_alias_mask; offs += i )
        if ( !(offs & ~pit_alias_mask) )
            rc |= ioports_deny_access(d, PIT_CH0 + offs, PIT_MODE + offs);

    /* PIT Channel 2 / PC Speaker Control. */
    rc |= ioports_deny_access(d, 0x61, 0x61);

    /* INIT# and alternative A20M# control. */
    rc |= ioports_deny_access(d, 0x92, 0x92);

    /* IGNNE# control. */
    rc |= ioports_deny_access(d, 0xF0, 0xF0);

    /* ACPI PM Timer. */
    if ( pmtmr_ioport )
        rc |= ioports_deny_access(d, pmtmr_ioport, pmtmr_ioport + 3);

    /* Reset control. */
    rc |= ioports_deny_access(d, 0xCF9, 0xCF9);

    /* PCI configuration space (NB. 0xCF8 has special treatment). */
    rc |= ioports_deny_access(d, 0xCFC, 0xCFF);

#ifdef CONFIG_HVM
    if ( is_hvm_domain(d) )
    {
        /* ISA DMA controller, channels 0-3 (incl possible aliases). */
        rc |= ioports_deny_access(d, 0x00, 0x1F);
        /* ISA DMA controller, page registers (incl various reserved ones). */
        rc |= ioports_deny_access(d, 0x80 + !!hvm_port80_allowed, 0x8F);
        /* ISA DMA controller, channels 4-7 (incl usual aliases). */
        rc |= ioports_deny_access(d, 0xC0, 0xDF);

        /* HVM debug console IO port. */
        rc |= ioports_deny_access(d, XEN_HVM_DEBUGCONS_IOPORT,
                                  XEN_HVM_DEBUGCONS_IOPORT);
        if ( amd_acpi_c1e_quirk )
            rc |= ioports_deny_access(d, acpi_smi_cmd, acpi_smi_cmd);
    }
#endif
    /* Command-line I/O ranges. */
    process_dom0_ioports_disable(d);

    /* Modify I/O memory access permissions. */

    /* Local APIC. */
    if ( mp_lapic_addr != 0 )
    {
        mfn = paddr_to_pfn(mp_lapic_addr);
        rc |= iomem_deny_access(d, mfn, mfn);
    }
    /* If using an emulated local APIC make sure its MMIO is unpopulated. */
    if ( has_vlapic(d) )
    {
        /* Xen doesn't allow changing the local APIC MMIO window position. */
        mfn = paddr_to_pfn(APIC_DEFAULT_PHYS_BASE);
        rc |= iomem_deny_access(d, mfn, mfn);
    }
    /* I/O APICs. */
    for ( i = 0; i < nr_ioapics; i++ )
    {
        mfn = paddr_to_pfn(mp_ioapics[i].mpc_apicaddr);
        /* If emulating IO-APIC(s) make sure the base address is unmapped. */
        if ( has_vioapic(d) ||
             !rangeset_contains_singleton(mmio_ro_ranges, mfn) )
            rc |= iomem_deny_access(d, mfn, mfn);
    }
    /* HyperTransport range. */
    if ( boot_cpu_data.x86_vendor & (X86_VENDOR_AMD | X86_VENDOR_HYGON) )
    {
        mfn = paddr_to_pfn(1UL <<
                           (boot_cpu_data.x86 < 0x17 ? 40 : paddr_bits));
        rc |= iomem_deny_access(d, mfn - paddr_to_pfn(3UL << 32), mfn - 1);
    }

    /* Remove access to E820_UNUSABLE I/O regions above 1MB. */
    for ( i = 0; i < e820.nr_map; i++ )
    {
        unsigned long sfn, efn;
        sfn = max_t(unsigned long, paddr_to_pfn(e820.map[i].addr), 0x100UL);
        efn = paddr_to_pfn(e820.map[i].addr + e820.map[i].size - 1);
        if ( (e820.map[i].type == E820_UNUSABLE) &&
             (e820.map[i].size != 0) &&
             (sfn <= efn) )
            rc |= iomem_deny_access(d, sfn, efn);
    }

    /* Prevent access to HPET */
    if ( hpet_address )
    {
        u8 prot_flags = hpet_flags & ACPI_HPET_PAGE_PROTECT_MASK;

        mfn = paddr_to_pfn(hpet_address);
        if ( prot_flags == ACPI_HPET_PAGE_PROTECT4 )
            rc |= iomem_deny_access(d, mfn, mfn);
        else if ( prot_flags == ACPI_HPET_PAGE_PROTECT64 )
            rc |= iomem_deny_access(d, mfn, mfn + 15);
        else if ( ro_hpet )
            rc |= rangeset_add_singleton(mmio_ro_ranges, mfn);
    }

    if ( has_vpci(d) )
        /*
         * TODO: runtime added MMCFG regions are not checked to make sure they
         * don't overlap with already mapped regions, thus preventing trapping.
         */
        rc |= vpci_mmcfg_deny_access(d);

    return rc;
}

int __init construct_dom0(const struct boot_domain *bd)
{
    int rc;
    const struct domain *d = bd->d;

    /* Sanity! */
    BUG_ON(!pv_shim && d->domain_id != 0);
    BUG_ON(d->vcpu[0] == NULL);
    BUG_ON(d->vcpu[0]->is_initialised);

    process_pending_softirqs();

    if ( is_hvm_domain(d) )
        rc = dom0_construct_pvh(bd);
    else if ( is_pv_domain(d) )
        rc = dom0_construct_pv(bd);
    else
        panic("Cannot construct Dom0. No guest interface available\n");

    if ( rc )
        return rc;

    /* Sanity! */
    BUG_ON(!d->vcpu[0]->is_initialised);

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
