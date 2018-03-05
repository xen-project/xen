/******************************************************************************
 * dom0_build.c
 * 
 * Copyright (c) 2002-2005, K A Fraser
 */

#include <xen/init.h>
#include <xen/iocap.h>
#include <xen/libelf.h>
#include <xen/pfn.h>
#include <xen/sched.h>
#include <xen/sched-if.h>
#include <xen/softirq.h>

#include <asm/dom0_build.h>
#include <asm/guest.h>
#include <asm/hpet.h>
#include <asm/io_apic.h>
#include <asm/p2m.h>
#include <asm/setup.h>

static long __initdata dom0_nrpages;
static long __initdata dom0_min_nrpages;
static long __initdata dom0_max_nrpages = LONG_MAX;

/*
 * dom0_mem=[min:<min_amt>,][max:<max_amt>,][<amt>]
 * 
 * <min_amt>: The minimum amount of memory which should be allocated for dom0.
 * <max_amt>: The maximum amount of memory which should be allocated for dom0.
 * <amt>:     The precise amount of memory to allocate for dom0.
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
static long __init parse_amt(const char *s, const char **ps)
{
    long pages = parse_size_and_unit((*s == '-') ? s+1 : s, ps) >> PAGE_SHIFT;
    return (*s == '-') ? -pages : pages;
}

static int __init parse_dom0_mem(const char *s)
{
    /* xen-shim uses shim_mem parameter instead of dom0_mem */
    if ( pv_shim )
    {
        printk("Ignoring dom0_mem param in pv-shim mode\n");
        return 0;
    }

    do {
        if ( !strncmp(s, "min:", 4) )
            dom0_min_nrpages = parse_amt(s+4, &s);
        else if ( !strncmp(s, "max:", 4) )
            dom0_max_nrpages = parse_amt(s+4, &s);
        else
            dom0_nrpages = parse_amt(s, &s);
    } while ( *s++ == ',' );

    return s[-1] ? -EINVAL : 0;
}
custom_param("dom0_mem", parse_dom0_mem);

static unsigned int __initdata opt_dom0_max_vcpus_min = 1;
static unsigned int __initdata opt_dom0_max_vcpus_max = UINT_MAX;

static int __init parse_dom0_max_vcpus(const char *s)
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
static __initdata bool dom0_affinity_relaxed;

static int __init parse_dom0_nodes(const char *s)
{
    do {
        if ( isdigit(*s) )
        {
            if ( dom0_nr_pxms >= ARRAY_SIZE(dom0_pxms) )
                return -E2BIG;
            dom0_pxms[dom0_nr_pxms] = simple_strtoul(s, &s, 0);
            if ( !*s || *s == ',' )
                ++dom0_nr_pxms;
        }
        else if ( !strncmp(s, "relaxed", 7) && (!s[7] || s[7] == ',') )
        {
            dom0_affinity_relaxed = true;
            s += 7;
        }
        else if ( !strncmp(s, "strict", 6) && (!s[6] || s[6] == ',') )
        {
            dom0_affinity_relaxed = false;
            s += 6;
        }
        else
            return -EINVAL;
    } while ( *s++ == ',' );

    return s[-1] ? -EINVAL : 0;
}
custom_param("dom0_nodes", parse_dom0_nodes);

static cpumask_t __initdata dom0_cpus;

struct vcpu *__init dom0_setup_vcpu(struct domain *d,
                                    unsigned int vcpu_id,
                                    unsigned int prev_cpu)
{
    unsigned int cpu = cpumask_cycle(prev_cpu, &dom0_cpus);
    struct vcpu *v = alloc_vcpu(d, vcpu_id, cpu);

    if ( v )
    {
        if ( pv_shim )
        {

            cpumask_setall(v->cpu_hard_affinity);
            cpumask_setall(v->cpu_soft_affinity);
        }
        else
        {
            if ( !d->is_pinned && !dom0_affinity_relaxed )
                cpumask_copy(v->cpu_hard_affinity, &dom0_cpus);
            cpumask_copy(v->cpu_soft_affinity, &dom0_cpus);
        }
    }

    return v;
}

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
    cpumask_and(&dom0_cpus, &dom0_cpus, cpupool0->cpu_valid);
    if ( cpumask_empty(&dom0_cpus) )
        cpumask_copy(&dom0_cpus, cpupool0->cpu_valid);

    max_vcpus = cpumask_weight(&dom0_cpus);
    if ( opt_dom0_max_vcpus_min > max_vcpus )
        max_vcpus = opt_dom0_max_vcpus_min;
    if ( opt_dom0_max_vcpus_max < max_vcpus )
        max_vcpus = opt_dom0_max_vcpus_max;
    limit = dom0_pvh ? HVM_MAX_VCPUS : MAX_VIRT_CPUS;
    if ( max_vcpus > limit )
        max_vcpus = limit;

    return max_vcpus;
}

struct vcpu *__init alloc_dom0_vcpu0(struct domain *dom0)
{
    unsigned int max_vcpus = dom0_max_vcpus();

    dom0->node_affinity = dom0_nodes;
    dom0->auto_node_affinity = !dom0_nr_pxms;

    dom0->vcpu = xzalloc_array(struct vcpu *, max_vcpus);
    if ( !dom0->vcpu )
        return NULL;
    dom0->max_vcpus = max_vcpus;

    return dom0_setup_vcpu(dom0, 0,
                           cpumask_last(&dom0_cpus) /* so it wraps around to first pcpu */);
}

#ifdef CONFIG_SHADOW_PAGING
bool __initdata opt_dom0_shadow;
#endif
bool __initdata dom0_pvh;

/*
 * List of parameters that affect Dom0 creation:
 *
 *  - pvh               Create a PVHv2 Dom0.
 *  - shadow            Use shadow paging for Dom0.
 */
static int __init parse_dom0_param(const char *s)
{
    const char *ss;
    int rc = 0;

    do {

        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        if ( !strncmp(s, "pvh", ss - s) )
            dom0_pvh = true;
#ifdef CONFIG_SHADOW_PAGING
        else if ( !strncmp(s, "shadow", ss - s) )
            opt_dom0_shadow = true;
#endif
        else
            rc = -EINVAL;

        s = ss + 1;
    } while ( *ss );

    return rc;
}
custom_param("dom0", parse_dom0_param);

static char __initdata opt_dom0_ioports_disable[200] = "";
string_param("dom0_ioports_disable", opt_dom0_ioports_disable);

static bool __initdata ro_hpet = true;
boolean_param("ro-hpet", ro_hpet);

unsigned int __initdata dom0_memflags = MEMF_no_dma|MEMF_exact_node;

unsigned long __init dom0_paging_pages(const struct domain *d,
                                       unsigned long nr_pages)
{
    /* Copied from: libxl_get_required_shadow_memory() */
    unsigned long memkb = nr_pages * (PAGE_SIZE / 1024);

    memkb = 4 * (256 * d->max_vcpus + 2 * (memkb / 1024));

    return ((memkb + 1023) / 1024) << (20 - PAGE_SHIFT);
}

unsigned long __init dom0_compute_nr_pages(
    struct domain *d, struct elf_dom_parms *parms, unsigned long initrd_len)
{
    nodeid_t node;
    unsigned long avail = 0, nr_pages, min_pages, max_pages;
    bool need_paging;

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
    if ( iommu_enabled )
    {
        unsigned int s;

        for ( s = 9; s < BITS_PER_LONG; s += 9 )
            avail -= max_pdx >> s;
    }

    need_paging = is_hvm_domain(d) &&
        (!iommu_hap_pt_share || !paging_mode_hap(d));
    for ( ; ; need_paging = false )
    {
        nr_pages = dom0_nrpages;
        min_pages = dom0_min_nrpages;
        max_pages = dom0_max_nrpages;

        /*
         * If allocation isn't specified, reserve 1/16th of available memory
         * for things like DMA buffers. This reservation is clamped to a
         * maximum of 128MB.
         */
        if ( !nr_pages )
            nr_pages = -(pv_shim ? pv_shim_mem(avail)
                                 : min(avail / 16, 128UL << (20 - PAGE_SHIFT)));

        /* Negative specification means "all memory - specified amount". */
        if ( (long)nr_pages  < 0 ) nr_pages  += avail;
        if ( (long)min_pages < 0 ) min_pages += avail;
        if ( (long)max_pages < 0 ) max_pages += avail;

        /* Clamp according to min/max limits and available memory. */
        nr_pages = max(nr_pages, min_pages);
        nr_pages = min(nr_pages, max_pages);
        nr_pages = min(nr_pages, avail);

        if ( !need_paging )
            break;

        /* Reserve memory for shadow or HAP. */
        avail -= dom0_paging_pages(d, nr_pages);
    }

    if ( is_pv_domain(d) &&
         (parms->p2m_base == UNSET_ADDR) && (dom0_nrpages <= 0) &&
         ((dom0_min_nrpages <= 0) || (nr_pages > min_pages)) )
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
            if ( dom0_min_nrpages > 0 && nr_pages < min_pages )
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
    unsigned int i;
    int rc;

    if ( pv_shim )
        return 0;

    /* The hardware domain is initially permitted full I/O capabilities. */
    rc = ioports_permit_access(d, 0, 0xFFFF);
    rc |= iomem_permit_access(d, 0UL, (1UL << (paddr_bits - PAGE_SHIFT)) - 1);
    rc |= irqs_permit_access(d, 1, nr_irqs_gsi - 1);

    /* Modify I/O port access permissions. */

    /* Master Interrupt Controller (PIC). */
    rc |= ioports_deny_access(d, 0x20, 0x21);
    /* Slave Interrupt Controller (PIC). */
    rc |= ioports_deny_access(d, 0xA0, 0xA1);
    /* Interval Timer (PIT). */
    rc |= ioports_deny_access(d, 0x40, 0x43);
    /* PIT Channel 2 / PC Speaker Control. */
    rc |= ioports_deny_access(d, 0x61, 0x61);
    /* ACPI PM Timer. */
    if ( pmtmr_ioport )
        rc |= ioports_deny_access(d, pmtmr_ioport, pmtmr_ioport + 3);
    /* PCI configuration space (NB. 0xcf8 has special treatment). */
    rc |= ioports_deny_access(d, 0xcfc, 0xcff);
    /* Command-line I/O ranges. */
    process_dom0_ioports_disable(d);

    /* Modify I/O memory access permissions. */

    /* Local APIC. */
    if ( mp_lapic_addr != 0 )
    {
        mfn = paddr_to_pfn(mp_lapic_addr);
        rc |= iomem_deny_access(d, mfn, mfn);
    }
    /* I/O APICs. */
    for ( i = 0; i < nr_ioapics; i++ )
    {
        mfn = paddr_to_pfn(mp_ioapics[i].mpc_apicaddr);
        if ( !rangeset_contains_singleton(mmio_ro_ranges, mfn) )
            rc |= iomem_deny_access(d, mfn, mfn);
    }
    /* MSI range. */
    rc |= iomem_deny_access(d, paddr_to_pfn(MSI_ADDR_BASE_LO),
                            paddr_to_pfn(MSI_ADDR_BASE_LO +
                                         MSI_ADDR_DEST_ID_MASK));
    /* HyperTransport range. */
    if ( boot_cpu_data.x86_vendor == X86_VENDOR_AMD )
        rc |= iomem_deny_access(d, paddr_to_pfn(0xfdULL << 32),
                                paddr_to_pfn((1ULL << 40) - 1));

    /* Remove access to E820_UNUSABLE I/O regions above 1MB. */
    for ( i = 0; i < e820.nr_map; i++ )
    {
        unsigned long sfn, efn;
        sfn = max_t(unsigned long, paddr_to_pfn(e820.map[i].addr), 0x100ul);
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

    return rc;
}

int __init construct_dom0(struct domain *d, const module_t *image,
                          unsigned long image_headroom, module_t *initrd,
                          void *(*bootstrap_map)(const module_t *),
                          char *cmdline)
{
    int rc;

    /* Sanity! */
    BUG_ON(!pv_shim && d->domain_id != 0);
    BUG_ON(d->vcpu[0] == NULL);
    BUG_ON(d->vcpu[0]->is_initialised);

    process_pending_softirqs();

#ifdef CONFIG_SHADOW_PAGING
    if ( opt_dom0_shadow && !dom0_pvh )
    {
        opt_dom0_shadow = false;
        printk(XENLOG_WARNING "Shadow Dom0 requires PVH. Option ignored.\n");
    }
#endif

    rc = (is_hvm_domain(d) ? dom0_construct_pvh : dom0_construct_pv)
         (d, image, image_headroom, initrd, bootstrap_map, cmdline);
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
