/*
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/sched.h>
#include <xen/iommu.h>
#include <xen/paging.h>
#include <xen/guest_access.h>
#include <xen/event.h>
#include <xen/param.h>
#include <xen/softirq.h>
#include <xen/keyhandler.h>
#include <xsm/xsm.h>

#ifdef CONFIG_X86
#include <asm/e820.h>
#endif

unsigned int __read_mostly iommu_dev_iotlb_timeout = 1000;
integer_param("iommu_dev_iotlb_timeout", iommu_dev_iotlb_timeout);

bool __initdata iommu_enable = 1;
bool __read_mostly iommu_enabled;
bool __read_mostly force_iommu;
bool __read_mostly iommu_verbose;
static bool __read_mostly iommu_crash_disable;

#define IOMMU_quarantine_none         0 /* aka false */
#define IOMMU_quarantine_basic        1 /* aka true */
#define IOMMU_quarantine_scratch_page 2
#ifdef CONFIG_HAS_PCI
uint8_t __read_mostly iommu_quarantine =
# if defined(CONFIG_IOMMU_QUARANTINE_NONE)
    IOMMU_quarantine_none;
# elif defined(CONFIG_IOMMU_QUARANTINE_BASIC)
    IOMMU_quarantine_basic;
# elif defined(CONFIG_IOMMU_QUARANTINE_SCRATCH_PAGE)
    IOMMU_quarantine_scratch_page;
# endif
#else
# define iommu_quarantine IOMMU_quarantine_none
#endif /* CONFIG_HAS_PCI */

static bool __hwdom_initdata iommu_hwdom_none;
bool __hwdom_initdata iommu_hwdom_strict;
bool __read_mostly iommu_hwdom_passthrough;
bool __hwdom_initdata iommu_hwdom_inclusive;
int8_t __hwdom_initdata iommu_hwdom_reserved = -1;

#ifndef iommu_hap_pt_share
bool __read_mostly iommu_hap_pt_share = true;
#endif

bool __read_mostly iommu_debug;

DEFINE_PER_CPU(bool, iommu_dont_flush_iotlb);

static int __init cf_check parse_iommu_param(const char *s)
{
    const char *ss;
    int val, rc = 0;

    do {
        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        if ( (val = parse_bool(s, ss)) >= 0 )
            iommu_enable = val;
        else if ( (val = parse_boolean("force", s, ss)) >= 0 ||
                  (val = parse_boolean("required", s, ss)) >= 0 )
            force_iommu = val;
#ifdef CONFIG_HAS_PCI
        else if ( (val = parse_boolean("quarantine", s, ss)) >= 0 )
            iommu_quarantine = val;
        else if ( ss == s + 23 && !strncmp(s, "quarantine=scratch-page", 23) )
            iommu_quarantine = IOMMU_quarantine_scratch_page;
#endif
        else if ( (val = parse_boolean("igfx", s, ss)) >= 0 )
#ifdef CONFIG_INTEL_IOMMU
            iommu_igfx = val;
#else
            no_config_param("INTEL_IOMMU", "iommu", s, ss);
#endif
        else if ( (val = parse_boolean("qinval", s, ss)) >= 0 )
#ifdef CONFIG_INTEL_IOMMU
            iommu_qinval = val;
#else
            no_config_param("INTEL_IOMMU", "iommu", s, ss);
#endif
#ifdef CONFIG_X86
        else if ( (val = parse_boolean("superpages", s, ss)) >= 0 )
            iommu_superpages = val;
#endif
        else if ( (val = parse_boolean("verbose", s, ss)) >= 0 )
            iommu_verbose = val;
#ifndef iommu_snoop
        else if ( (val = parse_boolean("snoop", s, ss)) >= 0 )
            iommu_snoop = val;
#endif
#ifndef iommu_intremap
        else if ( (val = parse_boolean("intremap", s, ss)) >= 0 )
            iommu_intremap = val ? iommu_intremap_full : iommu_intremap_off;
#endif
#ifndef iommu_intpost
        else if ( (val = parse_boolean("intpost", s, ss)) >= 0 )
            iommu_intpost = val;
#endif
#ifdef CONFIG_KEXEC
        else if ( (val = parse_boolean("crash-disable", s, ss)) >= 0 )
            iommu_crash_disable = val;
#endif
        else if ( (val = parse_boolean("debug", s, ss)) >= 0 )
        {
            iommu_debug = val;
            if ( val )
                iommu_verbose = 1;
        }
        else if ( (val = parse_boolean("amd-iommu-perdev-intremap", s, ss)) >= 0 )
#ifdef CONFIG_AMD_IOMMU
            amd_iommu_perdev_intremap = val;
#else
            no_config_param("AMD_IOMMU", "iommu", s, ss);
#endif
        else if ( (val = parse_boolean("dom0-passthrough", s, ss)) >= 0 )
            iommu_hwdom_passthrough = val;
        else if ( (val = parse_boolean("dom0-strict", s, ss)) >= 0 )
            iommu_hwdom_strict = val;
#ifndef iommu_hap_pt_share
        else if ( (val = parse_boolean("sharept", s, ss)) >= 0 )
            iommu_hap_pt_share = val;
#endif
        else
            rc = -EINVAL;

        s = ss + 1;
    } while ( *ss );

    return rc;
}
custom_param("iommu", parse_iommu_param);

static int __init cf_check parse_dom0_iommu_param(const char *s)
{
    const char *ss;
    int rc = 0;

    do {
        int val;

        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        if ( (val = parse_boolean("passthrough", s, ss)) >= 0 )
            iommu_hwdom_passthrough = val;
        else if ( (val = parse_boolean("strict", s, ss)) >= 0 )
            iommu_hwdom_strict = val;
        else if ( (val = parse_boolean("map-inclusive", s, ss)) >= 0 )
            iommu_hwdom_inclusive = val;
        else if ( (val = parse_boolean("map-reserved", s, ss)) >= 0 )
            iommu_hwdom_reserved = val;
        else if ( !cmdline_strcmp(s, "none") )
            iommu_hwdom_none = true;
        else
            rc = -EINVAL;

        s = ss + 1;
    } while ( *ss );

    return rc;
}
custom_param("dom0-iommu", parse_dom0_iommu_param);

static void __hwdom_init check_hwdom_reqs(struct domain *d)
{
    if ( iommu_hwdom_none || !is_hvm_domain(d) )
        return;

    iommu_hwdom_passthrough = false;
    iommu_hwdom_strict = true;

    arch_iommu_check_autotranslated_hwdom(d);
}

int iommu_domain_init(struct domain *d, unsigned int opts)
{
    struct domain_iommu *hd = dom_iommu(d);
    int ret = 0;

    if ( is_hardware_domain(d) )
        check_hwdom_reqs(d); /* may modify iommu_hwdom_strict */

    if ( !is_iommu_enabled(d) )
        return 0;

#ifdef CONFIG_NUMA
    hd->node = NUMA_NO_NODE;
#endif

    ret = arch_iommu_domain_init(d);
    if ( ret )
        return ret;

    hd->platform_ops = iommu_get_ops();
    ret = iommu_call(hd->platform_ops, init, d);
    if ( ret || is_system_domain(d) )
        return ret;

    /*
     * Use shared page tables for HAP and IOMMU if the global option
     * is enabled (from which we can infer the h/w is capable) and
     * the domain options do not disallow it. HAP must, of course, also
     * be enabled.
     */
    hd->hap_pt_share = hap_enabled(d) && iommu_hap_pt_share &&
        !(opts & XEN_DOMCTL_IOMMU_no_sharept);

    /*
     * NB: 'relaxed' h/w domains don't need the IOMMU mappings to be kept
     *     in-sync with their assigned pages because all host RAM will be
     *     mapped during hwdom_init().
     */
    if ( !is_hardware_domain(d) || iommu_hwdom_strict )
        hd->need_sync = !iommu_use_hap_pt(d);

    ASSERT(!(hd->need_sync && hd->hap_pt_share));

    return 0;
}

static void cf_check iommu_dump_page_tables(unsigned char key)
{
    struct domain *d;

    ASSERT(iommu_enabled);

    rcu_read_lock(&domlist_read_lock);

    for_each_domain(d)
    {
        if ( is_hardware_domain(d) || !is_iommu_enabled(d) )
            continue;

        if ( iommu_use_hap_pt(d) )
        {
            printk("%pd sharing page tables\n", d);
            continue;
        }

        iommu_vcall(dom_iommu(d)->platform_ops, dump_page_tables, d);
    }

    rcu_read_unlock(&domlist_read_lock);
}

void __hwdom_init iommu_hwdom_init(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);

    if ( !is_iommu_enabled(d) )
        return;

    iommu_vcall(hd->platform_ops, hwdom_init, d);
}

static void iommu_teardown(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);

    /*
     * During early domain creation failure, we may reach here with the
     * ops not yet initialized.
     */
    if ( !hd->platform_ops )
        return;

    iommu_vcall(hd->platform_ops, teardown, d);
}

void iommu_domain_destroy(struct domain *d)
{
    if ( !is_iommu_enabled(d) )
        return;

    iommu_teardown(d);

    arch_iommu_domain_destroy(d);
}

static unsigned int mapping_order(const struct domain_iommu *hd,
                                  dfn_t dfn, mfn_t mfn, unsigned long nr)
{
    unsigned long res = dfn_x(dfn) | mfn_x(mfn);
    unsigned long sizes = hd->platform_ops->page_sizes;
    unsigned int bit = ffsl(sizes) - 1, order = 0;

    ASSERT(bit == PAGE_SHIFT);

    while ( (sizes = (sizes >> bit) & ~1) )
    {
        unsigned long mask;

        bit = ffsl(sizes) - 1;
        mask = (1UL << bit) - 1;
        if ( nr <= mask || (res & mask) )
            break;
        order += bit;
        nr >>= bit;
        res >>= bit;
    }

    return order;
}

long iommu_map(struct domain *d, dfn_t dfn0, mfn_t mfn0,
               unsigned long page_count, unsigned int flags,
               unsigned int *flush_flags)
{
    const struct domain_iommu *hd = dom_iommu(d);
    unsigned long i;
    unsigned int order, j = 0;
    int rc = 0;

    if ( !is_iommu_enabled(d) )
        return 0;

    ASSERT(!IOMMUF_order(flags));

    for ( i = 0; i < page_count; i += 1UL << order )
    {
        dfn_t dfn = dfn_add(dfn0, i);
        mfn_t mfn = mfn_add(mfn0, i);

        order = mapping_order(hd, dfn, mfn, page_count - i);

        if ( (flags & IOMMUF_preempt) &&
             ((!(++j & 0xfff) && general_preempt_check()) ||
              i > LONG_MAX - (1UL << order)) )
            return i;

        rc = iommu_call(hd->platform_ops, map_page, d, dfn, mfn,
                        flags | IOMMUF_order(order), flush_flags);

        if ( likely(!rc) )
            continue;

        if ( !d->is_shutting_down && printk_ratelimit() )
            printk(XENLOG_ERR
                   "d%d: IOMMU mapping dfn %"PRI_dfn" to mfn %"PRI_mfn" failed: %d\n",
                   d->domain_id, dfn_x(dfn), mfn_x(mfn), rc);

        /* while statement to satisfy __must_check */
        while ( iommu_unmap(d, dfn0, i, 0, flush_flags) )
            break;

        if ( !is_hardware_domain(d) )
            domain_crash(d);

        break;
    }

    /*
     * Something went wrong so, if we were dealing with more than a single
     * page, flush everything and clear flush flags.
     */
    if ( page_count > 1 && unlikely(rc) &&
         !iommu_iotlb_flush_all(d, *flush_flags) )
        *flush_flags = 0;

    return rc;
}

int iommu_legacy_map(struct domain *d, dfn_t dfn, mfn_t mfn,
                     unsigned long page_count, unsigned int flags)
{
    unsigned int flush_flags = 0;
    int rc;

    ASSERT(!(flags & IOMMUF_preempt));
    rc = iommu_map(d, dfn, mfn, page_count, flags, &flush_flags);

    if ( !this_cpu(iommu_dont_flush_iotlb) && !rc )
        rc = iommu_iotlb_flush(d, dfn, page_count, flush_flags);

    return rc;
}

long iommu_unmap(struct domain *d, dfn_t dfn0, unsigned long page_count,
                 unsigned int flags, unsigned int *flush_flags)
{
    const struct domain_iommu *hd = dom_iommu(d);
    unsigned long i;
    unsigned int order, j = 0;
    int rc = 0;

    if ( !is_iommu_enabled(d) )
        return 0;

    ASSERT(!(flags & ~IOMMUF_preempt));

    for ( i = 0; i < page_count; i += 1UL << order )
    {
        dfn_t dfn = dfn_add(dfn0, i);
        int err;

        order = mapping_order(hd, dfn, _mfn(0), page_count - i);

        if ( (flags & IOMMUF_preempt) &&
             ((!(++j & 0xfff) && general_preempt_check()) ||
              i > LONG_MAX - (1UL << order)) )
            return i;

        err = iommu_call(hd->platform_ops, unmap_page, d, dfn,
                         flags | IOMMUF_order(order), flush_flags);

        if ( likely(!err) )
            continue;

        if ( !d->is_shutting_down && printk_ratelimit() )
            printk(XENLOG_ERR
                   "d%d: IOMMU unmapping dfn %"PRI_dfn" failed: %d\n",
                   d->domain_id, dfn_x(dfn), err);

        if ( !rc )
            rc = err;

        if ( !is_hardware_domain(d) )
        {
            domain_crash(d);
            break;
        }
    }

    /*
     * Something went wrong so, if we were dealing with more than a single
     * page, flush everything and clear flush flags.
     */
    if ( page_count > 1 && unlikely(rc) &&
         !iommu_iotlb_flush_all(d, *flush_flags) )
        *flush_flags = 0;

    return rc;
}

int iommu_legacy_unmap(struct domain *d, dfn_t dfn, unsigned long page_count)
{
    unsigned int flush_flags = 0;
    int rc = iommu_unmap(d, dfn, page_count, 0, &flush_flags);

    if ( !this_cpu(iommu_dont_flush_iotlb) && !rc )
        rc = iommu_iotlb_flush(d, dfn, page_count, flush_flags);

    return rc;
}

int iommu_lookup_page(struct domain *d, dfn_t dfn, mfn_t *mfn,
                      unsigned int *flags)
{
    const struct domain_iommu *hd = dom_iommu(d);

    if ( !is_iommu_enabled(d) || !hd->platform_ops->lookup_page )
        return -EOPNOTSUPP;

    return iommu_call(hd->platform_ops, lookup_page, d, dfn, mfn, flags);
}

int iommu_iotlb_flush(struct domain *d, dfn_t dfn, unsigned long page_count,
                      unsigned int flush_flags)
{
    const struct domain_iommu *hd = dom_iommu(d);
    int rc;

    if ( !is_iommu_enabled(d) || !hd->platform_ops->iotlb_flush ||
         !page_count || !flush_flags )
        return 0;

    if ( dfn_eq(dfn, INVALID_DFN) )
        return -EINVAL;

    rc = iommu_call(hd->platform_ops, iotlb_flush, d, dfn, page_count,
                    flush_flags);
    if ( unlikely(rc) )
    {
        if ( !d->is_shutting_down && printk_ratelimit() )
            printk(XENLOG_ERR
                   "d%d: IOMMU IOTLB flush failed: %d, dfn %"PRI_dfn", page count %lu flags %x\n",
                   d->domain_id, rc, dfn_x(dfn), page_count, flush_flags);

        if ( !is_hardware_domain(d) )
            domain_crash(d);
    }

    return rc;
}

int iommu_iotlb_flush_all(struct domain *d, unsigned int flush_flags)
{
    const struct domain_iommu *hd = dom_iommu(d);
    int rc;

    if ( !is_iommu_enabled(d) || !hd->platform_ops->iotlb_flush ||
         !flush_flags )
        return 0;

    rc = iommu_call(hd->platform_ops, iotlb_flush, d, INVALID_DFN, 0,
                    flush_flags | IOMMU_FLUSHF_all);
    if ( unlikely(rc) )
    {
        if ( !d->is_shutting_down && printk_ratelimit() )
            printk(XENLOG_ERR
                   "d%d: IOMMU IOTLB flush all failed: %d\n",
                   d->domain_id, rc);

        if ( !is_hardware_domain(d) )
            domain_crash(d);
    }

    return rc;
}

int iommu_quarantine_dev_init(device_t *dev)
{
    const struct domain_iommu *hd = dom_iommu(dom_io);

    if ( !iommu_quarantine || !hd->platform_ops->quarantine_init )
        return 0;

    return iommu_call(hd->platform_ops, quarantine_init,
                      dev, iommu_quarantine == IOMMU_quarantine_scratch_page);
}

static int __init iommu_quarantine_init(void)
{
    dom_io->options |= XEN_DOMCTL_CDF_iommu;

    return iommu_domain_init(dom_io, 0);
}

int __init iommu_setup(void)
{
    int rc = -ENODEV;
    bool force_intremap = force_iommu && iommu_intremap;

    if ( iommu_hwdom_strict )
        iommu_hwdom_passthrough = false;

    if ( iommu_enable )
    {
        const struct iommu_ops *ops = NULL;

        rc = iommu_hardware_setup();
        if ( !rc )
            ops = iommu_get_ops();
        if ( ops && (ISOLATE_LSB(ops->page_sizes)) != PAGE_SIZE )
        {
            printk(XENLOG_ERR "IOMMU: page size mask %lx unsupported\n",
                   ops->page_sizes);
            rc = ops->page_sizes ? -EPERM : -ENODATA;
        }
        iommu_enabled = (rc == 0);
    }

#ifndef iommu_intremap
    if ( !iommu_enabled )
        iommu_intremap = iommu_intremap_off;
#endif

    if ( (force_iommu && !iommu_enabled) ||
         (force_intremap && !iommu_intremap) )
        panic("Couldn't enable %s and iommu=required/force\n",
              !iommu_enabled ? "IOMMU" : "Interrupt Remapping");

#ifndef iommu_intpost
    if ( !iommu_intremap )
        iommu_intpost = false;
#endif

    printk("I/O virtualisation %sabled\n", iommu_enabled ? "en" : "dis");
    if ( !iommu_enabled )
    {
        iommu_hwdom_passthrough = false;
        iommu_hwdom_strict = false;
    }
    else
    {
        if ( iommu_quarantine_init() )
            panic("Could not set up quarantine\n");

        printk(" - Dom0 mode: %s\n",
               iommu_hwdom_passthrough ? "Passthrough" :
               iommu_hwdom_strict ? "Strict" : "Relaxed");
#ifndef iommu_intremap
        printk("Interrupt remapping %sabled\n", iommu_intremap ? "en" : "dis");
#endif

        register_keyhandler('o', &iommu_dump_page_tables,
                            "dump iommu page tables", 0);
    }

    return rc;
}

int iommu_suspend(void)
{
    if ( iommu_enabled )
        return iommu_call(iommu_get_ops(), suspend);

    return 0;
}

void iommu_resume(void)
{
    if ( iommu_enabled )
        iommu_vcall(iommu_get_ops(), resume);
}

int iommu_do_domctl(
    struct xen_domctl *domctl, struct domain *d,
    XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl)
{
    int ret = -ENODEV;

    if ( !(d ? is_iommu_enabled(d) : iommu_enabled) )
        return -EOPNOTSUPP;

#ifdef CONFIG_HAS_PCI
    ret = iommu_do_pci_domctl(domctl, d, u_domctl);
#endif

#ifdef CONFIG_HAS_DEVICE_TREE
    if ( ret == -ENODEV )
        ret = iommu_do_dt_domctl(domctl, d, u_domctl);
#endif

    return ret;
}

void iommu_crash_shutdown(void)
{
    if ( !iommu_crash_disable )
        return;

    if ( iommu_enabled )
        iommu_vcall(iommu_get_ops(), crash_shutdown);

    iommu_enabled = false;
#ifndef iommu_intremap
    iommu_intremap = iommu_intremap_off;
#endif
#ifndef iommu_intpost
    iommu_intpost = false;
#endif
}

void iommu_quiesce(void)
{
    const struct iommu_ops *ops;

    if ( !iommu_enabled )
        return;

    ops = iommu_get_ops();
    if ( ops->quiesce )
        iommu_vcall(ops, quiesce);
}

int iommu_get_reserved_device_memory(iommu_grdm_t *func, void *ctxt)
{
    const struct iommu_ops *ops;

    if ( !iommu_enabled )
        return 0;

    ops = iommu_get_ops();
    if ( !ops->get_reserved_device_memory )
        return 0;

    return iommu_call(ops, get_reserved_device_memory, func, ctxt);
}

bool iommu_has_feature(struct domain *d, enum iommu_feature feature)
{
    return is_iommu_enabled(d) && test_bit(feature, dom_iommu(d)->features);
}

#define MAX_EXTRA_RESERVED_RANGES 20
struct extra_reserved_range {
    unsigned long start;
    unsigned long nr;
    pci_sbdf_t sbdf;
    const char *name;
};
static unsigned int __initdata nr_extra_reserved_ranges;
static struct extra_reserved_range __initdata
    extra_reserved_ranges[MAX_EXTRA_RESERVED_RANGES];

int __init iommu_add_extra_reserved_device_memory(unsigned long start,
                                                  unsigned long nr,
                                                  pci_sbdf_t sbdf,
                                                  const char *name)
{
    unsigned int idx;

    if ( nr_extra_reserved_ranges >= MAX_EXTRA_RESERVED_RANGES )
        return -ENOMEM;

    idx = nr_extra_reserved_ranges++;
    extra_reserved_ranges[idx].start = start;
    extra_reserved_ranges[idx].nr = nr;
    extra_reserved_ranges[idx].sbdf = sbdf;
    extra_reserved_ranges[idx].name = name;

    return 0;
}

int __init iommu_get_extra_reserved_device_memory(iommu_grdm_t *func,
                                                  void *ctxt)
{
    unsigned int idx;
    int ret;

    for ( idx = 0; idx < nr_extra_reserved_ranges; idx++ )
    {
#ifdef CONFIG_X86
        paddr_t start = pfn_to_paddr(extra_reserved_ranges[idx].start);
        paddr_t end = pfn_to_paddr(extra_reserved_ranges[idx].start +
                                   extra_reserved_ranges[idx].nr);

        if ( !reserve_e820_ram(&e820, start, end) )
        {
            printk(XENLOG_ERR "Failed to reserve [%"PRIx64"-%"PRIx64") for %s, "
                   "skipping IOMMU mapping for it, some functionality may be broken\n",
                   start, end, extra_reserved_ranges[idx].name);
            continue;
        }
#endif
        ret = func(extra_reserved_ranges[idx].start,
                   extra_reserved_ranges[idx].nr,
                   extra_reserved_ranges[idx].sbdf.sbdf,
                   ctxt);
        if ( ret < 0 )
            return ret;
    }

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
