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
#include <xen/softirq.h>
#include <xen/keyhandler.h>
#include <xsm/xsm.h>

static void iommu_dump_p2m_table(unsigned char key);

unsigned int __read_mostly iommu_dev_iotlb_timeout = 1000;
integer_param("iommu_dev_iotlb_timeout", iommu_dev_iotlb_timeout);

bool_t __initdata iommu_enable = 1;
bool_t __read_mostly iommu_enabled;
bool_t __read_mostly force_iommu;
bool_t __read_mostly iommu_verbose;
bool __read_mostly iommu_quarantine = true;
bool_t __read_mostly iommu_igfx = 1;
bool_t __read_mostly iommu_snoop = 1;
bool_t __read_mostly iommu_qinval = 1;
bool_t __read_mostly iommu_intremap = 1;
bool_t __read_mostly iommu_crash_disable;

static bool __hwdom_initdata iommu_hwdom_none;
bool __hwdom_initdata iommu_hwdom_strict;
bool __read_mostly iommu_hwdom_passthrough;
bool __hwdom_initdata iommu_hwdom_inclusive;
int8_t __hwdom_initdata iommu_hwdom_reserved = -1;

/*
 * In the current implementation of VT-d posted interrupts, in some extreme
 * cases, the per cpu list which saves the blocked vCPU will be very long,
 * and this will affect the interrupt latency, so let this feature off by
 * default until we find a good solution to resolve it.
 */
bool_t __read_mostly iommu_intpost;

#ifndef iommu_hap_pt_share
bool __read_mostly iommu_hap_pt_share = true;
#endif

bool_t __read_mostly iommu_debug;
bool_t __read_mostly amd_iommu_perdev_intremap = 1;

DEFINE_PER_CPU(bool_t, iommu_dont_flush_iotlb);

DEFINE_SPINLOCK(iommu_pt_cleanup_lock);
PAGE_LIST_HEAD(iommu_pt_cleanup_list);
static struct tasklet iommu_pt_cleanup_tasklet;

static int __init parse_iommu_param(const char *s)
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
        else if ( (val = parse_boolean("quarantine", s, ss)) >= 0 )
            iommu_quarantine = val;
        else if ( (val = parse_boolean("igfx", s, ss)) >= 0 )
            iommu_igfx = val;
        else if ( (val = parse_boolean("verbose", s, ss)) >= 0 )
            iommu_verbose = val;
        else if ( (val = parse_boolean("snoop", s, ss)) >= 0 )
            iommu_snoop = val;
        else if ( (val = parse_boolean("qinval", s, ss)) >= 0 )
            iommu_qinval = val;
        else if ( (val = parse_boolean("intremap", s, ss)) >= 0 )
            iommu_intremap = val;
        else if ( (val = parse_boolean("intpost", s, ss)) >= 0 )
            iommu_intpost = val;
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
            amd_iommu_perdev_intremap = val;
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

static int __init parse_dom0_iommu_param(const char *s)
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

    if ( !is_iommu_enabled(d) )
        return 0;

#ifdef CONFIG_NUMA
    hd->node = NUMA_NO_NODE;
#endif

    ret = arch_iommu_domain_init(d);
    if ( ret )
        return ret;

    hd->platform_ops = iommu_get_ops();
    ret = hd->platform_ops->init(d);
    if ( ret || is_system_domain(d) )
        return ret;

    if ( is_hardware_domain(d) )
        check_hwdom_reqs(d); /* may modify iommu_hwdom_strict */

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

void __hwdom_init iommu_hwdom_init(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);

    if ( !is_iommu_enabled(d) )
        return;

    register_keyhandler('o', &iommu_dump_p2m_table, "dump iommu p2m table", 0);

    hd->platform_ops->hwdom_init(d);
}

static void iommu_teardown(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);

    hd->platform_ops->teardown(d);
    tasklet_schedule(&iommu_pt_cleanup_tasklet);
}

void iommu_domain_destroy(struct domain *d)
{
    if ( !is_iommu_enabled(d) )
        return;

    iommu_teardown(d);

    arch_iommu_domain_destroy(d);
}

int iommu_map(struct domain *d, dfn_t dfn, mfn_t mfn,
              unsigned int page_order, unsigned int flags,
              unsigned int *flush_flags)
{
    const struct domain_iommu *hd = dom_iommu(d);
    unsigned long i;
    int rc = 0;

    if ( !is_iommu_enabled(d) )
        return 0;

    ASSERT(IS_ALIGNED(dfn_x(dfn), (1ul << page_order)));
    ASSERT(IS_ALIGNED(mfn_x(mfn), (1ul << page_order)));

    for ( i = 0; i < (1ul << page_order); i++ )
    {
        rc = iommu_call(hd->platform_ops, map_page, d, dfn_add(dfn, i),
                        mfn_add(mfn, i), flags, flush_flags);

        if ( likely(!rc) )
            continue;

        if ( !d->is_shutting_down && printk_ratelimit() )
            printk(XENLOG_ERR
                   "d%d: IOMMU mapping dfn %"PRI_dfn" to mfn %"PRI_mfn" failed: %d\n",
                   d->domain_id, dfn_x(dfn_add(dfn, i)),
                   mfn_x(mfn_add(mfn, i)), rc);

        while ( i-- )
            /* if statement to satisfy __must_check */
            if ( iommu_call(hd->platform_ops, unmap_page, d, dfn_add(dfn, i),
                            flush_flags) )
                continue;

        if ( !is_hardware_domain(d) )
            domain_crash(d);

        break;
    }

    return rc;
}

int iommu_legacy_map(struct domain *d, dfn_t dfn, mfn_t mfn,
                     unsigned int page_order, unsigned int flags)
{
    unsigned int flush_flags = 0;
    int rc = iommu_map(d, dfn, mfn, page_order, flags, &flush_flags);

    if ( !this_cpu(iommu_dont_flush_iotlb) )
    {
        int err = iommu_iotlb_flush(d, dfn, (1u << page_order),
                                    flush_flags);

        if ( !rc )
            rc = err;
    }

    return rc;
}

int iommu_unmap(struct domain *d, dfn_t dfn, unsigned int page_order,
                unsigned int *flush_flags)
{
    const struct domain_iommu *hd = dom_iommu(d);
    unsigned long i;
    int rc = 0;

    if ( !is_iommu_enabled(d) )
        return 0;

    ASSERT(IS_ALIGNED(dfn_x(dfn), (1ul << page_order)));

    for ( i = 0; i < (1ul << page_order); i++ )
    {
        int err = iommu_call(hd->platform_ops, unmap_page, d, dfn_add(dfn, i),
                             flush_flags);

        if ( likely(!err) )
            continue;

        if ( !d->is_shutting_down && printk_ratelimit() )
            printk(XENLOG_ERR
                   "d%d: IOMMU unmapping dfn %"PRI_dfn" failed: %d\n",
                   d->domain_id, dfn_x(dfn_add(dfn, i)), err);

        if ( !rc )
            rc = err;

        if ( !is_hardware_domain(d) )
        {
            domain_crash(d);
            break;
        }
    }

    return rc;
}

int iommu_legacy_unmap(struct domain *d, dfn_t dfn, unsigned int page_order)
{
    unsigned int flush_flags = 0;
    int rc = iommu_unmap(d, dfn, page_order, &flush_flags);

    if ( !this_cpu(iommu_dont_flush_iotlb) )
    {
        int err = iommu_iotlb_flush(d, dfn, (1u << page_order),
                                    flush_flags);

        if ( !rc )
            rc = err;
    }

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

static void iommu_free_pagetables(void *unused)
{
    do {
        struct page_info *pg;

        spin_lock(&iommu_pt_cleanup_lock);
        pg = page_list_remove_head(&iommu_pt_cleanup_list);
        spin_unlock(&iommu_pt_cleanup_lock);
        if ( !pg )
            return;
        iommu_vcall(iommu_get_ops(), free_page_table, pg);
    } while ( !softirq_pending(smp_processor_id()) );

    tasklet_schedule_on_cpu(&iommu_pt_cleanup_tasklet,
                            cpumask_cycle(smp_processor_id(), &cpu_online_map));
}

int iommu_iotlb_flush(struct domain *d, dfn_t dfn, unsigned int page_count,
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
                   "d%d: IOMMU IOTLB flush failed: %d, dfn %"PRI_dfn", page count %u flags %x\n",
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

    if ( !is_iommu_enabled(d) || !hd->platform_ops->iotlb_flush_all ||
         !flush_flags )
        return 0;

    /*
     * The operation does a full flush so we don't need to pass the
     * flush_flags in.
     */
    rc = iommu_call(hd->platform_ops, iotlb_flush_all, d);
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

static int __init iommu_quarantine_init(void)
{
    const struct domain_iommu *hd = dom_iommu(dom_io);
    int rc;

    dom_io->options |= XEN_DOMCTL_CDF_iommu;

    rc = iommu_domain_init(dom_io, 0);
    if ( rc )
        return rc;

    if ( !hd->platform_ops->quarantine_init )
        return 0;

    return hd->platform_ops->quarantine_init(dom_io);
}

int __init iommu_setup(void)
{
    int rc = -ENODEV;
    bool_t force_intremap = force_iommu && iommu_intremap;

    if ( iommu_hwdom_strict )
        iommu_hwdom_passthrough = false;

    if ( iommu_enable )
    {
        rc = iommu_hardware_setup();
        iommu_enabled = (rc == 0);
    }
    if ( !iommu_enabled )
        iommu_intremap = 0;

    if ( (force_iommu && !iommu_enabled) ||
         (force_intremap && !iommu_intremap) )
        panic("Couldn't enable %s and iommu=required/force\n",
              !iommu_enabled ? "IOMMU" : "Interrupt Remapping");

    if ( !iommu_intremap )
        iommu_intpost = 0;

    printk("I/O virtualisation %sabled\n", iommu_enabled ? "en" : "dis");
    if ( !iommu_enabled )
    {
        iommu_snoop = 0;
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
        printk("Interrupt remapping %sabled\n", iommu_intremap ? "en" : "dis");
        tasklet_init(&iommu_pt_cleanup_tasklet, iommu_free_pagetables, NULL);
    }

    return rc;
}

int iommu_suspend()
{
    if ( iommu_enabled )
        return iommu_get_ops()->suspend();

    return 0;
}

void iommu_resume()
{
    if ( iommu_enabled )
        iommu_get_ops()->resume();
}

int iommu_do_domctl(
    struct xen_domctl *domctl, struct domain *d,
    XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl)
{
    int ret = -ENODEV;

    if ( !is_iommu_enabled(d) )
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

void iommu_share_p2m_table(struct domain* d)
{
    ASSERT(hap_enabled(d));

    if ( iommu_use_hap_pt(d) )
        iommu_get_ops()->share_p2m(d);
}

void iommu_crash_shutdown(void)
{
    if ( !iommu_crash_disable )
        return;

    if ( iommu_enabled )
        iommu_get_ops()->crash_shutdown();
    iommu_enabled = iommu_intremap = iommu_intpost = 0;
}

int iommu_get_reserved_device_memory(iommu_grdm_t *func, void *ctxt)
{
    const struct iommu_ops *ops;

    if ( !iommu_enabled )
        return 0;

    ops = iommu_get_ops();
    if ( !ops->get_reserved_device_memory )
        return 0;

    return ops->get_reserved_device_memory(func, ctxt);
}

bool_t iommu_has_feature(struct domain *d, enum iommu_feature feature)
{
    return is_iommu_enabled(d) && test_bit(feature, dom_iommu(d)->features);
}

static void iommu_dump_p2m_table(unsigned char key)
{
    struct domain *d;
    const struct iommu_ops *ops;

    if ( !iommu_enabled )
    {
        printk("IOMMU not enabled!\n");
        return;
    }

    ops = iommu_get_ops();
    for_each_domain(d)
    {
        if ( is_hardware_domain(d) || !is_iommu_enabled(d) )
            continue;

        if ( iommu_use_hap_pt(d) )
        {
            printk("\ndomain%d IOMMU p2m table shared with MMU: \n", d->domain_id);
            continue;
        }

        printk("\ndomain%d IOMMU p2m table: \n", d->domain_id);
        ops->dump_p2m_table(d);
    }
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
