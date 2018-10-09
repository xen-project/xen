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

static int parse_iommu_param(const char *s);
static void iommu_dump_p2m_table(unsigned char key);

unsigned int __read_mostly iommu_dev_iotlb_timeout = 1000;
integer_param("iommu_dev_iotlb_timeout", iommu_dev_iotlb_timeout);

/*
 * The 'iommu' parameter enables the IOMMU.  Optional comma separated
 * value may contain:
 *
 *   off|no|false|disable       Disable IOMMU (default)
 *   force|required             Don't boot unless IOMMU is enabled
 *   no-intremap                Disable interrupt remapping
 *   intpost                    Enable VT-d Interrupt posting
 *   verbose                    Be more verbose
 *   debug                      Enable debugging messages and checks
 *   workaround_bios_bug        Workaround some bios issue to still enable
 *                              VT-d, don't guarantee security
 *   dom0-passthrough           No DMA translation at all for Dom0
 *   dom0-strict                No 1:1 memory mapping for Dom0
 *   no-sharept                 Don't share VT-d and EPT page tables
 *   no-snoop                   Disable VT-d Snoop Control
 *   no-qinval                  Disable VT-d Queued Invalidation
 *   no-igfx                    Disable VT-d for IGD devices (insecure)
 *   no-amd-iommu-perdev-intremap Don't use per-device interrupt remapping
 *                              tables (insecure)
 */
custom_param("iommu", parse_iommu_param);
bool_t __initdata iommu_enable = 1;
bool_t __read_mostly iommu_enabled;
bool_t __read_mostly force_iommu;
bool_t __read_mostly iommu_verbose;
bool_t __read_mostly iommu_workaround_bios_bug;
bool_t __read_mostly iommu_igfx = 1;
bool_t __read_mostly iommu_snoop = 1;
bool_t __read_mostly iommu_qinval = 1;
bool_t __read_mostly iommu_intremap = 1;

bool __hwdom_initdata iommu_hwdom_strict;
bool __read_mostly iommu_hwdom_passthrough;
int8_t __hwdom_initdata iommu_hwdom_inclusive = -1;
int8_t __hwdom_initdata iommu_hwdom_reserved = -1;

/*
 * In the current implementation of VT-d posted interrupts, in some extreme
 * cases, the per cpu list which saves the blocked vCPU will be very long,
 * and this will affect the interrupt latency, so let this feature off by
 * default until we find a good solution to resolve it.
 */
bool_t __read_mostly iommu_intpost;
bool_t __read_mostly iommu_hap_pt_share = 1;
bool_t __read_mostly iommu_debug;
bool_t __read_mostly amd_iommu_perdev_intremap = 1;

DEFINE_PER_CPU(bool_t, iommu_dont_flush_iotlb);

DEFINE_SPINLOCK(iommu_pt_cleanup_lock);
PAGE_LIST_HEAD(iommu_pt_cleanup_list);
static struct tasklet iommu_pt_cleanup_tasklet;

static int __init parse_iommu_param(const char *s)
{
    const char *ss;
    int val, b, rc = 0;

    do {
        val = !!strncmp(s, "no-", 3);
        if ( !val )
            s += 3;

        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        b = parse_bool(s, ss);
        if ( b >= 0 )
            iommu_enable = b;
        else if ( !strncmp(s, "force", ss - s) ||
                  !strncmp(s, "required", ss - s) )
            force_iommu = val;
        else if ( !strncmp(s, "workaround_bios_bug", ss - s) )
            iommu_workaround_bios_bug = val;
        else if ( !strncmp(s, "igfx", ss - s) )
            iommu_igfx = val;
        else if ( !strncmp(s, "verbose", ss - s) )
            iommu_verbose = val;
        else if ( !strncmp(s, "snoop", ss - s) )
            iommu_snoop = val;
        else if ( !strncmp(s, "qinval", ss - s) )
            iommu_qinval = val;
        else if ( !strncmp(s, "intremap", ss - s) )
            iommu_intremap = val;
        else if ( !strncmp(s, "intpost", ss - s) )
            iommu_intpost = val;
        else if ( !strncmp(s, "debug", ss - s) )
        {
            iommu_debug = val;
            if ( val )
                iommu_verbose = 1;
        }
        else if ( !strncmp(s, "amd-iommu-perdev-intremap", ss - s) )
            amd_iommu_perdev_intremap = val;
        else if ( !strncmp(s, "dom0-passthrough", ss - s) )
            iommu_hwdom_passthrough = val;
        else if ( !strncmp(s, "dom0-strict", ss - s) )
            iommu_hwdom_strict = val;
        else if ( !strncmp(s, "sharept", ss - s) )
            iommu_hap_pt_share = val;
        else
            rc = -EINVAL;

        s = ss + 1;
    } while ( *ss );

    return rc;
}

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
        else
            rc = -EINVAL;

        s = ss + 1;
    } while ( *ss );

    return rc;
}
custom_param("dom0-iommu", parse_dom0_iommu_param);

int iommu_domain_init(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);
    int ret = 0;

    ret = arch_iommu_domain_init(d);
    if ( ret )
        return ret;

    if ( !iommu_enabled )
        return 0;

    hd->platform_ops = iommu_get_ops();
    return hd->platform_ops->init(d);
}

static void __hwdom_init check_hwdom_reqs(struct domain *d)
{
    if ( !paging_mode_translate(d) )
        return;

    arch_iommu_check_autotranslated_hwdom(d);

    iommu_hwdom_passthrough = false;
    iommu_hwdom_strict = true;
}

void __hwdom_init iommu_hwdom_init(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);

    check_hwdom_reqs(d);

    if ( !iommu_enabled )
        return;

    register_keyhandler('o', &iommu_dump_p2m_table, "dump iommu p2m table", 0);

    hd->status = IOMMU_STATUS_initializing;
    hd->need_sync = iommu_hwdom_strict && !iommu_use_hap_pt(d);
    if ( need_iommu_pt_sync(d) )
    {
        struct page_info *page;
        unsigned int i = 0;
        int rc = 0;

        page_list_for_each ( page, &d->page_list )
        {
            unsigned long mfn = mfn_x(page_to_mfn(page));
            unsigned long dfn = mfn_to_gmfn(d, mfn);
            unsigned int mapping = IOMMUF_readable;
            int ret;

            if ( ((page->u.inuse.type_info & PGT_count_mask) == 0) ||
                 ((page->u.inuse.type_info & PGT_type_mask)
                  == PGT_writable_page) )
                mapping |= IOMMUF_writable;

            ret = hd->platform_ops->map_page(d, _dfn(dfn), _mfn(mfn),
                                             mapping);
            if ( !rc )
                rc = ret;

            if ( !(i++ & 0xfffff) )
                process_pending_softirqs();
        }

        if ( rc )
            printk(XENLOG_WARNING "d%d: IOMMU mapping failed: %d\n",
                   d->domain_id, rc);
    }

    hd->platform_ops->hwdom_init(d);

    hd->status = IOMMU_STATUS_initialized;
}

void iommu_teardown(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);

    hd->status = IOMMU_STATUS_disabled;
    hd->platform_ops->teardown(d);
    tasklet_schedule(&iommu_pt_cleanup_tasklet);
}

int iommu_construct(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);

    if ( hd->status == IOMMU_STATUS_initialized )
        return 0;

    if ( !iommu_use_hap_pt(d) )
    {
        int rc;

        hd->status = IOMMU_STATUS_initializing;
        hd->need_sync = true;

        rc = arch_iommu_populate_page_table(d);
        if ( rc )
        {
            if ( rc != -ERESTART )
            {
                hd->need_sync = false;
                hd->status = IOMMU_STATUS_disabled;
            }

            return rc;
        }
    }

    hd->status = IOMMU_STATUS_initialized;

    /*
     * There may be dirty cache lines when a device is assigned
     * and before has_iommu_pt(d) becoming true, this will cause
     * memory_type_changed lose effect if memory type changes.
     * Call memory_type_changed here to amend this.
     */
    memory_type_changed(d);

    return 0;
}

void iommu_domain_destroy(struct domain *d)
{
    if ( !iommu_enabled || !dom_iommu(d)->platform_ops )
        return;

    iommu_teardown(d);

    arch_iommu_domain_destroy(d);
}

int iommu_map_page(struct domain *d, dfn_t dfn, mfn_t mfn,
                   unsigned int flags)
{
    const struct domain_iommu *hd = dom_iommu(d);
    int rc;

    if ( !iommu_enabled || !hd->platform_ops )
        return 0;

    rc = hd->platform_ops->map_page(d, dfn, mfn, flags);
    if ( unlikely(rc) )
    {
        if ( !d->is_shutting_down && printk_ratelimit() )
            printk(XENLOG_ERR
                   "d%d: IOMMU mapping dfn %"PRI_dfn" to mfn %"PRI_mfn" failed: %d\n",
                   d->domain_id, dfn_x(dfn), mfn_x(mfn), rc);

        if ( !is_hardware_domain(d) )
            domain_crash(d);
    }

    return rc;
}

int iommu_unmap_page(struct domain *d, dfn_t dfn)
{
    const struct domain_iommu *hd = dom_iommu(d);
    int rc;

    if ( !iommu_enabled || !hd->platform_ops )
        return 0;

    rc = hd->platform_ops->unmap_page(d, dfn);
    if ( unlikely(rc) )
    {
        if ( !d->is_shutting_down && printk_ratelimit() )
            printk(XENLOG_ERR
                   "d%d: IOMMU unmapping dfn %"PRI_dfn" failed: %d\n",
                   d->domain_id, dfn_x(dfn), rc);

        if ( !is_hardware_domain(d) )
            domain_crash(d);
    }

    return rc;
}

int iommu_lookup_page(struct domain *d, dfn_t dfn, mfn_t *mfn,
                      unsigned int *flags)
{
    const struct domain_iommu *hd = dom_iommu(d);

    if ( !iommu_enabled || !hd->platform_ops )
        return -EOPNOTSUPP;

    return hd->platform_ops->lookup_page(d, dfn, mfn, flags);
}

static void iommu_free_pagetables(unsigned long unused)
{
    do {
        struct page_info *pg;

        spin_lock(&iommu_pt_cleanup_lock);
        pg = page_list_remove_head(&iommu_pt_cleanup_list);
        spin_unlock(&iommu_pt_cleanup_lock);
        if ( !pg )
            return;
        iommu_get_ops()->free_page_table(pg);
    } while ( !softirq_pending(smp_processor_id()) );

    tasklet_schedule_on_cpu(&iommu_pt_cleanup_tasklet,
                            cpumask_cycle(smp_processor_id(), &cpu_online_map));
}

int iommu_iotlb_flush(struct domain *d, dfn_t dfn, unsigned int page_count)
{
    const struct domain_iommu *hd = dom_iommu(d);
    int rc;

    if ( !iommu_enabled || !hd->platform_ops || !hd->platform_ops->iotlb_flush )
        return 0;

    rc = hd->platform_ops->iotlb_flush(d, dfn, page_count);
    if ( unlikely(rc) )
    {
        if ( !d->is_shutting_down && printk_ratelimit() )
            printk(XENLOG_ERR
                   "d%d: IOMMU IOTLB flush failed: %d, dfn %"PRI_dfn", page count %u\n",
                   d->domain_id, rc, dfn_x(dfn), page_count);

        if ( !is_hardware_domain(d) )
            domain_crash(d);
    }

    return rc;
}

int iommu_iotlb_flush_all(struct domain *d)
{
    const struct domain_iommu *hd = dom_iommu(d);
    int rc;

    if ( !iommu_enabled || !hd->platform_ops || !hd->platform_ops->iotlb_flush_all )
        return 0;

    rc = hd->platform_ops->iotlb_flush_all(d);
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

    if ( !iommu_enabled )
    {
        iommu_snoop = 0;
        iommu_hwdom_passthrough = false;
        iommu_hwdom_strict = false;
    }
    printk("I/O virtualisation %sabled\n", iommu_enabled ? "en" : "dis");
    if ( iommu_enabled )
    {
        printk(" - Dom0 mode: %s\n",
               iommu_hwdom_passthrough ? "Passthrough" :
               iommu_hwdom_strict ? "Strict" : "Relaxed");
        printk("Interrupt remapping %sabled\n", iommu_intremap ? "en" : "dis");
        tasklet_init(&iommu_pt_cleanup_tasklet, iommu_free_pagetables, 0);
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

    if ( !iommu_enabled )
        return -ENOSYS;

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
#ifdef CONFIG_X86
    ASSERT(hap_enabled(d));
#endif
    /*
     * iommu_use_hap_pt(d) cannot be used here because during domain
     * construction need_iommu(d) will always return false here.
     */
    if ( iommu_enabled && iommu_hap_pt_share )
        iommu_get_ops()->share_p2m(d);
}

void iommu_crash_shutdown(void)
{
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
    if ( !iommu_enabled )
        return 0;

    return test_bit(feature, dom_iommu(d)->features);
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
        if ( is_hardware_domain(d) ||
             dom_iommu(d)->status < IOMMU_STATUS_initialized )
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
