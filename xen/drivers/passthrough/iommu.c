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

static void parse_iommu_param(char *s);
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
bool_t __hwdom_initdata iommu_dom0_strict;
bool_t __read_mostly iommu_verbose;
bool_t __read_mostly iommu_workaround_bios_bug;
bool_t __read_mostly iommu_igfx = 1;
bool_t __read_mostly iommu_passthrough;
bool_t __read_mostly iommu_snoop = 1;
bool_t __read_mostly iommu_qinval = 1;
bool_t __read_mostly iommu_intremap = 1;

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

static void __init parse_iommu_param(char *s)
{
    char *ss;
    int val;

    do {
        val = !!strncmp(s, "no-", 3);
        if ( !val )
            s += 3;

        ss = strchr(s, ',');
        if ( ss )
            *ss = '\0';

        if ( !parse_bool(s) )
            iommu_enable = 0;
        else if ( !strcmp(s, "force") || !strcmp(s, "required") )
            force_iommu = val;
        else if ( !strcmp(s, "workaround_bios_bug") )
            iommu_workaround_bios_bug = val;
        else if ( !strcmp(s, "igfx") )
            iommu_igfx = val;
        else if ( !strcmp(s, "verbose") )
            iommu_verbose = val;
        else if ( !strcmp(s, "snoop") )
            iommu_snoop = val;
        else if ( !strcmp(s, "qinval") )
            iommu_qinval = val;
        else if ( !strcmp(s, "intremap") )
            iommu_intremap = val;
        else if ( !strcmp(s, "intpost") )
            iommu_intpost = val;
        else if ( !strcmp(s, "debug") )
        {
            iommu_debug = val;
            if ( val )
                iommu_verbose = 1;
        }
        else if ( !strcmp(s, "amd-iommu-perdev-intremap") )
            amd_iommu_perdev_intremap = val;
        else if ( !strcmp(s, "dom0-passthrough") )
            iommu_passthrough = val;
        else if ( !strcmp(s, "dom0-strict") )
            iommu_dom0_strict = val;
        else if ( !strcmp(s, "sharept") )
            iommu_hap_pt_share = val;

        s = ss + 1;
    } while ( ss );
}

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

    if ( iommu_passthrough )
        panic("Dom0 uses paging translated mode, dom0-passthrough must not be "
              "enabled\n");

    iommu_dom0_strict = 1;
}

void __hwdom_init iommu_hwdom_init(struct domain *d)
{
    const struct domain_iommu *hd = dom_iommu(d);

    check_hwdom_reqs(d);

    if ( !iommu_enabled )
        return;

    register_keyhandler('o', &iommu_dump_p2m_table, "dump iommu p2m table", 0);
    d->need_iommu = !!iommu_dom0_strict;
    if ( need_iommu(d) && !iommu_use_hap_pt(d) )
    {
        struct page_info *page;
        unsigned int i = 0;
        int rc = 0;

        page_list_for_each ( page, &d->page_list )
        {
            unsigned long mfn = page_to_mfn(page);
            unsigned long gfn = mfn_to_gmfn(d, mfn);
            unsigned int mapping = IOMMUF_readable;
            int ret;

            if ( ((page->u.inuse.type_info & PGT_count_mask) == 0) ||
                 ((page->u.inuse.type_info & PGT_type_mask)
                  == PGT_writable_page) )
                mapping |= IOMMUF_writable;

            ret = hd->platform_ops->map_page(d, gfn, mfn, mapping);
            if ( !rc )
                rc = ret;

            if ( !(i++ & 0xfffff) )
                process_pending_softirqs();
        }

        if ( rc )
            printk(XENLOG_WARNING "d%d: IOMMU mapping failed: %d\n",
                   d->domain_id, rc);
    }

    return hd->platform_ops->hwdom_init(d);
}

void iommu_teardown(struct domain *d)
{
    const struct domain_iommu *hd = dom_iommu(d);

    d->need_iommu = 0;
    hd->platform_ops->teardown(d);
    tasklet_schedule(&iommu_pt_cleanup_tasklet);
}

int iommu_construct(struct domain *d)
{
    if ( need_iommu(d) > 0 )
        return 0;

    if ( !iommu_use_hap_pt(d) )
    {
        int rc;

        rc = arch_iommu_populate_page_table(d);
        if ( rc )
            return rc;
    }

    d->need_iommu = 1;
    /*
     * There may be dirty cache lines when a device is assigned
     * and before need_iommu(d) becoming true, this will cause
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

int iommu_map_page(struct domain *d, unsigned long gfn, unsigned long mfn,
                   unsigned int flags)
{
    const struct domain_iommu *hd = dom_iommu(d);
    int rc;

    if ( !iommu_enabled || !hd->platform_ops )
        return 0;

    rc = hd->platform_ops->map_page(d, gfn, mfn, flags);
    if ( unlikely(rc) )
    {
        if ( !d->is_shutting_down && printk_ratelimit() )
            printk(XENLOG_ERR
                   "d%d: IOMMU mapping gfn %#lx to mfn %#lx failed: %d\n",
                   d->domain_id, gfn, mfn, rc);

        if ( !is_hardware_domain(d) )
            domain_crash(d);
    }

    return rc;
}

int iommu_unmap_page(struct domain *d, unsigned long gfn)
{
    const struct domain_iommu *hd = dom_iommu(d);
    int rc;

    if ( !iommu_enabled || !hd->platform_ops )
        return 0;

    rc = hd->platform_ops->unmap_page(d, gfn);
    if ( unlikely(rc) )
    {
        if ( !d->is_shutting_down && printk_ratelimit() )
            printk(XENLOG_ERR
                   "d%d: IOMMU unmapping gfn %#lx failed: %d\n",
                   d->domain_id, gfn, rc);

        if ( !is_hardware_domain(d) )
            domain_crash(d);
    }

    return rc;
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

int iommu_iotlb_flush(struct domain *d, unsigned long gfn,
                      unsigned int page_count)
{
    const struct domain_iommu *hd = dom_iommu(d);
    int rc;

    if ( !iommu_enabled || !hd->platform_ops || !hd->platform_ops->iotlb_flush )
        return 0;

    rc = hd->platform_ops->iotlb_flush(d, gfn, page_count);
    if ( unlikely(rc) )
    {
        if ( !d->is_shutting_down && printk_ratelimit() )
            printk(XENLOG_ERR
                   "d%d: IOMMU IOTLB flush failed: %d, gfn %#lx, page count %u\n",
                   d->domain_id, rc, gfn, page_count);

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

    if ( iommu_dom0_strict )
        iommu_passthrough = 0;

    if ( iommu_enable )
    {
        rc = iommu_hardware_setup();
        iommu_enabled = (rc == 0);
    }
    if ( !iommu_enabled )
        iommu_intremap = 0;

    if ( (force_iommu && !iommu_enabled) ||
         (force_intremap && !iommu_intremap) )
        panic("Couldn't enable %s and iommu=required/force",
              !iommu_enabled ? "IOMMU" : "Interrupt Remapping");

    if ( !iommu_intremap )
        iommu_intpost = 0;

    if ( !iommu_enabled )
    {
        iommu_snoop = 0;
        iommu_passthrough = 0;
        iommu_dom0_strict = 0;
    }
    printk("I/O virtualisation %sabled\n", iommu_enabled ? "en" : "dis");
    if ( iommu_enabled )
    {
        printk(" - Dom0 mode: %s\n",
               iommu_passthrough ? "Passthrough" :
               iommu_dom0_strict ? "Strict" : "Relaxed");
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
    if ( iommu_enabled && iommu_use_hap_pt(d) )
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
        if ( is_hardware_domain(d) || need_iommu(d) <= 0 )
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
