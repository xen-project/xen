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
#include <xsm/xsm.h>

#include <asm/hvm/io.h>
#include <asm/setup.h>

const struct iommu_init_ops *__initdata iommu_init_ops;
struct iommu_ops __read_mostly iommu_ops;

int __init iommu_hardware_setup(void)
{
    int rc;

    if ( !iommu_init_ops )
        return -ENODEV;

    rc = scan_pci_devices();
    if ( rc )
        return rc;

    if ( !iommu_ops.init )
        iommu_ops = *iommu_init_ops->ops;
    else
        /* x2apic setup may have previously initialised the struct. */
        ASSERT(iommu_ops.init == iommu_init_ops->ops->init);

    return iommu_init_ops->setup();
}

int iommu_enable_x2apic(void)
{
    if ( system_state < SYS_STATE_active )
    {
        if ( !iommu_supports_x2apic() )
            return -EOPNOTSUPP;

        iommu_ops = *iommu_init_ops->ops;
    }
    else if ( !x2apic_enabled )
        return -EOPNOTSUPP;

    if ( !iommu_ops.enable_x2apic )
        return -EOPNOTSUPP;

    return iommu_ops.enable_x2apic();
}

void iommu_update_ire_from_apic(
    unsigned int apic, unsigned int reg, unsigned int value)
{
    iommu_vcall(&iommu_ops, update_ire_from_apic, apic, reg, value);
}

unsigned int iommu_read_apic_from_ire(unsigned int apic, unsigned int reg)
{
    return iommu_call(&iommu_ops, read_apic_from_ire, apic, reg);
}

int __init iommu_setup_hpet_msi(struct msi_desc *msi)
{
    const struct iommu_ops *ops = iommu_get_ops();
    return ops->setup_hpet_msi ? ops->setup_hpet_msi(msi) : -ENODEV;
}

void __hwdom_init arch_iommu_check_autotranslated_hwdom(struct domain *d)
{
    if ( !is_iommu_enabled(d) )
        panic("Presently, iommu must be enabled for PVH hardware domain\n");
}

int arch_iommu_domain_init(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);

    spin_lock_init(&hd->arch.mapping_lock);
    INIT_LIST_HEAD(&hd->arch.mapped_rmrrs);

    return 0;
}

void arch_iommu_domain_destroy(struct domain *d)
{
}

static bool __hwdom_init hwdom_iommu_map(const struct domain *d,
                                         unsigned long pfn,
                                         unsigned long max_pfn)
{
    mfn_t mfn = _mfn(pfn);
    unsigned int i, type;

    /*
     * Set up 1:1 mapping for dom0. Default to include only conventional RAM
     * areas and let RMRRs include needed reserved regions. When set, the
     * inclusive mapping additionally maps in every pfn up to 4GB except those
     * that fall in unusable ranges for PV Dom0.
     */
    if ( (pfn > max_pfn && !mfn_valid(mfn)) || xen_in_range(pfn) )
        return false;

    switch ( type = page_get_ram_type(mfn) )
    {
    case RAM_TYPE_UNUSABLE:
        return false;

    case RAM_TYPE_CONVENTIONAL:
        if ( iommu_hwdom_strict )
            return false;
        break;

    default:
        if ( type & RAM_TYPE_RESERVED )
        {
            if ( !iommu_hwdom_inclusive && !iommu_hwdom_reserved )
                return false;
        }
        else if ( is_hvm_domain(d) || !iommu_hwdom_inclusive || pfn > max_pfn )
            return false;
    }

    /* Check that it doesn't overlap with the Interrupt Address Range. */
    if ( pfn >= 0xfee00 && pfn <= 0xfeeff )
        return false;
    /* ... or the IO-APIC */
    for ( i = 0; has_vioapic(d) && i < d->arch.hvm.nr_vioapics; i++ )
        if ( pfn == PFN_DOWN(domain_vioapic(d, i)->base_address) )
            return false;
    /*
     * ... or the PCIe MCFG regions.
     * TODO: runtime added MMCFG regions are not checked to make sure they
     * don't overlap with already mapped regions, thus preventing trapping.
     */
    if ( has_vpci(d) && vpci_is_mmcfg_address(d, pfn_to_paddr(pfn)) )
        return false;

    return true;
}

void __hwdom_init arch_iommu_hwdom_init(struct domain *d)
{
    unsigned long i, top, max_pfn;
    unsigned int flush_flags = 0;

    BUG_ON(!is_hardware_domain(d));

    /* Reserved IOMMU mappings are enabled by default. */
    if ( iommu_hwdom_reserved == -1 )
        iommu_hwdom_reserved = 1;

    if ( iommu_hwdom_inclusive )
    {
        printk(XENLOG_WARNING
               "IOMMU inclusive mappings are deprecated and will be removed in future versions\n");

        if ( !is_pv_domain(d) )
        {
            printk(XENLOG_WARNING
                   "IOMMU inclusive mappings are only supported on PV Dom0\n");
            iommu_hwdom_inclusive = false;
        }
    }

    if ( iommu_hwdom_passthrough )
        return;

    max_pfn = (GB(4) >> PAGE_SHIFT) - 1;
    top = max(max_pdx, pfn_to_pdx(max_pfn) + 1);

    for ( i = 0; i < top; i++ )
    {
        unsigned long pfn = pdx_to_pfn(i);
        int rc;

        if ( !hwdom_iommu_map(d, pfn, max_pfn) )
            continue;

        if ( paging_mode_translate(d) )
            rc = set_identity_p2m_entry(d, pfn, p2m_access_rw, 0);
        else
            rc = iommu_map(d, _dfn(pfn), _mfn(pfn), PAGE_ORDER_4K,
                           IOMMUF_readable | IOMMUF_writable, &flush_flags);

        if ( rc )
            printk(XENLOG_WARNING " d%d: IOMMU mapping failed: %d\n",
                   d->domain_id, rc);

        if (!(i & 0xfffff))
            process_pending_softirqs();
    }

    /* Use if to avoid compiler warning */
    if ( iommu_iotlb_flush_all(d, flush_flags) )
        return;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
