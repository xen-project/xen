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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include <xen/sched.h>
#include <xen/iommu.h>

extern struct iommu_ops intel_iommu_ops;
extern struct iommu_ops amd_iommu_ops;
int intel_vtd_setup(void);
int amd_iov_detect(void);

int iommu_domain_init(struct domain *domain)
{
    struct hvm_iommu *hd = domain_hvm_iommu(domain);

    spin_lock_init(&hd->mapping_lock);
    spin_lock_init(&hd->iommu_list_lock);
    INIT_LIST_HEAD(&hd->pdev_list);
    INIT_LIST_HEAD(&hd->g2m_ioport_list);

    if ( !iommu_enabled )
        return 0;

    switch ( boot_cpu_data.x86_vendor )
    {
    case X86_VENDOR_INTEL:
        hd->platform_ops = &intel_iommu_ops;
        break;
    case X86_VENDOR_AMD:
        hd->platform_ops = &amd_iommu_ops;
        break;
    default:
        BUG();
    }

    return hd->platform_ops->init(domain);
}

int assign_device(struct domain *d, u8 bus, u8 devfn)
{
    struct hvm_iommu *hd = domain_hvm_iommu(d);

    if ( !iommu_enabled || !hd->platform_ops )
        return 0;

    return hd->platform_ops->assign_device(d, bus, devfn);
}

void iommu_domain_destroy(struct domain *d)
{
    struct hvm_irq_dpci *hvm_irq_dpci = domain_get_irq_dpci(d);
    uint32_t i;
    struct hvm_iommu *hd  = domain_hvm_iommu(d);
    struct list_head *ioport_list, *digl_list, *tmp;
    struct g2m_ioport *ioport;
    struct dev_intx_gsi_link *digl;

    if ( !iommu_enabled || !hd->platform_ops )
        return;

    if ( hvm_irq_dpci != NULL )
    {
        for ( i = 0; i < NR_IRQS; i++ )
        {
            if ( !hvm_irq_dpci->mirq[i].valid )
                continue;

            pirq_guest_unbind(d, i);
            kill_timer(&hvm_irq_dpci->hvm_timer[irq_to_vector(i)]);

            list_for_each_safe ( digl_list, tmp,
                                 &hvm_irq_dpci->mirq[i].digl_list )
            {
                digl = list_entry(digl_list,
                                  struct dev_intx_gsi_link, list);
                list_del(&digl->list);
                xfree(digl);
            }
        }

        d->arch.hvm_domain.irq.dpci = NULL;
        xfree(hvm_irq_dpci);
    }

    if ( hd )
    {
        list_for_each_safe ( ioport_list, tmp, &hd->g2m_ioport_list )
        {
            ioport = list_entry(ioport_list, struct g2m_ioport, list);
            list_del(&ioport->list);
            xfree(ioport);
        }
    }

    return hd->platform_ops->teardown(d);
}

int iommu_map_page(struct domain *d, unsigned long gfn, unsigned long mfn)
{
    struct hvm_iommu *hd = domain_hvm_iommu(d);

    if ( !iommu_enabled || !hd->platform_ops )
        return 0;

    return hd->platform_ops->map_page(d, gfn, mfn);
}

int iommu_unmap_page(struct domain *d, unsigned long gfn)
{
    struct hvm_iommu *hd = domain_hvm_iommu(d);

    if ( !iommu_enabled || !hd->platform_ops )
        return 0;

    return hd->platform_ops->unmap_page(d, gfn);
}

void deassign_device(struct domain *d, u8 bus, u8 devfn)
{
    struct hvm_iommu *hd = domain_hvm_iommu(d);

    if ( !iommu_enabled || !hd->platform_ops )
        return;

    return hd->platform_ops->reassign_device(d, dom0, bus, devfn);
}

int iommu_setup(void)
{
    switch ( boot_cpu_data.x86_vendor )
    {
    case X86_VENDOR_INTEL:
        return intel_vtd_setup();
    case X86_VENDOR_AMD:
        return amd_iov_detect();
    }

    return 0;
}
