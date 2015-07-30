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
#include <xen/pci.h>
#include <xen/pci_regs.h>
#include "../ats.h"

LIST_HEAD(ats_devices);

bool_t __read_mostly ats_enabled = 0;
boolean_param("ats", ats_enabled);

int enable_ats_device(int seg, int bus, int devfn, const void *iommu)
{
    struct pci_ats_dev *pdev = NULL;
    u32 value;
    int pos;

    pos = pci_find_ext_capability(seg, bus, devfn, PCI_EXT_CAP_ID_ATS);
    BUG_ON(!pos);

    if ( iommu_verbose )
        dprintk(XENLOG_INFO, "%04x:%02x:%02x.%u: ATS capability found\n",
                seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn));

    value = pci_conf_read16(seg, bus, PCI_SLOT(devfn),
                            PCI_FUNC(devfn), pos + ATS_REG_CTL);
    if ( value & ATS_ENABLE )
    {
        list_for_each_entry ( pdev, &ats_devices, list )
        {
            if ( pdev->seg == seg && pdev->bus == bus && pdev->devfn == devfn )
            {
                pos = 0;
                break;
            }
        }
    }
    if ( pos )
        pdev = xmalloc(struct pci_ats_dev);
    if ( !pdev )
        return -ENOMEM;

    if ( !(value & ATS_ENABLE) )
    {
        value |= ATS_ENABLE;
        pci_conf_write16(seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                         pos + ATS_REG_CTL, value);
    }

    if ( pos )
    {
        pdev->seg = seg;
        pdev->bus = bus;
        pdev->devfn = devfn;
        pdev->iommu = iommu;
        value = pci_conf_read16(seg, bus, PCI_SLOT(devfn),
                                PCI_FUNC(devfn), pos + ATS_REG_CAP);
        pdev->ats_queue_depth = value & ATS_QUEUE_DEPTH_MASK ?:
                                ATS_QUEUE_DEPTH_MASK + 1;
        list_add(&pdev->list, &ats_devices);
    }

    if ( iommu_verbose )
        dprintk(XENLOG_INFO, "%04x:%02x:%02x.%u: ATS %s enabled\n",
                seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                pos ? "is" : "was");

    return pos;
}

void disable_ats_device(int seg, int bus, int devfn)
{
    struct pci_ats_dev *pdev;
    u32 value;
    int pos;

    pos = pci_find_ext_capability(seg, bus, devfn, PCI_EXT_CAP_ID_ATS);
    BUG_ON(!pos);

    value = pci_conf_read16(seg, bus, PCI_SLOT(devfn),
                            PCI_FUNC(devfn), pos + ATS_REG_CTL);
    value &= ~ATS_ENABLE;
    pci_conf_write16(seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                     pos + ATS_REG_CTL, value);

    list_for_each_entry ( pdev, &ats_devices, list )
    {
        if ( pdev->seg == seg && pdev->bus == bus && pdev->devfn == devfn )
        {
            list_del(&pdev->list);
            xfree(pdev);
            break;
        }
    }

    if ( iommu_verbose )
        dprintk(XENLOG_INFO, "%04x:%02x:%02x.%u: ATS is disabled\n",
                seg, bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
}

struct pci_ats_dev *get_ats_device(int seg, int bus, int devfn)
{
    struct pci_ats_dev *pdev;

    if ( !pci_ats_device(seg, bus, devfn) )
        return NULL;

    list_for_each_entry ( pdev, &ats_devices, list )
    {
        if ( pdev->seg == seg && pdev->bus == bus && pdev->devfn == devfn )
            return pdev;
    }

    return NULL;
}
