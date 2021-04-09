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

#include <xen/param.h>
#include <xen/sched.h>
#include <xen/pci.h>
#include <xen/pci_regs.h>
#include "ats.h"

bool_t __read_mostly ats_enabled = 0;
boolean_param("ats", ats_enabled);

int enable_ats_device(struct pci_dev *pdev, struct list_head *ats_list)
{
    u32 value;
    u16 seg = pdev->seg;
    u8 bus = pdev->bus, devfn = pdev->devfn;
    int pos;

    pos = pci_find_ext_capability(seg, bus, devfn, PCI_EXT_CAP_ID_ATS);
    BUG_ON(!pos);

    if ( iommu_verbose )
        dprintk(XENLOG_INFO, "%pp: ATS capability found\n", &pdev->sbdf);

    value = pci_conf_read16(pdev->sbdf, pos + ATS_REG_CTL);
    if ( value & ATS_ENABLE )
    {
        struct pci_dev *other;

        list_for_each_entry ( other, ats_list, ats.list )
            if ( other == pdev )
            {
                pos = 0;
                break;
            }
    }

    if ( !(value & ATS_ENABLE) )
    {
        value |= ATS_ENABLE;
        pci_conf_write16(pdev->sbdf, pos + ATS_REG_CTL, value);
    }

    if ( pos )
    {
        pdev->ats.cap_pos = pos;
        value = pci_conf_read16(pdev->sbdf, pos + ATS_REG_CAP);
        pdev->ats.queue_depth = value & ATS_QUEUE_DEPTH_MASK ?:
                                ATS_QUEUE_DEPTH_MASK + 1;
        list_add(&pdev->ats.list, ats_list);
    }

    if ( iommu_verbose )
        dprintk(XENLOG_INFO, "%pp: ATS %s enabled\n",
                &pdev->sbdf, pos ? "is" : "was");

    return pos;
}

void disable_ats_device(struct pci_dev *pdev)
{
    u32 value;

    BUG_ON(!pdev->ats.cap_pos);

    value = pci_conf_read16(pdev->sbdf, pdev->ats.cap_pos + ATS_REG_CTL);
    value &= ~ATS_ENABLE;
    pci_conf_write16(pdev->sbdf, pdev->ats.cap_pos + ATS_REG_CTL, value);

    list_del(&pdev->ats.list);

    if ( iommu_verbose )
        dprintk(XENLOG_INFO, "%pp: ATS is disabled\n", &pdev->sbdf);
}
