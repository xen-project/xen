/*
 * Copyright (c) 2008, Intel Corporation.
 *
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
 *
 * Copyright (C) Allen Kay <allen.m.kay@intel.com>
 * Copyright (C) Weidong Han <weidong.han@intel.com>
 */

#include <xen/iommu.h>
#include <xen/irq.h>
#include <xen/sched.h>

static int _hvm_dpci_isairq_eoi(struct domain *d,
                                struct hvm_pirq_dpci *pirq_dpci, void *arg)
{
    struct hvm_irq *hvm_irq = hvm_domain_irq(d);
    unsigned int isairq = (long)arg;
    const struct dev_intx_gsi_link *digl;

    list_for_each_entry ( digl, &pirq_dpci->digl_list, list )
    {
        unsigned int link = hvm_pci_intx_link(digl->device, digl->intx);

        if ( hvm_irq->pci_link.route[link] == isairq )
        {
            hvm_pci_intx_deassert(d, digl->device, digl->intx);
            if ( --pirq_dpci->pending == 0 )
            {
                stop_timer(&pirq_dpci->timer);
                pirq_guest_eoi(dpci_pirq(pirq_dpci));
            }
        }
    }

    return 0;
}

void hvm_dpci_isairq_eoi(struct domain *d, unsigned int isairq)
{
    struct hvm_irq_dpci *dpci = NULL;

    ASSERT(isairq < NR_ISAIRQS);
    if ( !is_iommu_enabled(d) )
        return;

    spin_lock(&d->event_lock);

    dpci = domain_get_irq_dpci(d);

    if ( dpci && test_bit(isairq, dpci->isairq_map) )
    {
        /* Multiple mirq may be mapped to one isa irq */
        pt_pirq_iterate(d, _hvm_dpci_isairq_eoi, (void *)(long)isairq);
    }
    spin_unlock(&d->event_lock);
}
