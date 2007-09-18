/*
 * Copyright (c) 2006, Intel Corporation.
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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 * Copyright (C) Allen Kay <allen.m.kay@intel.com>
 * Copyright (C) Xiaohui Xin <xiaohui.xin@intel.com>
 */

#include <xen/init.h>
#include <xen/config.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/trace.h>
#include <xen/event.h>
#include <xen/hypercall.h>
#include <asm/current.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/apic.h>
#include <asm/paging.h>
#include <asm/shadow.h>
#include <asm/p2m.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vpt.h>
#include <asm/hvm/vpic.h>
#include <asm/hvm/vlapic.h>
#include <public/sched.h>
#include <xen/iocap.h>
#include <public/hvm/ioreq.h>

int hvm_do_IRQ_dpci(struct domain *d, unsigned int mirq)
{
    uint32_t device, intx;
    uint32_t link, isa_irq;
    struct hvm_irq *hvm_irq;

    if ( !vtd_enabled || (d == dom0) ||
         !d->arch.hvm_domain.irq.mirq[mirq].valid )
        return 0;

    device = d->arch.hvm_domain.irq.mirq[mirq].device;
    intx = d->arch.hvm_domain.irq.mirq[mirq].intx;
    link = hvm_pci_intx_link(device, intx);
    hvm_irq = &d->arch.hvm_domain.irq;
    isa_irq = hvm_irq->pci_link.route[link];

    if ( !d->arch.hvm_domain.irq.girq[isa_irq].valid )
    {
        d->arch.hvm_domain.irq.girq[isa_irq].valid = 1;
        d->arch.hvm_domain.irq.girq[isa_irq].device = device;
        d->arch.hvm_domain.irq.girq[isa_irq].intx = intx;
        d->arch.hvm_domain.irq.girq[isa_irq].machine_gsi = mirq;
    }

    if ( !test_and_set_bit(mirq, d->arch.hvm_domain.irq.dirq_mask) )
    {
        vcpu_kick(d->vcpu[0]);
        return 1;
    }

    dprintk(XENLOG_INFO, "mirq already pending\n");
    return 0;
}

void hvm_dpci_eoi(unsigned int guest_gsi, union vioapic_redir_entry *ent)
{
    struct domain *d = current->domain;
    uint32_t device, intx, machine_gsi;
    irq_desc_t *desc;

    ASSERT(spin_is_locked(&d->arch.hvm_domain.irq_lock));

    if ( !vtd_enabled || !d->arch.hvm_domain.irq.girq[guest_gsi].valid )
        return;

    device = d->arch.hvm_domain.irq.girq[guest_gsi].device;
    intx = d->arch.hvm_domain.irq.girq[guest_gsi].intx;
    machine_gsi = d->arch.hvm_domain.irq.girq[guest_gsi].machine_gsi;
    gdprintk(XENLOG_INFO, "hvm_dpci_eoi:: device %x intx %x\n",
             device, intx);
    __hvm_pci_intx_deassert(d, device, intx);
    if ( (ent == NULL) || (ent->fields.mask == 0) )
    {
        desc = &irq_desc[irq_to_vector(machine_gsi)];
        desc->handler->end(irq_to_vector(machine_gsi));
    }
}

int release_devices(struct domain *d)
{
    struct hvm_domain *hd = &d->arch.hvm_domain;
    uint32_t i;
    int ret = 0;

    if ( !vtd_enabled )
        return ret;

    for ( i = 0; i < NR_IRQS; i++ )
        if ( hd->irq.mirq[i].valid )
            ret = pirq_guest_unbind(d, i);

    iommu_domain_teardown(d);
    return ret;
}
