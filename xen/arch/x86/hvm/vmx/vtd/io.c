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
#include <public/domctl.h>

static void pt_irq_time_out(void *data)
{
    struct hvm_mirq_dpci_mapping *irq_map = data;
    unsigned int guest_gsi, machine_gsi = 0;
    struct hvm_irq_dpci *dpci = irq_map->dom->arch.hvm_domain.irq.dpci;
    struct dev_intx_gsi *dig;
    uint32_t device, intx;

    list_for_each_entry ( dig, &irq_map->dig_list, list )
    {
        guest_gsi = dig->gsi;
        machine_gsi = dpci->girq[guest_gsi].machine_gsi;
        device = dig->device;
        intx = dig->intx;
        hvm_pci_intx_deassert(irq_map->dom, device, intx);
    }

    clear_bit(machine_gsi, dpci->dirq_mask);
    stop_timer(&dpci->hvm_timer[irq_to_vector(machine_gsi)]);
    spin_lock(&dpci->dirq_lock);
    dpci->mirq[machine_gsi].pending = 0;
    spin_unlock(&dpci->dirq_lock);
    pirq_guest_eoi(irq_map->dom, machine_gsi);
}

int pt_irq_create_bind_vtd(
    struct domain *d, xen_domctl_bind_pt_irq_t *pt_irq_bind)
{
    struct hvm_irq_dpci *hvm_irq_dpci = d->arch.hvm_domain.irq.dpci;
    uint32_t machine_gsi, guest_gsi;
    uint32_t device, intx, link;
    struct dev_intx_gsi *dig;

    if ( hvm_irq_dpci == NULL )
    {
        hvm_irq_dpci = xmalloc(struct hvm_irq_dpci);
        if ( hvm_irq_dpci == NULL )
            return -ENOMEM;

        memset(hvm_irq_dpci, 0, sizeof(*hvm_irq_dpci));
        spin_lock_init(&hvm_irq_dpci->dirq_lock);
        for ( int i = 0; i < NR_IRQS; i++ )
            INIT_LIST_HEAD(&hvm_irq_dpci->mirq[i].dig_list);

        if ( cmpxchg((unsigned long *)&d->arch.hvm_domain.irq.dpci,
                     0, (unsigned long)hvm_irq_dpci) != 0 )
            xfree(hvm_irq_dpci);

        hvm_irq_dpci = d->arch.hvm_domain.irq.dpci;
    }

    machine_gsi = pt_irq_bind->machine_irq;
    device = pt_irq_bind->u.pci.device;
    intx = pt_irq_bind->u.pci.intx;
    guest_gsi = hvm_pci_intx_gsi(device, intx);
    link = hvm_pci_intx_link(device, intx);

    dig = xmalloc(struct dev_intx_gsi);
    if ( !dig )
        return -ENOMEM;

    dig->device = device;
    dig->intx = intx;
    dig->gsi = guest_gsi;
    list_add_tail(&dig->list,
                  &hvm_irq_dpci->mirq[machine_gsi].dig_list);
 
    hvm_irq_dpci->girq[guest_gsi].valid = 1;
    hvm_irq_dpci->girq[guest_gsi].device = device;
    hvm_irq_dpci->girq[guest_gsi].intx = intx;
    hvm_irq_dpci->girq[guest_gsi].machine_gsi = machine_gsi;

    hvm_irq_dpci->link[link].valid = 1;
    hvm_irq_dpci->link[link].device = device;
    hvm_irq_dpci->link[link].intx = intx;
    hvm_irq_dpci->link[link].machine_gsi = machine_gsi;

    /* Bind the same mirq once in the same domain */
    if ( !hvm_irq_dpci->mirq[machine_gsi].valid )
    {
        hvm_irq_dpci->mirq[machine_gsi].valid = 1;
        hvm_irq_dpci->mirq[machine_gsi].dom = d;

        init_timer(&hvm_irq_dpci->hvm_timer[irq_to_vector(machine_gsi)],
                   pt_irq_time_out, &hvm_irq_dpci->mirq[machine_gsi], 0);
        /* Deal with gsi for legacy devices */
        pirq_guest_bind(d->vcpu[0], machine_gsi, BIND_PIRQ__WILL_SHARE);
    }

    gdprintk(XENLOG_INFO,
             "VT-d irq bind: m_irq = %x device = %x intx = %x\n",
             machine_gsi, device, intx);
    return 0;
}

int hvm_do_IRQ_dpci(struct domain *d, unsigned int mirq)
{
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;

    if ( !vtd_enabled || (d == dom0) || (hvm_irq->dpci == NULL) ||
         !hvm_irq->dpci->mirq[mirq].valid )
        return 0;

    /*
     * Set a timer here to avoid situations where the IRQ line is shared, and
     * the device belonging to the pass-through guest is not yet active. In
     * this case the guest may not pick up the interrupt (e.g., masked at the
     * PIC) and we need to detect that.
     */
    set_bit(mirq, hvm_irq->dpci->dirq_mask);
    set_timer(&hvm_irq->dpci->hvm_timer[irq_to_vector(mirq)],
              NOW() + PT_IRQ_TIME_OUT);
    vcpu_kick(d->vcpu[0]);

    return 1;
}

void hvm_dpci_eoi(struct domain *d, unsigned int guest_gsi,
                  union vioapic_redir_entry *ent)
{
    struct hvm_irq_dpci *hvm_irq_dpci = d->arch.hvm_domain.irq.dpci;
    uint32_t device, intx, machine_gsi;

    if ( !vtd_enabled || (hvm_irq_dpci == NULL) ||
         !hvm_irq_dpci->girq[guest_gsi].valid )
        return;

    machine_gsi = hvm_irq_dpci->girq[guest_gsi].machine_gsi;
    device = hvm_irq_dpci->girq[guest_gsi].device;
    intx = hvm_irq_dpci->girq[guest_gsi].intx;
    hvm_pci_intx_deassert(d, device, intx);
 
    spin_lock(&hvm_irq_dpci->dirq_lock);
    if ( --hvm_irq_dpci->mirq[machine_gsi].pending == 0 )
    {
        spin_unlock(&hvm_irq_dpci->dirq_lock);

        gdprintk(XENLOG_INFO, "hvm_dpci_eoi:: mirq = %x\n", machine_gsi);
        stop_timer(&hvm_irq_dpci->hvm_timer[irq_to_vector(machine_gsi)]);
        if ( (ent == NULL) || !ent->fields.mask )
            pirq_guest_eoi(d, machine_gsi);
    }
    else
        spin_unlock(&hvm_irq_dpci->dirq_lock);
}

void iommu_domain_destroy(struct domain *d)
{
    struct hvm_irq_dpci *hvm_irq_dpci = d->arch.hvm_domain.irq.dpci;
    uint32_t i;
    struct hvm_iommu *hd  = domain_hvm_iommu(d);
    struct list_head *ioport_list, *dig_list, *tmp;
    struct g2m_ioport *ioport;
    struct dev_intx_gsi *dig;

    if ( !vtd_enabled )
        return;

    if ( hvm_irq_dpci != NULL )
    {
        for ( i = 0; i < NR_IRQS; i++ )
            if ( hvm_irq_dpci->mirq[i].valid )
            {
                pirq_guest_unbind(d, i);
                kill_timer(&hvm_irq_dpci->hvm_timer[irq_to_vector(i)]);

                list_for_each_safe ( dig_list, tmp,
                                     &hvm_irq_dpci->mirq[i].dig_list )
                {
                    dig = list_entry(dig_list, struct dev_intx_gsi, list);
                    list_del(&dig->list);
                    xfree(dig);
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

    iommu_domain_teardown(d);
}
