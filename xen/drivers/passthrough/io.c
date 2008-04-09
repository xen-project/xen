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

#include <xen/event.h>
#include <xen/iommu.h>

static void pt_irq_time_out(void *data)
{
    struct hvm_mirq_dpci_mapping *irq_map = data;
    unsigned int guest_gsi, machine_gsi = 0;
    struct hvm_irq_dpci *dpci = domain_get_irq_dpci(irq_map->dom);
    struct dev_intx_gsi_link *digl;
    uint32_t device, intx;

    list_for_each_entry ( digl, &irq_map->digl_list, list )
    {
        guest_gsi = digl->gsi;
        machine_gsi = dpci->girq[guest_gsi].machine_gsi;
        device = digl->device;
        intx = digl->intx;
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
    struct hvm_irq_dpci *hvm_irq_dpci = domain_get_irq_dpci(d);
    uint32_t machine_gsi, guest_gsi;
    uint32_t device, intx, link;
    struct dev_intx_gsi_link *digl;

    if ( hvm_irq_dpci == NULL )
    {
        hvm_irq_dpci = xmalloc(struct hvm_irq_dpci);
        if ( hvm_irq_dpci == NULL )
            return -ENOMEM;

        memset(hvm_irq_dpci, 0, sizeof(*hvm_irq_dpci));
        spin_lock_init(&hvm_irq_dpci->dirq_lock);
        for ( int i = 0; i < NR_IRQS; i++ )
            INIT_LIST_HEAD(&hvm_irq_dpci->mirq[i].digl_list);

        if ( domain_set_irq_dpci(d, hvm_irq_dpci) == 0 )
            xfree(hvm_irq_dpci);
    }

    machine_gsi = pt_irq_bind->machine_irq;
    device = pt_irq_bind->u.pci.device;
    intx = pt_irq_bind->u.pci.intx;
    guest_gsi = hvm_pci_intx_gsi(device, intx);
    link = hvm_pci_intx_link(device, intx);
    hvm_irq_dpci->link_cnt[link]++;

    digl = xmalloc(struct dev_intx_gsi_link);
    if ( !digl )
        return -ENOMEM;

    digl->device = device;
    digl->intx = intx;
    digl->gsi = guest_gsi;
    digl->link = link;
    list_add_tail(&digl->list,
                  &hvm_irq_dpci->mirq[machine_gsi].digl_list);

    hvm_irq_dpci->girq[guest_gsi].valid = 1;
    hvm_irq_dpci->girq[guest_gsi].device = device;
    hvm_irq_dpci->girq[guest_gsi].intx = intx;
    hvm_irq_dpci->girq[guest_gsi].machine_gsi = machine_gsi;

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

    gdprintk(XENLOG_INFO VTDPREFIX,
             "VT-d irq bind: m_irq = %x device = %x intx = %x\n",
             machine_gsi, device, intx);
    return 0;
}

int pt_irq_destroy_bind_vtd(
    struct domain *d, xen_domctl_bind_pt_irq_t *pt_irq_bind)
{
    struct hvm_irq_dpci *hvm_irq_dpci = domain_get_irq_dpci(d);
    uint32_t machine_gsi, guest_gsi;
    uint32_t device, intx, link;
    struct list_head *digl_list, *tmp;
    struct dev_intx_gsi_link *digl;

    if ( hvm_irq_dpci == NULL )
        return 0;

    machine_gsi = pt_irq_bind->machine_irq;
    device = pt_irq_bind->u.pci.device;
    intx = pt_irq_bind->u.pci.intx;
    guest_gsi = hvm_pci_intx_gsi(device, intx);
    link = hvm_pci_intx_link(device, intx);
    hvm_irq_dpci->link_cnt[link]--;

    gdprintk(XENLOG_INFO,
             "pt_irq_destroy_bind_vtd: machine_gsi=%d "
             "guest_gsi=%d, device=%d, intx=%d.\n",
             machine_gsi, guest_gsi, device, intx);
    memset(&hvm_irq_dpci->girq[guest_gsi], 0,
           sizeof(struct hvm_girq_dpci_mapping));

    /* clear the mirq info */
    if ( hvm_irq_dpci->mirq[machine_gsi].valid )
    {
        list_for_each_safe ( digl_list, tmp,
                &hvm_irq_dpci->mirq[machine_gsi].digl_list )
        {
            digl = list_entry(digl_list,
                    struct dev_intx_gsi_link, list);
            if ( digl->device == device &&
                 digl->intx   == intx &&
                 digl->link   == link &&
                 digl->gsi    == guest_gsi )
            {
                list_del(&digl->list);
                xfree(digl);
            }
        }

        if ( list_empty(&hvm_irq_dpci->mirq[machine_gsi].digl_list) )
        {
            pirq_guest_unbind(d, machine_gsi);
            kill_timer(&hvm_irq_dpci->hvm_timer[irq_to_vector(machine_gsi)]);
            hvm_irq_dpci->mirq[machine_gsi].dom   = NULL;
            hvm_irq_dpci->mirq[machine_gsi].valid = 0;
        }
    }

    gdprintk(XENLOG_INFO,
             "XEN_DOMCTL_irq_unmapping: m_irq = %x device = %x intx = %x\n",
             machine_gsi, device, intx);

    return 0;
}

int hvm_do_IRQ_dpci(struct domain *d, unsigned int mirq)
{
    struct hvm_irq_dpci *dpci = domain_get_irq_dpci(d);

    if ( !iommu_enabled || (d == dom0) || !dpci ||
         !dpci->mirq[mirq].valid )
        return 0;

    /*
     * Set a timer here to avoid situations where the IRQ line is shared, and
     * the device belonging to the pass-through guest is not yet active. In
     * this case the guest may not pick up the interrupt (e.g., masked at the
     * PIC) and we need to detect that.
     */
    set_bit(mirq, dpci->dirq_mask);
    set_timer(&dpci->hvm_timer[irq_to_vector(mirq)],
              NOW() + PT_IRQ_TIME_OUT);
    vcpu_kick(d->vcpu[0]);

    return 1;
}

void hvm_dpci_eoi(struct domain *d, unsigned int guest_gsi,
                  union vioapic_redir_entry *ent)
{
    struct hvm_irq_dpci *hvm_irq_dpci = domain_get_irq_dpci(d);
    uint32_t device, intx, machine_gsi;

    if ( !iommu_enabled || (hvm_irq_dpci == NULL) ||
         (guest_gsi >= NR_ISAIRQS &&
          !hvm_irq_dpci->girq[guest_gsi].valid) )
        return;

    if ( guest_gsi < NR_ISAIRQS )
    {
        hvm_dpci_isairq_eoi(d, guest_gsi);
        return;
    }

    machine_gsi = hvm_irq_dpci->girq[guest_gsi].machine_gsi;
    device = hvm_irq_dpci->girq[guest_gsi].device;
    intx = hvm_irq_dpci->girq[guest_gsi].intx;
    hvm_pci_intx_deassert(d, device, intx);

    spin_lock(&hvm_irq_dpci->dirq_lock);
    if ( --hvm_irq_dpci->mirq[machine_gsi].pending == 0 )
    {
        spin_unlock(&hvm_irq_dpci->dirq_lock);

        gdprintk(XENLOG_INFO VTDPREFIX,
                 "hvm_dpci_eoi:: mirq = %x\n", machine_gsi);
        stop_timer(&hvm_irq_dpci->hvm_timer[irq_to_vector(machine_gsi)]);
        if ( (ent == NULL) || !ent->fields.mask )
            pirq_guest_eoi(d, machine_gsi);
    }
    else
        spin_unlock(&hvm_irq_dpci->dirq_lock);
}
