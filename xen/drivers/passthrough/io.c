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
#include <asm/hvm/irq.h>
#include <asm/hvm/iommu.h>
#include <asm/hvm/support.h>
#include <xen/hvm/irq.h>

static void hvm_dirq_assist(unsigned long _d);

static int pt_irq_need_timer(uint32_t flags)
{
    return !(flags & (HVM_IRQ_DPCI_GUEST_MSI | HVM_IRQ_DPCI_TRANSLATE));
}

static void pt_irq_time_out(void *data)
{
    struct hvm_mirq_dpci_mapping *irq_map = data;
    unsigned int guest_gsi, machine_gsi = 0;
    struct hvm_irq_dpci *dpci = NULL;
    struct dev_intx_gsi_link *digl;
    struct hvm_girq_dpci_mapping *girq;
    uint32_t device, intx;
    unsigned int nr_pirqs = irq_map->dom->nr_pirqs;
    DECLARE_BITMAP(machine_gsi_map, nr_pirqs);

    bitmap_zero(machine_gsi_map, nr_pirqs);

    spin_lock(&irq_map->dom->event_lock);

    dpci = domain_get_irq_dpci(irq_map->dom);
    ASSERT(dpci);
    list_for_each_entry ( digl, &irq_map->digl_list, list )
    {
        guest_gsi = digl->gsi;
        list_for_each_entry ( girq, &dpci->girq[guest_gsi], list )
        {
            machine_gsi = girq->machine_gsi;
            set_bit(machine_gsi, machine_gsi_map);
        }
        device = digl->device;
        intx = digl->intx;
        hvm_pci_intx_deassert(irq_map->dom, device, intx);
    }

    for ( machine_gsi = find_first_bit(machine_gsi_map, nr_pirqs);
          machine_gsi < nr_pirqs;
          machine_gsi = find_next_bit(machine_gsi_map, nr_pirqs,
                                      machine_gsi + 1) )
    {
        clear_bit(machine_gsi, dpci->dirq_mask);
        dpci->mirq[machine_gsi].pending = 0;
    }

    spin_unlock(&irq_map->dom->event_lock);

    for ( machine_gsi = find_first_bit(machine_gsi_map, nr_pirqs);
          machine_gsi < nr_pirqs;
          machine_gsi = find_next_bit(machine_gsi_map, nr_pirqs,
                                      machine_gsi + 1) )
    {
        pirq_guest_eoi(irq_map->dom, machine_gsi);
    }
}

void free_hvm_irq_dpci(struct hvm_irq_dpci *dpci)
{
    xfree(dpci->mirq);
    xfree(dpci->dirq_mask);
    xfree(dpci->mapping);
    xfree(dpci->hvm_timer);
    xfree(dpci);
}

int pt_irq_create_bind_vtd(
    struct domain *d, xen_domctl_bind_pt_irq_t *pt_irq_bind)
{
    struct hvm_irq_dpci *hvm_irq_dpci = NULL;
    uint32_t machine_gsi, guest_gsi;
    uint32_t device, intx, link;
    struct dev_intx_gsi_link *digl;
    struct hvm_girq_dpci_mapping *girq;
    int rc, pirq = pt_irq_bind->machine_irq;

    if ( pirq < 0 || pirq >= d->nr_pirqs )
        return -EINVAL;

    spin_lock(&d->event_lock);

    hvm_irq_dpci = domain_get_irq_dpci(d);
    if ( hvm_irq_dpci == NULL )
    {
        hvm_irq_dpci = xmalloc(struct hvm_irq_dpci);
        if ( hvm_irq_dpci == NULL )
        {
            spin_unlock(&d->event_lock);
            return -ENOMEM;
        }
        memset(hvm_irq_dpci, 0, sizeof(*hvm_irq_dpci));
        tasklet_init(&hvm_irq_dpci->dirq_tasklet, 
                     hvm_dirq_assist, (unsigned long)d);
        hvm_irq_dpci->mirq = xmalloc_array(struct hvm_mirq_dpci_mapping,
                                           d->nr_pirqs);
        hvm_irq_dpci->dirq_mask = xmalloc_array(unsigned long,
                                                BITS_TO_LONGS(d->nr_pirqs));
        hvm_irq_dpci->mapping = xmalloc_array(unsigned long,
                                              BITS_TO_LONGS(d->nr_pirqs));
        hvm_irq_dpci->hvm_timer = xmalloc_array(struct timer, nr_irqs);
        if ( !hvm_irq_dpci->mirq ||
             !hvm_irq_dpci->dirq_mask ||
             !hvm_irq_dpci->mapping ||
             !hvm_irq_dpci->hvm_timer)
        {
            spin_unlock(&d->event_lock);
            free_hvm_irq_dpci(hvm_irq_dpci);
            return -ENOMEM;
        }
        memset(hvm_irq_dpci->mirq, 0,
               d->nr_pirqs * sizeof(*hvm_irq_dpci->mirq));
        bitmap_zero(hvm_irq_dpci->dirq_mask, d->nr_pirqs);
        bitmap_zero(hvm_irq_dpci->mapping, d->nr_pirqs);
        memset(hvm_irq_dpci->hvm_timer, 0, 
                nr_irqs * sizeof(*hvm_irq_dpci->hvm_timer));
        for ( int i = 0; i < d->nr_pirqs; i++ ) {
            INIT_LIST_HEAD(&hvm_irq_dpci->mirq[i].digl_list);
            hvm_irq_dpci->mirq[i].gmsi.dest_vcpu_id = -1;
        }
        for ( int i = 0; i < NR_HVM_IRQS; i++ )
            INIT_LIST_HEAD(&hvm_irq_dpci->girq[i]);

        if ( domain_set_irq_dpci(d, hvm_irq_dpci) == 0 )
        {
            spin_unlock(&d->event_lock);
            free_hvm_irq_dpci(hvm_irq_dpci);
            return -EINVAL;
        }
    }

    if ( pt_irq_bind->irq_type == PT_IRQ_TYPE_MSI )
    {
        uint8_t dest, dest_mode;
        int dest_vcpu_id;

        if ( !test_and_set_bit(pirq, hvm_irq_dpci->mapping))
        {
            hvm_irq_dpci->mirq[pirq].flags = HVM_IRQ_DPCI_MACH_MSI |
                                             HVM_IRQ_DPCI_GUEST_MSI;
            hvm_irq_dpci->mirq[pirq].gmsi.old_gvec = pt_irq_bind->u.msi.gvec;
            hvm_irq_dpci->mirq[pirq].gmsi.gvec = pt_irq_bind->u.msi.gvec;
            hvm_irq_dpci->mirq[pirq].gmsi.old_gflags = pt_irq_bind->u.msi.gflags;
            hvm_irq_dpci->mirq[pirq].gmsi.gflags = pt_irq_bind->u.msi.gflags;
            /* bind after hvm_irq_dpci is setup to avoid race with irq handler*/
            rc = pirq_guest_bind(d->vcpu[0], pirq, 0);
            if ( rc == 0 && pt_irq_bind->u.msi.gtable )
            {
                rc = msixtbl_pt_register(d, pirq, pt_irq_bind->u.msi.gtable);
                if ( unlikely(rc) )
                    pirq_guest_unbind(d, pirq);
            }
            if ( unlikely(rc) )
            {
                hvm_irq_dpci->mirq[pirq].gmsi.gflags = 0;
                hvm_irq_dpci->mirq[pirq].gmsi.gvec = 0;
                hvm_irq_dpci->mirq[pirq].gmsi.old_gvec = 0;
                hvm_irq_dpci->mirq[pirq].gmsi.old_gflags = 0;
                hvm_irq_dpci->mirq[pirq].flags = 0;
                clear_bit(pirq, hvm_irq_dpci->mapping);
                spin_unlock(&d->event_lock);
                return rc;
            }
        }
        else
        {
            uint32_t mask = HVM_IRQ_DPCI_MACH_MSI | HVM_IRQ_DPCI_GUEST_MSI;

            if ( (hvm_irq_dpci->mirq[pirq].flags & mask) != mask)
            {
	            spin_unlock(&d->event_lock);
        	    return -EBUSY;
            }
 
            /* if pirq is already mapped as vmsi, update the guest data/addr */
            if ( hvm_irq_dpci->mirq[pirq].gmsi.gvec != pt_irq_bind->u.msi.gvec ) {
                hvm_irq_dpci->mirq[pirq].gmsi.old_gvec =
                                    hvm_irq_dpci->mirq[pirq].gmsi.gvec;
                hvm_irq_dpci->mirq[pirq].gmsi.old_gflags =
                                    hvm_irq_dpci->mirq[pirq].gmsi.gflags;
                hvm_irq_dpci->mirq[pirq].gmsi.gvec = pt_irq_bind->u.msi.gvec;
                hvm_irq_dpci->mirq[pirq].gmsi.gflags = pt_irq_bind->u.msi.gflags;
            }
        }
        /* Caculate dest_vcpu_id for MSI-type pirq migration */
        dest = hvm_irq_dpci->mirq[pirq].gmsi.gflags & VMSI_DEST_ID_MASK;
        dest_mode = !!(hvm_irq_dpci->mirq[pirq].gmsi.gflags & VMSI_DM_MASK);
        dest_vcpu_id = hvm_girq_dest_2_vcpu_id(d, dest, dest_mode);
        hvm_irq_dpci->mirq[pirq].gmsi.dest_vcpu_id = dest_vcpu_id;
        spin_unlock(&d->event_lock);
        if ( dest_vcpu_id >= 0 )
            hvm_migrate_pirqs(d->vcpu[dest_vcpu_id]);
    }
    else
    {
        machine_gsi = pt_irq_bind->machine_irq;
        device = pt_irq_bind->u.pci.device;
        intx = pt_irq_bind->u.pci.intx;
        guest_gsi = hvm_pci_intx_gsi(device, intx);
        link = hvm_pci_intx_link(device, intx);
        hvm_irq_dpci->link_cnt[link]++;

        digl = xmalloc(struct dev_intx_gsi_link);
        if ( !digl )
        {
            spin_unlock(&d->event_lock);
            return -ENOMEM;
        }

        girq = xmalloc(struct hvm_girq_dpci_mapping);
        if ( !girq )
        {
            xfree(digl);
            spin_unlock(&d->event_lock);
            return -ENOMEM;
        }

        digl->device = device;
        digl->intx = intx;
        digl->gsi = guest_gsi;
        digl->link = link;
        list_add_tail(&digl->list,
                      &hvm_irq_dpci->mirq[machine_gsi].digl_list);

        girq->device = device;
        girq->intx = intx;
        girq->machine_gsi = machine_gsi;
        list_add_tail(&girq->list, &hvm_irq_dpci->girq[guest_gsi]);

        /* Bind the same mirq once in the same domain */
        if ( !test_and_set_bit(machine_gsi, hvm_irq_dpci->mapping))
        {
            unsigned int irq = domain_pirq_to_irq(d, machine_gsi);
            unsigned int share;

            hvm_irq_dpci->mirq[machine_gsi].dom = d;
            if ( pt_irq_bind->irq_type == PT_IRQ_TYPE_MSI_TRANSLATE )
            {
                hvm_irq_dpci->mirq[machine_gsi].flags = HVM_IRQ_DPCI_MACH_MSI |
                                                        HVM_IRQ_DPCI_GUEST_PCI |
                                                        HVM_IRQ_DPCI_TRANSLATE;
                share = 0;
            }
            else    /* PT_IRQ_TYPE_PCI */
            {
                hvm_irq_dpci->mirq[machine_gsi].flags = HVM_IRQ_DPCI_MACH_PCI |
                                                        HVM_IRQ_DPCI_GUEST_PCI;
                share = BIND_PIRQ__WILL_SHARE;
            }

            /* Init timer before binding */
            if ( pt_irq_need_timer(hvm_irq_dpci->mirq[machine_gsi].flags) )
                init_timer(&hvm_irq_dpci->hvm_timer[irq],
                           pt_irq_time_out, &hvm_irq_dpci->mirq[machine_gsi], 0);
            /* Deal with gsi for legacy devices */
            rc = pirq_guest_bind(d->vcpu[0], machine_gsi, share);
            if ( unlikely(rc) )
            {
                if ( pt_irq_need_timer(hvm_irq_dpci->mirq[machine_gsi].flags) )
                    kill_timer(&hvm_irq_dpci->hvm_timer[irq]);
                hvm_irq_dpci->mirq[machine_gsi].dom = NULL;
                clear_bit(machine_gsi, hvm_irq_dpci->mapping);
                list_del(&girq->list);
                xfree(girq);
                list_del(&digl->list);
                hvm_irq_dpci->link_cnt[link]--;
                spin_unlock(&d->event_lock);
                xfree(digl);
                return rc;
            }
        }

        gdprintk(XENLOG_INFO VTDPREFIX,
                 "VT-d irq bind: m_irq = %x device = %x intx = %x\n",
                 machine_gsi, device, intx);
        spin_unlock(&d->event_lock);
    }
    return 0;
}

int pt_irq_destroy_bind_vtd(
    struct domain *d, xen_domctl_bind_pt_irq_t *pt_irq_bind)
{
    struct hvm_irq_dpci *hvm_irq_dpci = NULL;
    uint32_t machine_gsi, guest_gsi;
    uint32_t device, intx, link;
    struct list_head *digl_list, *tmp;
    struct dev_intx_gsi_link *digl;
    struct hvm_girq_dpci_mapping *girq;

    machine_gsi = pt_irq_bind->machine_irq;
    device = pt_irq_bind->u.pci.device;
    intx = pt_irq_bind->u.pci.intx;
    guest_gsi = hvm_pci_intx_gsi(device, intx);
    link = hvm_pci_intx_link(device, intx);

    gdprintk(XENLOG_INFO,
             "pt_irq_destroy_bind_vtd: machine_gsi=%d "
             "guest_gsi=%d, device=%d, intx=%d.\n",
             machine_gsi, guest_gsi, device, intx);
    spin_lock(&d->event_lock);

    hvm_irq_dpci = domain_get_irq_dpci(d);

    if ( hvm_irq_dpci == NULL )
    {
        spin_unlock(&d->event_lock);
        return -EINVAL;
    }

    hvm_irq_dpci->link_cnt[link]--;

    list_for_each_entry ( girq, &hvm_irq_dpci->girq[guest_gsi], list )
    {
        if ( girq->machine_gsi == machine_gsi )
        {
                list_del(&girq->list);
                xfree(girq);
                break;
        }
    }

    /* clear the mirq info */
    if ( test_bit(machine_gsi, hvm_irq_dpci->mapping))
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
            msixtbl_pt_unregister(d, machine_gsi);
            if ( pt_irq_need_timer(hvm_irq_dpci->mirq[machine_gsi].flags) )
                kill_timer(&hvm_irq_dpci->hvm_timer[domain_pirq_to_irq(d, machine_gsi)]);
            hvm_irq_dpci->mirq[machine_gsi].dom   = NULL;
            hvm_irq_dpci->mirq[machine_gsi].flags = 0;
            clear_bit(machine_gsi, hvm_irq_dpci->mapping);
        }
    }
    spin_unlock(&d->event_lock);
    gdprintk(XENLOG_INFO,
             "XEN_DOMCTL_irq_unmapping: m_irq = 0x%x device = 0x%x intx = 0x%x\n",
             machine_gsi, device, intx);

    return 0;
}

int hvm_do_IRQ_dpci(struct domain *d, unsigned int mirq)
{
    struct hvm_irq_dpci *dpci = domain_get_irq_dpci(d);

    ASSERT(spin_is_locked(&irq_desc[domain_pirq_to_irq(d, mirq)].lock));
    if ( !iommu_enabled || (d == dom0) || !dpci ||
         !test_bit(mirq, dpci->mapping))
        return 0;

    set_bit(mirq, dpci->dirq_mask);
    tasklet_schedule(&dpci->dirq_tasklet);
    return 1;
}

#ifdef SUPPORT_MSI_REMAPPING
/* called with d->event_lock held */
static void __msi_pirq_eoi(struct domain *d, int pirq)
{
    struct hvm_irq_dpci *hvm_irq_dpci = d->arch.hvm_domain.irq.dpci;
    irq_desc_t *desc;

    if ( ( pirq >= 0 ) && ( pirq < d->nr_pirqs ) &&
         test_bit(pirq, hvm_irq_dpci->mapping) &&
         ( hvm_irq_dpci->mirq[pirq].flags & HVM_IRQ_DPCI_MACH_MSI) )
    {
         BUG_ON(!local_irq_is_enabled());
         desc = domain_spin_lock_irq_desc(d, pirq, NULL);
         if ( !desc )
            return;

         desc->status &= ~IRQ_INPROGRESS;
         spin_unlock_irq(&desc->lock);

         pirq_guest_eoi(d, pirq);
    }
}

void hvm_dpci_msi_eoi(struct domain *d, int vector)
{
    int pirq, dest, dest_mode;
    struct hvm_irq_dpci *hvm_irq_dpci = d->arch.hvm_domain.irq.dpci;

    if ( !iommu_enabled || (hvm_irq_dpci == NULL) )
       return;

    spin_lock(&d->event_lock);
    for ( pirq = find_first_bit(hvm_irq_dpci->mapping, d->nr_pirqs);
          pirq < d->nr_pirqs;
          pirq = find_next_bit(hvm_irq_dpci->mapping, d->nr_pirqs, pirq + 1) )
    {
        if ( (!(hvm_irq_dpci->mirq[pirq].flags & HVM_IRQ_DPCI_MACH_MSI)) ||
                (hvm_irq_dpci->mirq[pirq].gmsi.gvec != vector &&
                 hvm_irq_dpci->mirq[pirq].gmsi.old_gvec != vector) )
            continue;

        if ( hvm_irq_dpci->mirq[pirq].gmsi.gvec == vector ) {
            dest = hvm_irq_dpci->mirq[pirq].gmsi.gflags & VMSI_DEST_ID_MASK;
            dest_mode = !!(hvm_irq_dpci->mirq[pirq].gmsi.gflags & VMSI_DM_MASK);
        } else {
            dest = hvm_irq_dpci->mirq[pirq].gmsi.old_gflags & VMSI_DEST_ID_MASK;
            dest_mode = !!(hvm_irq_dpci->mirq[pirq].gmsi.old_gflags & VMSI_DM_MASK);
        }
        if ( vlapic_match_dest(vcpu_vlapic(current), NULL, 0, dest, dest_mode) )
            break;
    }

    if ( pirq < d->nr_pirqs )
        __msi_pirq_eoi(d, pirq);
    spin_unlock(&d->event_lock);
}

extern int vmsi_deliver(struct domain *d, int pirq);
static int hvm_pci_msi_assert(struct domain *d, int pirq)
{
    return vmsi_deliver(d, pirq);
}
#endif

static void hvm_dirq_assist(unsigned long _d)
{
    unsigned int pirq;
    uint32_t device, intx;
    struct domain *d = (struct domain *)_d;
    struct hvm_irq_dpci *hvm_irq_dpci = d->arch.hvm_domain.irq.dpci;
    struct dev_intx_gsi_link *digl;

    ASSERT(hvm_irq_dpci);

    for ( pirq = find_first_bit(hvm_irq_dpci->dirq_mask, d->nr_pirqs);
          pirq < d->nr_pirqs;
          pirq = find_next_bit(hvm_irq_dpci->dirq_mask, d->nr_pirqs, pirq + 1) )
    {
        if ( !test_and_clear_bit(pirq, hvm_irq_dpci->dirq_mask) )
            continue;

        spin_lock(&d->event_lock);
#ifdef SUPPORT_MSI_REMAPPING
        if ( hvm_irq_dpci->mirq[pirq].flags & HVM_IRQ_DPCI_GUEST_MSI )
        {
            hvm_pci_msi_assert(d, pirq);
            spin_unlock(&d->event_lock);
            continue;
        }
#endif
        list_for_each_entry ( digl, &hvm_irq_dpci->mirq[pirq].digl_list, list )
        {
            device = digl->device;
            intx = digl->intx;
            hvm_pci_intx_assert(d, device, intx);
            hvm_irq_dpci->mirq[pirq].pending++;

#ifdef SUPPORT_MSI_REMAPPING
            if ( hvm_irq_dpci->mirq[pirq].flags & HVM_IRQ_DPCI_TRANSLATE )
            {
                /* for translated MSI to INTx interrupt, eoi as early as possible */
                __msi_pirq_eoi(d, pirq);
            }
#endif
        }

        /*
         * Set a timer to see if the guest can finish the interrupt or not. For
         * example, the guest OS may unmask the PIC during boot, before the
         * guest driver is loaded. hvm_pci_intx_assert() may succeed, but the
         * guest will never deal with the irq, then the physical interrupt line
         * will never be deasserted.
         */
        if ( pt_irq_need_timer(hvm_irq_dpci->mirq[pirq].flags) )
            set_timer(&hvm_irq_dpci->hvm_timer[domain_pirq_to_irq(d, pirq)],
                      NOW() + PT_IRQ_TIME_OUT);
        spin_unlock(&d->event_lock);
    }
}

static void __hvm_dpci_eoi(struct domain *d,
                           struct hvm_irq_dpci *hvm_irq_dpci,
                           struct hvm_girq_dpci_mapping *girq,
                           union vioapic_redir_entry *ent)
{
    uint32_t device, intx, machine_gsi;

    device = girq->device;
    intx = girq->intx;
    hvm_pci_intx_deassert(d, device, intx);

    machine_gsi = girq->machine_gsi;

    /*
     * No need to get vector lock for timer
     * since interrupt is still not EOIed
     */
    if ( --hvm_irq_dpci->mirq[machine_gsi].pending ||
         ( ent && ent->fields.mask ) ||
         ! pt_irq_need_timer(hvm_irq_dpci->mirq[machine_gsi].flags) )
        return;

    stop_timer(&hvm_irq_dpci->hvm_timer[domain_pirq_to_irq(d, machine_gsi)]);
    pirq_guest_eoi(d, machine_gsi);
}

void hvm_dpci_eoi(struct domain *d, unsigned int guest_gsi,
                  union vioapic_redir_entry *ent)
{
    struct hvm_irq_dpci *hvm_irq_dpci;
    struct hvm_girq_dpci_mapping *girq;

    if ( !iommu_enabled )
        return;

    if ( guest_gsi < NR_ISAIRQS )
    {
        hvm_dpci_isairq_eoi(d, guest_gsi);
        return;
    }

    spin_lock(&d->event_lock);
    hvm_irq_dpci = domain_get_irq_dpci(d);

    if ( !hvm_irq_dpci )
        goto unlock;

    list_for_each_entry ( girq, &hvm_irq_dpci->girq[guest_gsi], list )
        __hvm_dpci_eoi(d, hvm_irq_dpci, girq, ent);

unlock:
    spin_unlock(&d->event_lock);
}
