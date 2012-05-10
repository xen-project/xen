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
#include <xen/irq.h>
#include <asm/hvm/irq.h>
#include <asm/hvm/iommu.h>
#include <asm/hvm/support.h>
#include <xen/hvm/irq.h>
#include <xen/tasklet.h>

struct rangeset *__read_mostly mmio_ro_ranges;

static void hvm_dirq_assist(unsigned long _d);

bool_t pt_irq_need_timer(uint32_t flags)
{
    return !(flags & (HVM_IRQ_DPCI_GUEST_MSI | HVM_IRQ_DPCI_TRANSLATE));
}

static int pt_irq_guest_eoi(struct domain *d, struct hvm_pirq_dpci *pirq_dpci,
                            void *arg)
{
    if ( __test_and_clear_bit(_HVM_IRQ_DPCI_EOI_LATCH_SHIFT,
                              &pirq_dpci->flags) )
    {
        pirq_dpci->masked = 0;
        pirq_dpci->pending = 0;
        pirq_guest_eoi(dpci_pirq(pirq_dpci));
    }

    return 0;
}

static void pt_irq_time_out(void *data)
{
    struct hvm_pirq_dpci *irq_map = data;
    unsigned int guest_gsi;
    struct hvm_irq_dpci *dpci = NULL;
    struct dev_intx_gsi_link *digl;
    struct hvm_girq_dpci_mapping *girq;
    uint32_t device, intx;

    spin_lock(&irq_map->dom->event_lock);

    dpci = domain_get_irq_dpci(irq_map->dom);
    ASSERT(dpci);
    list_for_each_entry ( digl, &irq_map->digl_list, list )
    {
        guest_gsi = digl->gsi;
        list_for_each_entry ( girq, &dpci->girq[guest_gsi], list )
        {
            struct pirq *pirq = pirq_info(irq_map->dom, girq->machine_gsi);

            pirq_dpci(pirq)->flags |= HVM_IRQ_DPCI_EOI_LATCH;
        }
        device = digl->device;
        intx = digl->intx;
        hvm_pci_intx_deassert(irq_map->dom, device, intx);
    }

    pt_pirq_iterate(irq_map->dom, pt_irq_guest_eoi, NULL);

    spin_unlock(&irq_map->dom->event_lock);
}

struct hvm_irq_dpci *domain_get_irq_dpci(const struct domain *d)
{
    if ( !d || !is_hvm_domain(d) )
        return NULL;

    return d->arch.hvm_domain.irq.dpci;
}

void free_hvm_irq_dpci(struct hvm_irq_dpci *dpci)
{
    xfree(dpci);
}

int pt_irq_create_bind_vtd(
    struct domain *d, xen_domctl_bind_pt_irq_t *pt_irq_bind)
{
    struct hvm_irq_dpci *hvm_irq_dpci = NULL;
    struct hvm_pirq_dpci *pirq_dpci;
    struct pirq *info;
    uint32_t guest_gsi;
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
        hvm_irq_dpci = xzalloc(struct hvm_irq_dpci);
        if ( hvm_irq_dpci == NULL )
        {
            spin_unlock(&d->event_lock);
            return -ENOMEM;
        }
        softirq_tasklet_init(
            &hvm_irq_dpci->dirq_tasklet,
            hvm_dirq_assist, (unsigned long)d);
        for ( int i = 0; i < NR_HVM_IRQS; i++ )
            INIT_LIST_HEAD(&hvm_irq_dpci->girq[i]);

        d->arch.hvm_domain.irq.dpci = hvm_irq_dpci;
    }

    info = pirq_get_info(d, pirq);
    if ( !info )
    {
        spin_unlock(&d->event_lock);
        return -ENOMEM;
    }
    pirq_dpci = pirq_dpci(info);

    if ( pt_irq_bind->irq_type == PT_IRQ_TYPE_MSI )
    {
        uint8_t dest, dest_mode;
        int dest_vcpu_id;

        if ( !(pirq_dpci->flags & HVM_IRQ_DPCI_MAPPED) )
        {
            pirq_dpci->flags = HVM_IRQ_DPCI_MAPPED | HVM_IRQ_DPCI_MACH_MSI |
                               HVM_IRQ_DPCI_GUEST_MSI;
            pirq_dpci->gmsi.gvec = pt_irq_bind->u.msi.gvec;
            pirq_dpci->gmsi.gflags = pt_irq_bind->u.msi.gflags;
            /* bind after hvm_irq_dpci is setup to avoid race with irq handler*/
            rc = pirq_guest_bind(d->vcpu[0], info, 0);
            if ( rc == 0 && pt_irq_bind->u.msi.gtable )
            {
                rc = msixtbl_pt_register(d, info, pt_irq_bind->u.msi.gtable);
                if ( unlikely(rc) )
                    pirq_guest_unbind(d, info);
            }
            if ( unlikely(rc) )
            {
                pirq_dpci->gmsi.gflags = 0;
                pirq_dpci->gmsi.gvec = 0;
                pirq_dpci->flags = 0;
                pirq_cleanup_check(info, d);
                spin_unlock(&d->event_lock);
                return rc;
            }
        }
        else
        {
            uint32_t mask = HVM_IRQ_DPCI_MACH_MSI | HVM_IRQ_DPCI_GUEST_MSI;

            if ( (pirq_dpci->flags & mask) != mask)
            {
	            spin_unlock(&d->event_lock);
        	    return -EBUSY;
            }

            /* if pirq is already mapped as vmsi, update the guest data/addr */
            if ( pirq_dpci->gmsi.gvec != pt_irq_bind->u.msi.gvec ||
                 pirq_dpci->gmsi.gflags != pt_irq_bind->u.msi.gflags) {
                /* Directly clear pending EOIs before enabling new MSI info. */
                pirq_guest_eoi(info);

                pirq_dpci->gmsi.gvec = pt_irq_bind->u.msi.gvec;
                pirq_dpci->gmsi.gflags = pt_irq_bind->u.msi.gflags;
            }
        }
        /* Caculate dest_vcpu_id for MSI-type pirq migration */
        dest = pirq_dpci->gmsi.gflags & VMSI_DEST_ID_MASK;
        dest_mode = !!(pirq_dpci->gmsi.gflags & VMSI_DM_MASK);
        dest_vcpu_id = hvm_girq_dest_2_vcpu_id(d, dest, dest_mode);
        pirq_dpci->gmsi.dest_vcpu_id = dest_vcpu_id;
        spin_unlock(&d->event_lock);
        if ( dest_vcpu_id >= 0 )
            hvm_migrate_pirqs(d->vcpu[dest_vcpu_id]);
    }
    else
    {
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
        list_add_tail(&digl->list, &pirq_dpci->digl_list);

        girq->device = device;
        girq->intx = intx;
        girq->machine_gsi = pirq;
        list_add_tail(&girq->list, &hvm_irq_dpci->girq[guest_gsi]);

        /* Bind the same mirq once in the same domain */
        if ( !(pirq_dpci->flags & HVM_IRQ_DPCI_MAPPED) )
        {
            unsigned int share;

            pirq_dpci->dom = d;
            if ( pt_irq_bind->irq_type == PT_IRQ_TYPE_MSI_TRANSLATE )
            {
                pirq_dpci->flags = HVM_IRQ_DPCI_MAPPED |
                                   HVM_IRQ_DPCI_MACH_MSI |
                                   HVM_IRQ_DPCI_GUEST_PCI |
                                   HVM_IRQ_DPCI_TRANSLATE;
                share = 0;
            }
            else    /* PT_IRQ_TYPE_PCI */
            {
                pirq_dpci->flags = HVM_IRQ_DPCI_MAPPED |
                                   HVM_IRQ_DPCI_MACH_PCI |
                                   HVM_IRQ_DPCI_GUEST_PCI;
                share = BIND_PIRQ__WILL_SHARE;
            }

            /* Init timer before binding */
            if ( pt_irq_need_timer(pirq_dpci->flags) )
                init_timer(&pirq_dpci->timer, pt_irq_time_out, pirq_dpci, 0);
            /* Deal with gsi for legacy devices */
            rc = pirq_guest_bind(d->vcpu[0], info, share);
            if ( unlikely(rc) )
            {
                if ( pt_irq_need_timer(pirq_dpci->flags) )
                    kill_timer(&pirq_dpci->timer);
                pirq_dpci->dom = NULL;
                list_del(&girq->list);
                xfree(girq);
                list_del(&digl->list);
                hvm_irq_dpci->link_cnt[link]--;
                pirq_dpci->flags = 0;
                pirq_cleanup_check(info, d);
                spin_unlock(&d->event_lock);
                xfree(digl);
                return rc;
            }
        }

        spin_unlock(&d->event_lock);

        if ( iommu_verbose )
            dprintk(VTDPREFIX,
                    "d%d: bind: m_gsi=%u g_gsi=%u device=%u intx=%u\n",
                    d->domain_id, pirq, guest_gsi, device, intx);
    }
    return 0;
}

int pt_irq_destroy_bind_vtd(
    struct domain *d, xen_domctl_bind_pt_irq_t *pt_irq_bind)
{
    struct hvm_irq_dpci *hvm_irq_dpci = NULL;
    struct hvm_pirq_dpci *pirq_dpci;
    uint32_t machine_gsi, guest_gsi;
    uint32_t device, intx, link;
    struct dev_intx_gsi_link *digl, *tmp;
    struct hvm_girq_dpci_mapping *girq;
    struct pirq *pirq;

    machine_gsi = pt_irq_bind->machine_irq;
    device = pt_irq_bind->u.pci.device;
    intx = pt_irq_bind->u.pci.intx;
    guest_gsi = hvm_pci_intx_gsi(device, intx);
    link = hvm_pci_intx_link(device, intx);

    if ( iommu_verbose )
        dprintk(VTDPREFIX,
                "d%d: unbind: m_gsi=%u g_gsi=%u device=%u intx=%u\n",
                d->domain_id, machine_gsi, guest_gsi, device, intx);

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

    pirq = pirq_info(d, machine_gsi);
    pirq_dpci = pirq_dpci(pirq);

    /* clear the mirq info */
    if ( pirq_dpci && (pirq_dpci->flags & HVM_IRQ_DPCI_MAPPED) )
    {
        list_for_each_entry_safe ( digl, tmp, &pirq_dpci->digl_list, list )
        {
            if ( digl->device == device &&
                 digl->intx   == intx &&
                 digl->link   == link &&
                 digl->gsi    == guest_gsi )
            {
                list_del(&digl->list);
                xfree(digl);
            }
        }

        if ( list_empty(&pirq_dpci->digl_list) )
        {
            pirq_guest_unbind(d, pirq);
            msixtbl_pt_unregister(d, pirq);
            if ( pt_irq_need_timer(pirq_dpci->flags) )
                kill_timer(&pirq_dpci->timer);
            pirq_dpci->dom   = NULL;
            pirq_dpci->flags = 0;
            pirq_cleanup_check(pirq, d);
        }
    }
    spin_unlock(&d->event_lock);

    if ( iommu_verbose )
        dprintk(VTDPREFIX,
                "d%d unmap: m_irq=%u device=%u intx=%u\n",
                d->domain_id, machine_gsi, device, intx);

    return 0;
}

void pt_pirq_init(struct domain *d, struct hvm_pirq_dpci *dpci)
{
    INIT_LIST_HEAD(&dpci->digl_list);
    dpci->gmsi.dest_vcpu_id = -1;
}

bool_t pt_pirq_cleanup_check(struct hvm_pirq_dpci *dpci)
{
    return !dpci->flags;
}

int pt_pirq_iterate(struct domain *d,
                    int (*cb)(struct domain *,
                              struct hvm_pirq_dpci *, void *),
                    void *arg)
{
    int rc = 0;
    unsigned int pirq = 0, n, i;
    struct pirq *pirqs[8];

    ASSERT(spin_is_locked(&d->event_lock));

    do {
        n = radix_tree_gang_lookup(&d->pirq_tree, (void **)pirqs, pirq,
                                   ARRAY_SIZE(pirqs));
        for ( i = 0; i < n; ++i )
        {
            struct hvm_pirq_dpci *pirq_dpci = pirq_dpci(pirqs[i]);

            pirq = pirqs[i]->pirq;
            if ( (pirq_dpci->flags & HVM_IRQ_DPCI_MAPPED) )
                rc = cb(d, pirq_dpci, arg);
        }
    } while ( !rc && ++pirq < d->nr_pirqs && n == ARRAY_SIZE(pirqs) );

    return rc;
}

int hvm_do_IRQ_dpci(struct domain *d, struct pirq *pirq)
{
    struct hvm_irq_dpci *dpci = domain_get_irq_dpci(d);
    struct hvm_pirq_dpci *pirq_dpci = pirq_dpci(pirq);

    if ( !iommu_enabled || !dpci || !pirq_dpci ||
         !(pirq_dpci->flags & HVM_IRQ_DPCI_MAPPED) )
        return 0;

    pirq_dpci->masked = 1;
    tasklet_schedule(&dpci->dirq_tasklet);
    return 1;
}

/* called with d->event_lock held */
static void __msi_pirq_eoi(struct hvm_pirq_dpci *pirq_dpci)
{
    irq_desc_t *desc;

    if ( (pirq_dpci->flags & HVM_IRQ_DPCI_MAPPED) &&
         (pirq_dpci->flags & HVM_IRQ_DPCI_MACH_MSI) )
    {
        struct pirq *pirq = dpci_pirq(pirq_dpci);

        BUG_ON(!local_irq_is_enabled());
        desc = pirq_spin_lock_irq_desc(pirq, NULL);
        if ( !desc )
            return;
        desc_guest_eoi(desc, pirq);
    }
}

static int _hvm_dpci_msi_eoi(struct domain *d,
                             struct hvm_pirq_dpci *pirq_dpci, void *arg)
{
    int vector = (long)arg;

    if ( (pirq_dpci->flags & HVM_IRQ_DPCI_MACH_MSI) &&
         (pirq_dpci->gmsi.gvec == vector) )
    {
        int dest = pirq_dpci->gmsi.gflags & VMSI_DEST_ID_MASK;
        int dest_mode = !!(pirq_dpci->gmsi.gflags & VMSI_DM_MASK);

        if ( vlapic_match_dest(vcpu_vlapic(current), NULL, 0, dest,
                               dest_mode) )
        {
            __msi_pirq_eoi(pirq_dpci);
            return 1;
        }
    }

    return 0;
}

void hvm_dpci_msi_eoi(struct domain *d, int vector)
{
    if ( !iommu_enabled || !d->arch.hvm_domain.irq.dpci )
       return;

    spin_lock(&d->event_lock);
    pt_pirq_iterate(d, _hvm_dpci_msi_eoi, (void *)(long)vector);
    spin_unlock(&d->event_lock);
}

static void hvm_pci_msi_assert(
    struct domain *d, struct hvm_pirq_dpci *pirq_dpci)
{
    struct pirq *pirq = dpci_pirq(pirq_dpci);

    if ( hvm_domain_use_pirq(d, pirq) )
        send_guest_pirq(d, pirq);
    else
        vmsi_deliver_pirq(d, pirq_dpci);
}

static int _hvm_dirq_assist(struct domain *d, struct hvm_pirq_dpci *pirq_dpci,
                            void *arg)
{
    uint32_t device, intx;
    struct dev_intx_gsi_link *digl;

    if ( test_and_clear_bool(pirq_dpci->masked) )
    {
        if ( pirq_dpci->flags & HVM_IRQ_DPCI_GUEST_MSI )
        {
            hvm_pci_msi_assert(d, pirq_dpci);
            return 0;
        }

        list_for_each_entry ( digl, &pirq_dpci->digl_list, list )
        {
            struct pirq *info = dpci_pirq(pirq_dpci);

            device = digl->device;
            intx = digl->intx;
            if ( hvm_domain_use_pirq(d, info) )
                send_guest_pirq(d, info);
            else
                hvm_pci_intx_assert(d, device, intx);
            pirq_dpci->pending++;

            if ( pirq_dpci->flags & HVM_IRQ_DPCI_TRANSLATE )
            {
                /* for translated MSI to INTx interrupt, eoi as early as possible */
                __msi_pirq_eoi(pirq_dpci);
            }
        }

        /*
         * Set a timer to see if the guest can finish the interrupt or not. For
         * example, the guest OS may unmask the PIC during boot, before the
         * guest driver is loaded. hvm_pci_intx_assert() may succeed, but the
         * guest will never deal with the irq, then the physical interrupt line
         * will never be deasserted.
         */
        if ( pt_irq_need_timer(pirq_dpci->flags) )
            set_timer(&pirq_dpci->timer, NOW() + PT_IRQ_TIME_OUT);
    }

    return 0;
}

static void hvm_dirq_assist(unsigned long _d)
{
    struct domain *d = (struct domain *)_d;

    ASSERT(d->arch.hvm_domain.irq.dpci);

    spin_lock(&d->event_lock);
    pt_pirq_iterate(d, _hvm_dirq_assist, NULL);
    spin_unlock(&d->event_lock);
}

static void __hvm_dpci_eoi(struct domain *d,
                           struct hvm_girq_dpci_mapping *girq,
                           union vioapic_redir_entry *ent)
{
    uint32_t device, intx;
    struct pirq *pirq;
    struct hvm_pirq_dpci *pirq_dpci;

    device = girq->device;
    intx = girq->intx;
    hvm_pci_intx_deassert(d, device, intx);

    pirq = pirq_info(d, girq->machine_gsi);
    pirq_dpci = pirq_dpci(pirq);

    /*
     * No need to get vector lock for timer
     * since interrupt is still not EOIed
     */
    if ( --pirq_dpci->pending ||
         ( ent && ent->fields.mask ) ||
         ! pt_irq_need_timer(pirq_dpci->flags) )
        return;

    stop_timer(&pirq_dpci->timer);
    pirq_guest_eoi(pirq);
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
        __hvm_dpci_eoi(d, girq, ent);

unlock:
    spin_unlock(&d->event_lock);
}

static int __init setup_mmio_ro_ranges(void)
{
    mmio_ro_ranges = rangeset_new(NULL, "r/o mmio ranges",
                                  RANGESETF_prettyprint_hex);
    return 0;
}
__initcall(setup_mmio_ro_ranges);
