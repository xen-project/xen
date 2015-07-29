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
 * this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) Allen Kay <allen.m.kay@intel.com>
 * Copyright (C) Xiaohui Xin <xiaohui.xin@intel.com>
 */

#include <xen/event.h>
#include <xen/iommu.h>
#include <xen/cpu.h>
#include <xen/irq.h>
#include <asm/hvm/irq.h>
#include <asm/hvm/iommu.h>
#include <asm/hvm/support.h>
#include <xen/hvm/irq.h>

static DEFINE_PER_CPU(struct list_head, dpci_list);

/*
 * These two bit states help to safely schedule, deschedule, and wait until
 * the softirq has finished.
 *
 * The semantics behind these two bits is as follow:
 *  - STATE_SCHED - whoever modifies it has to ref-count the domain (->dom).
 *  - STATE_RUN - only softirq is allowed to set and clear it. If it has
 *      been set hvm_dirq_assist will RUN with a saved value of the
 *      'struct domain' copied from 'pirq_dpci->dom' before STATE_RUN was set.
 *
 * The usual states are: STATE_SCHED(set) -> STATE_RUN(set) ->
 * STATE_SCHED(unset) -> STATE_RUN(unset).
 *
 * However the states can also diverge such as: STATE_SCHED(set) ->
 * STATE_SCHED(unset) -> STATE_RUN(set) -> STATE_RUN(unset). That means
 * the 'hvm_dirq_assist' never run and that the softirq did not do any
 * ref-counting.
 */

enum {
    STATE_SCHED,
    STATE_RUN
};

/*
 * This can be called multiple times, but the softirq is only raised once.
 * That is until the STATE_SCHED state has been cleared. The state can be
 * cleared by: the 'dpci_softirq' (when it has executed 'hvm_dirq_assist'),
 * or by 'pt_pirq_softirq_reset' (which will try to clear the state before
 * the softirq had a chance to run).
 */
static void raise_softirq_for(struct hvm_pirq_dpci *pirq_dpci)
{
    unsigned long flags;

    if ( test_and_set_bit(STATE_SCHED, &pirq_dpci->state) )
        return;

    get_knownalive_domain(pirq_dpci->dom);

    local_irq_save(flags);
    list_add_tail(&pirq_dpci->softirq_list, &this_cpu(dpci_list));
    local_irq_restore(flags);

    raise_softirq(HVM_DPCI_SOFTIRQ);
}

/*
 * If we are racing with softirq_dpci (STATE_SCHED) we return
 * true. Otherwise we return false.
 *
 * If it is false, it is the callers responsibility to make sure
 * that the softirq (with the event_lock dropped) has ran.
 */
bool_t pt_pirq_softirq_active(struct hvm_pirq_dpci *pirq_dpci)
{
    if ( pirq_dpci->state & ((1 << STATE_RUN) | (1 << STATE_SCHED)) )
        return 1;

    /*
     * If in the future we would call 'raise_softirq_for' right away
     * after 'pt_pirq_softirq_active' we MUST reset the list (otherwise it
     * might have stale data).
     */
    return 0;
}

/*
 * Reset the pirq_dpci->dom parameter to NULL.
 *
 * This function checks the different states to make sure it can do it
 * at the right time. If it unschedules the 'hvm_dirq_assist' from running
 * it also refcounts (which is what the softirq would have done) properly.
 */
static void pt_pirq_softirq_reset(struct hvm_pirq_dpci *pirq_dpci)
{
    struct domain *d = pirq_dpci->dom;

    ASSERT(spin_is_locked(&d->event_lock));

    switch ( cmpxchg(&pirq_dpci->state, 1 << STATE_SCHED, 0) )
    {
    case (1 << STATE_SCHED):
        /*
         * We are going to try to de-schedule the softirq before it goes in
         * STATE_RUN. Whoever clears STATE_SCHED MUST refcount the 'dom'.
         */
        put_domain(d);
        /* fallthrough. */
    case (1 << STATE_RUN):
    case (1 << STATE_RUN) | (1 << STATE_SCHED):
        /*
         * The reason it is OK to reset 'dom' when STATE_RUN bit is set is due
         * to a shortcut the 'dpci_softirq' implements. It stashes the 'dom'
         * in local variable before it sets STATE_RUN - and therefore will not
         * dereference '->dom' which would crash.
         */
        pirq_dpci->dom = NULL;
        break;
    }
    /*
     * Inhibit 'hvm_dirq_assist' from doing anything useful and at worst
     * calling 'set_timer' which will blow up (as we have called kill_timer
     * or never initialized it). Note that we hold the lock that
     * 'hvm_dirq_assist' could be spinning on.
     */
    pirq_dpci->masked = 0;
}

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
    const struct hvm_irq_dpci *dpci;
    const struct dev_intx_gsi_link *digl;

    spin_lock(&irq_map->dom->event_lock);

    dpci = domain_get_irq_dpci(irq_map->dom);
    ASSERT(dpci);
    list_for_each_entry ( digl, &irq_map->digl_list, list )
    {
        unsigned int guest_gsi = hvm_pci_intx_gsi(digl->device, digl->intx);
        const struct hvm_girq_dpci_mapping *girq;

        list_for_each_entry ( girq, &dpci->girq[guest_gsi], list )
        {
            struct pirq *pirq = pirq_info(irq_map->dom, girq->machine_gsi);

            pirq_dpci(pirq)->flags |= HVM_IRQ_DPCI_EOI_LATCH;
        }
        hvm_pci_intx_deassert(irq_map->dom, digl->device, digl->intx);
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

int pt_irq_create_bind(
    struct domain *d, xen_domctl_bind_pt_irq_t *pt_irq_bind)
{
    struct hvm_irq_dpci *hvm_irq_dpci;
    struct hvm_pirq_dpci *pirq_dpci;
    struct pirq *info;
    int rc, pirq = pt_irq_bind->machine_irq;

    if ( pirq < 0 || pirq >= d->nr_pirqs )
        return -EINVAL;

 restart:
    spin_lock(&d->event_lock);

    hvm_irq_dpci = domain_get_irq_dpci(d);
    if ( hvm_irq_dpci == NULL )
    {
        unsigned int i;

        hvm_irq_dpci = xzalloc(struct hvm_irq_dpci);
        if ( hvm_irq_dpci == NULL )
        {
            spin_unlock(&d->event_lock);
            return -ENOMEM;
        }
        for ( i = 0; i < NR_HVM_IRQS; i++ )
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

    /*
     * A crude 'while' loop with us dropping the spinlock and giving
     * the softirq_dpci a chance to run.
     * We MUST check for this condition as the softirq could be scheduled
     * and hasn't run yet. Note that this code replaced tasklet_kill which
     * would have spun forever and would do the same thing (wait to flush out
     * outstanding hvm_dirq_assist calls.
     */
    if ( pt_pirq_softirq_active(pirq_dpci) )
    {
        spin_unlock(&d->event_lock);
        cpu_relax();
        goto restart;
    }

    switch ( pt_irq_bind->irq_type )
    {
    case PT_IRQ_TYPE_MSI:
    {
        uint8_t dest, dest_mode;
        int dest_vcpu_id;

        if ( !(pirq_dpci->flags & HVM_IRQ_DPCI_MAPPED) )
        {
            pirq_dpci->flags = HVM_IRQ_DPCI_MAPPED | HVM_IRQ_DPCI_MACH_MSI |
                               HVM_IRQ_DPCI_GUEST_MSI;
            pirq_dpci->gmsi.gvec = pt_irq_bind->u.msi.gvec;
            pirq_dpci->gmsi.gflags = pt_irq_bind->u.msi.gflags;
            /*
             * 'pt_irq_create_bind' can be called after 'pt_irq_destroy_bind'.
             * The 'pirq_cleanup_check' which would free the structure is only
             * called if the event channel for the PIRQ is active. However
             * OS-es that use event channels usually bind PIRQs to eventds
             * and unbind them before calling 'pt_irq_destroy_bind' - with the
             * result that we re-use the 'dpci' structure. This can be
             * reproduced with unloading and loading the driver for a device.
             *
             * As such on every 'pt_irq_create_bind' call we MUST set it.
             */
            pirq_dpci->dom = d;
            /* bind after hvm_irq_dpci is setup to avoid race with irq handler*/
            rc = pirq_guest_bind(d->vcpu[0], info, 0);
            if ( rc == 0 && pt_irq_bind->u.msi.gtable )
            {
                rc = msixtbl_pt_register(d, info, pt_irq_bind->u.msi.gtable);
                if ( unlikely(rc) )
                {
                    pirq_guest_unbind(d, info);
                    /*
                     * Between 'pirq_guest_bind' and before 'pirq_guest_unbind'
                     * an interrupt can be scheduled. No more of them are going
                     * to be scheduled but we must deal with the one that may be
                     * in the queue.
                     */
                    pt_pirq_softirq_reset(pirq_dpci);
                }
            }
            if ( unlikely(rc) )
            {
                pirq_dpci->gmsi.gflags = 0;
                pirq_dpci->gmsi.gvec = 0;
                pirq_dpci->dom = NULL;
                pirq_dpci->flags = 0;
                pirq_cleanup_check(info, d);
                spin_unlock(&d->event_lock);
                return rc;
            }
        }
        else
        {
            uint32_t mask = HVM_IRQ_DPCI_MACH_MSI | HVM_IRQ_DPCI_GUEST_MSI;

            if ( (pirq_dpci->flags & mask) != mask )
            {
                spin_unlock(&d->event_lock);
                return -EBUSY;
            }

            /* If pirq is already mapped as vmsi, update guest data/addr. */
            if ( pirq_dpci->gmsi.gvec != pt_irq_bind->u.msi.gvec ||
                 pirq_dpci->gmsi.gflags != pt_irq_bind->u.msi.gflags )
            {
                /* Directly clear pending EOIs before enabling new MSI info. */
                pirq_guest_eoi(info);

                pirq_dpci->gmsi.gvec = pt_irq_bind->u.msi.gvec;
                pirq_dpci->gmsi.gflags = pt_irq_bind->u.msi.gflags;
            }
        }
        /* Calculate dest_vcpu_id for MSI-type pirq migration. */
        dest = pirq_dpci->gmsi.gflags & VMSI_DEST_ID_MASK;
        dest_mode = !!(pirq_dpci->gmsi.gflags & VMSI_DM_MASK);
        dest_vcpu_id = hvm_girq_dest_2_vcpu_id(d, dest, dest_mode);
        pirq_dpci->gmsi.dest_vcpu_id = dest_vcpu_id;
        spin_unlock(&d->event_lock);
        if ( dest_vcpu_id >= 0 )
            hvm_migrate_pirqs(d->vcpu[dest_vcpu_id]);
        break;
    }

    case PT_IRQ_TYPE_PCI:
    case PT_IRQ_TYPE_MSI_TRANSLATE:
    {
        unsigned int bus = pt_irq_bind->u.pci.bus;
        unsigned int device = pt_irq_bind->u.pci.device;
        unsigned int intx = pt_irq_bind->u.pci.intx;
        unsigned int guest_gsi = hvm_pci_intx_gsi(device, intx);
        unsigned int link = hvm_pci_intx_link(device, intx);
        struct dev_intx_gsi_link *digl = xmalloc(struct dev_intx_gsi_link);
        struct hvm_girq_dpci_mapping *girq =
            xmalloc(struct hvm_girq_dpci_mapping);

        if ( !digl || !girq )
        {
            spin_unlock(&d->event_lock);
            xfree(girq);
            xfree(digl);
            return -ENOMEM;
        }

        hvm_irq_dpci->link_cnt[link]++;

        digl->bus = bus;
        digl->device = device;
        digl->intx = intx;
        list_add_tail(&digl->list, &pirq_dpci->digl_list);

        girq->bus = bus;
        girq->device = device;
        girq->intx = intx;
        girq->machine_gsi = pirq;
        list_add_tail(&girq->list, &hvm_irq_dpci->girq[guest_gsi]);

        /* Bind the same mirq once in the same domain */
        if ( !(pirq_dpci->flags & HVM_IRQ_DPCI_MAPPED) )
        {
            unsigned int share;

            /* MUST be set, as the pirq_dpci can be re-used. */
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
                /*
                 * There is no path for __do_IRQ to schedule softirq as
                 * IRQ_GUEST is not set. As such we can reset 'dom' directly.
                 */
                pirq_dpci->dom = NULL;
                list_del(&girq->list);
                list_del(&digl->list);
                hvm_irq_dpci->link_cnt[link]--;
                pirq_dpci->flags = 0;
                pirq_cleanup_check(info, d);
                spin_unlock(&d->event_lock);
                xfree(girq);
                xfree(digl);
                return rc;
            }
        }

        spin_unlock(&d->event_lock);

        if ( iommu_verbose )
            dprintk(XENLOG_G_INFO,
                    "d%d: bind: m_gsi=%u g_gsi=%u dev=%02x.%02x.%u intx=%u\n",
                    d->domain_id, pirq, guest_gsi, bus,
                    PCI_SLOT(device), PCI_FUNC(device), intx);
        break;
    }

    default:
        spin_unlock(&d->event_lock);
        return -EOPNOTSUPP;
    }

    return 0;
}

int pt_irq_destroy_bind(
    struct domain *d, xen_domctl_bind_pt_irq_t *pt_irq_bind)
{
    struct hvm_irq_dpci *hvm_irq_dpci;
    struct hvm_pirq_dpci *pirq_dpci;
    unsigned int machine_gsi = pt_irq_bind->machine_irq;
    struct pirq *pirq;
    const char *what = NULL;

    switch ( pt_irq_bind->irq_type )
    {
    case PT_IRQ_TYPE_PCI:
    case PT_IRQ_TYPE_MSI_TRANSLATE:
        if ( iommu_verbose )
        {
            unsigned int device = pt_irq_bind->u.pci.device;
            unsigned int intx = pt_irq_bind->u.pci.intx;

            dprintk(XENLOG_G_INFO,
                    "d%d: unbind: m_gsi=%u g_gsi=%u dev=%02x:%02x.%u intx=%u\n",
                    d->domain_id, machine_gsi, hvm_pci_intx_gsi(device, intx),
                    pt_irq_bind->u.pci.bus,
                    PCI_SLOT(device), PCI_FUNC(device), intx);
        }
        break;
    case PT_IRQ_TYPE_MSI:
        break;
    default:
        return -EOPNOTSUPP;
    }

    spin_lock(&d->event_lock);

    hvm_irq_dpci = domain_get_irq_dpci(d);

    if ( hvm_irq_dpci == NULL )
    {
        spin_unlock(&d->event_lock);
        return -EINVAL;
    }

    pirq = pirq_info(d, machine_gsi);
    pirq_dpci = pirq_dpci(pirq);

    if ( pt_irq_bind->irq_type != PT_IRQ_TYPE_MSI )
    {
        unsigned int bus = pt_irq_bind->u.pci.bus;
        unsigned int device = pt_irq_bind->u.pci.device;
        unsigned int intx = pt_irq_bind->u.pci.intx;
        unsigned int guest_gsi = hvm_pci_intx_gsi(device, intx);
        unsigned int link = hvm_pci_intx_link(device, intx);
        struct hvm_girq_dpci_mapping *girq;
        struct dev_intx_gsi_link *digl, *tmp;

        list_for_each_entry ( girq, &hvm_irq_dpci->girq[guest_gsi], list )
        {
            if ( girq->bus         == bus &&
                 girq->device      == device &&
                 girq->intx        == intx &&
                 girq->machine_gsi == machine_gsi )
            {
                list_del(&girq->list);
                xfree(girq);
                girq = NULL;
                break;
            }
        }

        if ( girq )
        {
            spin_unlock(&d->event_lock);
            return -EINVAL;
        }

        hvm_irq_dpci->link_cnt[link]--;

        /* clear the mirq info */
        if ( pirq_dpci && (pirq_dpci->flags & HVM_IRQ_DPCI_MAPPED) )
        {
            list_for_each_entry_safe ( digl, tmp, &pirq_dpci->digl_list, list )
            {
                if ( digl->bus    == bus &&
                     digl->device == device &&
                     digl->intx   == intx )
                {
                    list_del(&digl->list);
                    xfree(digl);
                }
            }
            what = list_empty(&pirq_dpci->digl_list) ? "final" : "partial";
        }
        else
            what = "bogus";
    }

    if ( pirq_dpci && (pirq_dpci->flags & HVM_IRQ_DPCI_MAPPED) &&
         list_empty(&pirq_dpci->digl_list) )
    {
        pirq_guest_unbind(d, pirq);
        msixtbl_pt_unregister(d, pirq);
        if ( pt_irq_need_timer(pirq_dpci->flags) )
            kill_timer(&pirq_dpci->timer);
        pirq_dpci->flags = 0;
        /*
         * See comment in pt_irq_create_bind's PT_IRQ_TYPE_MSI before the
         * call to pt_pirq_softirq_reset.
         */
        pt_pirq_softirq_reset(pirq_dpci);

        pirq_cleanup_check(pirq, d);
    }

    spin_unlock(&d->event_lock);

    if ( what && iommu_verbose )
    {
        unsigned int device = pt_irq_bind->u.pci.device;

        dprintk(XENLOG_G_INFO,
                "d%d %s unmap: m_irq=%u dev=%02x:%02x.%u intx=%u\n",
                d->domain_id, what, machine_gsi, pt_irq_bind->u.pci.bus,
                PCI_SLOT(device), PCI_FUNC(device), pt_irq_bind->u.pci.intx);
    }

    return 0;
}

void pt_pirq_init(struct domain *d, struct hvm_pirq_dpci *dpci)
{
    INIT_LIST_HEAD(&dpci->digl_list);
    dpci->gmsi.dest_vcpu_id = -1;
}

bool_t pt_pirq_cleanup_check(struct hvm_pirq_dpci *dpci)
{
    if ( !dpci->flags && !pt_pirq_softirq_active(dpci) )
    {
        dpci->dom = NULL;
        return 1;
    }
    return 0;
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
    raise_softirq_for(pirq_dpci);
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

static void hvm_dirq_assist(struct domain *d, struct hvm_pirq_dpci *pirq_dpci)
{
    ASSERT(d->arch.hvm_domain.irq.dpci);

    spin_lock(&d->event_lock);
    if ( test_and_clear_bool(pirq_dpci->masked) )
    {
        struct pirq *pirq = dpci_pirq(pirq_dpci);
        const struct dev_intx_gsi_link *digl;

        if ( hvm_domain_use_pirq(d, pirq) )
        {
            send_guest_pirq(d, pirq);

            if ( pirq_dpci->flags & HVM_IRQ_DPCI_GUEST_MSI )
            {
                spin_unlock(&d->event_lock);
                return;
            }
        }

        if ( pirq_dpci->flags & HVM_IRQ_DPCI_GUEST_MSI )
        {
            vmsi_deliver_pirq(d, pirq_dpci);
            spin_unlock(&d->event_lock);
            return;
        }

        list_for_each_entry ( digl, &pirq_dpci->digl_list, list )
        {
            hvm_pci_intx_assert(d, digl->device, digl->intx);
            pirq_dpci->pending++;
        }

        if ( pirq_dpci->flags & HVM_IRQ_DPCI_TRANSLATE )
        {
            /* for translated MSI to INTx interrupt, eoi as early as possible */
            __msi_pirq_eoi(pirq_dpci);
            spin_unlock(&d->event_lock);
            return;
        }

        /*
         * Set a timer to see if the guest can finish the interrupt or not. For
         * example, the guest OS may unmask the PIC during boot, before the
         * guest driver is loaded. hvm_pci_intx_assert() may succeed, but the
         * guest will never deal with the irq, then the physical interrupt line
         * will never be deasserted.
         */
        ASSERT(pt_irq_need_timer(pirq_dpci->flags));
        set_timer(&pirq_dpci->timer, NOW() + PT_IRQ_TIME_OUT);
    }
    spin_unlock(&d->event_lock);
}

static void __hvm_dpci_eoi(struct domain *d,
                           const struct hvm_girq_dpci_mapping *girq,
                           const union vioapic_redir_entry *ent)
{
    struct pirq *pirq = pirq_info(d, girq->machine_gsi);
    struct hvm_pirq_dpci *pirq_dpci;

    if ( !hvm_domain_use_pirq(d, pirq) )
        hvm_pci_intx_deassert(d, girq->device, girq->intx);

    pirq_dpci = pirq_dpci(pirq);

    /*
     * No need to get vector lock for timer
     * since interrupt is still not EOIed
     */
    if ( --pirq_dpci->pending ||
         (ent && ent->fields.mask) ||
         !pt_irq_need_timer(pirq_dpci->flags) )
        return;

    stop_timer(&pirq_dpci->timer);
    pirq_guest_eoi(pirq);
}

void hvm_dpci_eoi(struct domain *d, unsigned int guest_gsi,
                  const union vioapic_redir_entry *ent)
{
    const struct hvm_irq_dpci *hvm_irq_dpci;
    const struct hvm_girq_dpci_mapping *girq;

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

/*
 * Note: 'pt_pirq_softirq_reset' can clear the STATE_SCHED before we get to
 * doing it. If that is the case we let 'pt_pirq_softirq_reset' do ref-counting.
 */
static void dpci_softirq(void)
{
    unsigned int cpu = smp_processor_id();
    LIST_HEAD(our_list);

    local_irq_disable();
    list_splice_init(&per_cpu(dpci_list, cpu), &our_list);
    local_irq_enable();

    while ( !list_empty(&our_list) )
    {
        struct hvm_pirq_dpci *pirq_dpci;
        struct domain *d;

        pirq_dpci = list_entry(our_list.next, struct hvm_pirq_dpci, softirq_list);
        list_del(&pirq_dpci->softirq_list);

        d = pirq_dpci->dom;
        smp_mb(); /* 'd' MUST be saved before we set/clear the bits. */
        if ( test_and_set_bit(STATE_RUN, &pirq_dpci->state) )
        {
            unsigned long flags;

            /* Put back on the list and retry. */
            local_irq_save(flags);
            list_add_tail(&pirq_dpci->softirq_list, &this_cpu(dpci_list));
            local_irq_restore(flags);

            raise_softirq(HVM_DPCI_SOFTIRQ);
            continue;
        }
        /*
         * The one who clears STATE_SCHED MUST refcount the domain.
         */
        if ( test_and_clear_bit(STATE_SCHED, &pirq_dpci->state) )
        {
            hvm_dirq_assist(d, pirq_dpci);
            put_domain(d);
        }
        clear_bit(STATE_RUN, &pirq_dpci->state);
    }
}

static int cpu_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    unsigned int cpu = (unsigned long)hcpu;

    switch ( action )
    {
    case CPU_UP_PREPARE:
        INIT_LIST_HEAD(&per_cpu(dpci_list, cpu));
        break;
    case CPU_UP_CANCELED:
    case CPU_DEAD:
        /*
         * On CPU_DYING this callback is called (on the CPU that is dying)
         * with an possible HVM_DPIC_SOFTIRQ pending - at which point we can
         * clear out any outstanding domains (by the virtue of the idle loop
         * calling the softirq later). In CPU_DEAD case the CPU is deaf and
         * there are no pending softirqs for us to handle so we can chill.
         */
        ASSERT(list_empty(&per_cpu(dpci_list, cpu)));
        break;
    }

    return NOTIFY_DONE;
}

static struct notifier_block cpu_nfb = {
    .notifier_call = cpu_callback,
};

static int __init setup_dpci_softirq(void)
{
    unsigned int cpu;

    for_each_online_cpu(cpu)
        INIT_LIST_HEAD(&per_cpu(dpci_list, cpu));

    open_softirq(HVM_DPCI_SOFTIRQ, dpci_softirq);
    register_cpu_notifier(&cpu_nfb);
    return 0;
}
__initcall(setup_dpci_softirq);
