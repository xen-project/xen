/******************************************************************************
 * mem_event.c
 *
 * Memory event support.
 *
 * Copyright (c) 2009 Citrix Systems, Inc. (Patrick Colp)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#include <xen/sched.h>
#include <xen/event.h>
#include <xen/wait.h>
#include <xen/mem_event.h>
#include <xen/mem_access.h>
#include <asm/p2m.h>

#ifdef HAS_MEM_PAGING
#include <asm/mem_paging.h>
#endif

#ifdef HAS_MEM_SHARING
#include <asm/mem_sharing.h>
#endif

#include <xsm/xsm.h>

/* for public/io/ring.h macros */
#define xen_mb()   mb()
#define xen_rmb()  rmb()
#define xen_wmb()  wmb()

#define mem_event_ring_lock_init(_med)  spin_lock_init(&(_med)->ring_lock)
#define mem_event_ring_lock(_med)       spin_lock(&(_med)->ring_lock)
#define mem_event_ring_unlock(_med)     spin_unlock(&(_med)->ring_lock)

static int mem_event_enable(
    struct domain *d,
    xen_domctl_mem_event_op_t *mec,
    struct mem_event_domain *med,
    int pause_flag,
    int param,
    xen_event_channel_notification_t notification_fn)
{
    int rc;
    unsigned long ring_gfn = d->arch.hvm_domain.params[param];

    /* Only one helper at a time. If the helper crashed,
     * the ring is in an undefined state and so is the guest.
     */
    if ( med->ring_page )
        return -EBUSY;

    /* The parameter defaults to zero, and it should be
     * set to something */
    if ( ring_gfn == 0 )
        return -ENOSYS;

    mem_event_ring_lock_init(med);
    mem_event_ring_lock(med);

    rc = prepare_ring_for_helper(d, ring_gfn, &med->ring_pg_struct,
                                    &med->ring_page);
    if ( rc < 0 )
        goto err;

    /* Set the number of currently blocked vCPUs to 0. */
    med->blocked = 0;

    /* Allocate event channel */
    rc = alloc_unbound_xen_event_channel(d->vcpu[0],
                                         current->domain->domain_id,
                                         notification_fn);
    if ( rc < 0 )
        goto err;

    med->xen_port = mec->port = rc;

    /* Prepare ring buffer */
    FRONT_RING_INIT(&med->front_ring,
                    (mem_event_sring_t *)med->ring_page,
                    PAGE_SIZE);

    /* Save the pause flag for this particular ring. */
    med->pause_flag = pause_flag;

    /* Initialize the last-chance wait queue. */
    init_waitqueue_head(&med->wq);

    mem_event_ring_unlock(med);
    return 0;

 err:
    destroy_ring_for_helper(&med->ring_page,
                            med->ring_pg_struct);
    mem_event_ring_unlock(med);

    return rc;
}

static unsigned int mem_event_ring_available(struct mem_event_domain *med)
{
    int avail_req = RING_FREE_REQUESTS(&med->front_ring);
    avail_req -= med->target_producers;
    avail_req -= med->foreign_producers;

    BUG_ON(avail_req < 0);

    return avail_req;
}

/*
 * mem_event_wake_blocked() will wakeup vcpus waiting for room in the
 * ring. These vCPUs were paused on their way out after placing an event,
 * but need to be resumed where the ring is capable of processing at least
 * one event from them.
 */
static void mem_event_wake_blocked(struct domain *d, struct mem_event_domain *med)
{
    struct vcpu *v;
    int online = d->max_vcpus;
    unsigned int avail_req = mem_event_ring_available(med);

    if ( avail_req == 0 || med->blocked == 0 )
        return;

    /*
     * We ensure that we only have vCPUs online if there are enough free slots
     * for their memory events to be processed.  This will ensure that no
     * memory events are lost (due to the fact that certain types of events
     * cannot be replayed, we need to ensure that there is space in the ring
     * for when they are hit).
     * See comment below in mem_event_put_request().
     */
    for_each_vcpu ( d, v )
        if ( test_bit(med->pause_flag, &v->pause_flags) )
            online--;

    ASSERT(online == (d->max_vcpus - med->blocked));

    /* We remember which vcpu last woke up to avoid scanning always linearly
     * from zero and starving higher-numbered vcpus under high load */
    if ( d->vcpu )
    {
        int i, j, k;

        for (i = med->last_vcpu_wake_up + 1, j = 0; j < d->max_vcpus; i++, j++)
        {
            k = i % d->max_vcpus;
            v = d->vcpu[k];
            if ( !v )
                continue;

            if ( !(med->blocked) || online >= avail_req )
               break;

            if ( test_and_clear_bit(med->pause_flag, &v->pause_flags) )
            {
                vcpu_unpause(v);
                online++;
                med->blocked--;
                med->last_vcpu_wake_up = k;
            }
        }
    }
}

/*
 * In the event that a vCPU attempted to place an event in the ring and
 * was unable to do so, it is queued on a wait queue.  These are woken as
 * needed, and take precedence over the blocked vCPUs.
 */
static void mem_event_wake_queued(struct domain *d, struct mem_event_domain *med)
{
    unsigned int avail_req = mem_event_ring_available(med);

    if ( avail_req > 0 )
        wake_up_nr(&med->wq, avail_req);
}

/*
 * mem_event_wake() will wakeup all vcpus waiting for the ring to
 * become available.  If we have queued vCPUs, they get top priority. We
 * are guaranteed that they will go through code paths that will eventually
 * call mem_event_wake() again, ensuring that any blocked vCPUs will get
 * unpaused once all the queued vCPUs have made it through.
 */
void mem_event_wake(struct domain *d, struct mem_event_domain *med)
{
    if (!list_empty(&med->wq.list))
        mem_event_wake_queued(d, med);
    else
        mem_event_wake_blocked(d, med);
}

static int mem_event_disable(struct domain *d, struct mem_event_domain *med)
{
    if ( med->ring_page )
    {
        struct vcpu *v;

        mem_event_ring_lock(med);

        if ( !list_empty(&med->wq.list) )
        {
            mem_event_ring_unlock(med);
            return -EBUSY;
        }

        /* Free domU's event channel and leave the other one unbound */
        free_xen_event_channel(d->vcpu[0], med->xen_port);

        /* Unblock all vCPUs */
        for_each_vcpu ( d, v )
        {
            if ( test_and_clear_bit(med->pause_flag, &v->pause_flags) )
            {
                vcpu_unpause(v);
                med->blocked--;
            }
        }

        destroy_ring_for_helper(&med->ring_page,
                                med->ring_pg_struct);
        mem_event_ring_unlock(med);
    }

    return 0;
}

static inline void mem_event_release_slot(struct domain *d,
                                          struct mem_event_domain *med)
{
    /* Update the accounting */
    if ( current->domain == d )
        med->target_producers--;
    else
        med->foreign_producers--;

    /* Kick any waiters */
    mem_event_wake(d, med);
}

/*
 * mem_event_mark_and_pause() tags vcpu and put it to sleep.
 * The vcpu will resume execution in mem_event_wake_waiters().
 */
void mem_event_mark_and_pause(struct vcpu *v, struct mem_event_domain *med)
{
    if ( !test_and_set_bit(med->pause_flag, &v->pause_flags) )
    {
        vcpu_pause_nosync(v);
        med->blocked++;
    }
}

/*
 * This must be preceded by a call to claim_slot(), and is guaranteed to
 * succeed.  As a side-effect however, the vCPU may be paused if the ring is
 * overly full and its continued execution would cause stalling and excessive
 * waiting.  The vCPU will be automatically unpaused when the ring clears.
 */
void mem_event_put_request(struct domain *d,
                           struct mem_event_domain *med,
                           mem_event_request_t *req)
{
    mem_event_front_ring_t *front_ring;
    int free_req;
    unsigned int avail_req;
    RING_IDX req_prod;

    if ( current->domain != d )
    {
        req->flags |= MEM_EVENT_FLAG_FOREIGN;
#ifndef NDEBUG
        if ( !(req->flags & MEM_EVENT_FLAG_VCPU_PAUSED) )
            gdprintk(XENLOG_G_WARNING, "d%dv%d was not paused.\n",
                     d->domain_id, req->vcpu_id);
#endif
    }

    mem_event_ring_lock(med);

    /* Due to the reservations, this step must succeed. */
    front_ring = &med->front_ring;
    free_req = RING_FREE_REQUESTS(front_ring);
    ASSERT(free_req > 0);

    /* Copy request */
    req_prod = front_ring->req_prod_pvt;
    memcpy(RING_GET_REQUEST(front_ring, req_prod), req, sizeof(*req));
    req_prod++;

    /* Update ring */
    front_ring->req_prod_pvt = req_prod;
    RING_PUSH_REQUESTS(front_ring);

    /* We've actually *used* our reservation, so release the slot. */
    mem_event_release_slot(d, med);

    /* Give this vCPU a black eye if necessary, on the way out.
     * See the comments above wake_blocked() for more information
     * on how this mechanism works to avoid waiting. */
    avail_req = mem_event_ring_available(med);
    if( current->domain == d && avail_req < d->max_vcpus )
        mem_event_mark_and_pause(current, med);

    mem_event_ring_unlock(med);

    notify_via_xen_event_channel(d, med->xen_port);
}

int mem_event_get_response(struct domain *d, struct mem_event_domain *med, mem_event_response_t *rsp)
{
    mem_event_front_ring_t *front_ring;
    RING_IDX rsp_cons;

    mem_event_ring_lock(med);

    front_ring = &med->front_ring;
    rsp_cons = front_ring->rsp_cons;

    if ( !RING_HAS_UNCONSUMED_RESPONSES(front_ring) )
    {
        mem_event_ring_unlock(med);
        return 0;
    }

    /* Copy response */
    memcpy(rsp, RING_GET_RESPONSE(front_ring, rsp_cons), sizeof(*rsp));
    rsp_cons++;

    /* Update ring */
    front_ring->rsp_cons = rsp_cons;
    front_ring->sring->rsp_event = rsp_cons + 1;

    /* Kick any waiters -- since we've just consumed an event,
     * there may be additional space available in the ring. */
    mem_event_wake(d, med);

    mem_event_ring_unlock(med);

    return 1;
}

void mem_event_cancel_slot(struct domain *d, struct mem_event_domain *med)
{
    mem_event_ring_lock(med);
    mem_event_release_slot(d, med);
    mem_event_ring_unlock(med);
}

static int mem_event_grab_slot(struct mem_event_domain *med, int foreign)
{
    unsigned int avail_req;

    if ( !med->ring_page )
        return -ENOSYS;

    mem_event_ring_lock(med);

    avail_req = mem_event_ring_available(med);
    if ( avail_req == 0 )
    {
        mem_event_ring_unlock(med);
        return -EBUSY;
    }

    if ( !foreign )
        med->target_producers++;
    else
        med->foreign_producers++;

    mem_event_ring_unlock(med);

    return 0;
}

/* Simple try_grab wrapper for use in the wait_event() macro. */
static int mem_event_wait_try_grab(struct mem_event_domain *med, int *rc)
{
    *rc = mem_event_grab_slot(med, 0);
    return *rc;
}

/* Call mem_event_grab_slot() until the ring doesn't exist, or is available. */
static int mem_event_wait_slot(struct mem_event_domain *med)
{
    int rc = -EBUSY;
    wait_event(med->wq, mem_event_wait_try_grab(med, &rc) != -EBUSY);
    return rc;
}

bool_t mem_event_check_ring(struct mem_event_domain *med)
{
    return (med->ring_page != NULL);
}

/*
 * Determines whether or not the current vCPU belongs to the target domain,
 * and calls the appropriate wait function.  If it is a guest vCPU, then we
 * use mem_event_wait_slot() to reserve a slot.  As long as there is a ring,
 * this function will always return 0 for a guest.  For a non-guest, we check
 * for space and return -EBUSY if the ring is not available.
 *
 * Return codes: -ENOSYS: the ring is not yet configured
 *               -EBUSY: the ring is busy
 *               0: a spot has been reserved
 *
 */
int __mem_event_claim_slot(struct domain *d, struct mem_event_domain *med,
                            bool_t allow_sleep)
{
    if ( (current->domain == d) && allow_sleep )
        return mem_event_wait_slot(med);
    else
        return mem_event_grab_slot(med, (current->domain != d));
}

#ifdef HAS_MEM_PAGING
/* Registered with Xen-bound event channel for incoming notifications. */
static void mem_paging_notification(struct vcpu *v, unsigned int port)
{
    if ( likely(v->domain->mem_event->paging.ring_page != NULL) )
        p2m_mem_paging_resume(v->domain);
}
#endif

#ifdef HAS_MEM_ACCESS
/* Registered with Xen-bound event channel for incoming notifications. */
static void mem_access_notification(struct vcpu *v, unsigned int port)
{
    if ( likely(v->domain->mem_event->access.ring_page != NULL) )
        mem_access_resume(v->domain);
}
#endif

#ifdef HAS_MEM_SHARING
/* Registered with Xen-bound event channel for incoming notifications. */
static void mem_sharing_notification(struct vcpu *v, unsigned int port)
{
    if ( likely(v->domain->mem_event->share.ring_page != NULL) )
        mem_sharing_sharing_resume(v->domain);
}
#endif

int do_mem_event_op(int op, uint32_t domain, void *arg)
{
    int ret;
    struct domain *d;

    ret = rcu_lock_live_remote_domain_by_id(domain, &d);
    if ( ret )
        return ret;

    ret = xsm_mem_event_op(XSM_DM_PRIV, d, op);
    if ( ret )
        goto out;

    switch (op)
    {
#ifdef HAS_MEM_PAGING
        case XENMEM_paging_op:
            ret = mem_paging_memop(d, (xen_mem_event_op_t *) arg);
            break;
#endif
#ifdef HAS_MEM_SHARING
        case XENMEM_sharing_op:
            ret = mem_sharing_memop(d, (xen_mem_sharing_op_t *) arg);
            break;
#endif
        default:
            ret = -ENOSYS;
    }

 out:
    rcu_unlock_domain(d);
    return ret;
}

/* Clean up on domain destruction */
void mem_event_cleanup(struct domain *d)
{
#ifdef HAS_MEM_PAGING
    if ( d->mem_event->paging.ring_page ) {
        /* Destroying the wait queue head means waking up all
         * queued vcpus. This will drain the list, allowing
         * the disable routine to complete. It will also drop
         * all domain refs the wait-queued vcpus are holding.
         * Finally, because this code path involves previously
         * pausing the domain (domain_kill), unpausing the
         * vcpus causes no harm. */
        destroy_waitqueue_head(&d->mem_event->paging.wq);
        (void)mem_event_disable(d, &d->mem_event->paging);
    }
#endif
#ifdef HAS_MEM_ACCESS
    if ( d->mem_event->access.ring_page ) {
        destroy_waitqueue_head(&d->mem_event->access.wq);
        (void)mem_event_disable(d, &d->mem_event->access);
    }
#endif
#ifdef HAS_MEM_SHARING
    if ( d->mem_event->share.ring_page ) {
        destroy_waitqueue_head(&d->mem_event->share.wq);
        (void)mem_event_disable(d, &d->mem_event->share);
    }
#endif
}

int mem_event_domctl(struct domain *d, xen_domctl_mem_event_op_t *mec,
                     XEN_GUEST_HANDLE_PARAM(void) u_domctl)
{
    int rc;

    rc = xsm_mem_event_control(XSM_PRIV, d, mec->mode, mec->op);
    if ( rc )
        return rc;

    if ( unlikely(d == current->domain) )
    {
        gdprintk(XENLOG_INFO, "Tried to do a memory event op on itself.\n");
        return -EINVAL;
    }

    if ( unlikely(d->is_dying) )
    {
        gdprintk(XENLOG_INFO, "Ignoring memory event op on dying domain %u\n",
                 d->domain_id);
        return 0;
    }

    if ( unlikely(d->vcpu == NULL) || unlikely(d->vcpu[0] == NULL) )
    {
        gdprintk(XENLOG_INFO,
                 "Memory event op on a domain (%u) with no vcpus\n",
                 d->domain_id);
        return -EINVAL;
    }

    rc = -ENOSYS;

    switch ( mec->mode )
    {
#ifdef HAS_MEM_PAGING
    case XEN_DOMCTL_MEM_EVENT_OP_PAGING:
    {
        struct mem_event_domain *med = &d->mem_event->paging;
        rc = -EINVAL;

        switch( mec->op )
        {
        case XEN_DOMCTL_MEM_EVENT_OP_PAGING_ENABLE:
        {
            struct p2m_domain *p2m = p2m_get_hostp2m(d);

            rc = -EOPNOTSUPP;
            /* pvh fixme: p2m_is_foreign types need addressing */
            if ( is_pvh_vcpu(current) || is_pvh_domain(hardware_domain) )
                break;

            rc = -ENODEV;
            /* Only HAP is supported */
            if ( !hap_enabled(d) )
                break;

            /* No paging if iommu is used */
            rc = -EMLINK;
            if ( unlikely(need_iommu(d)) )
                break;

            rc = -EXDEV;
            /* Disallow paging in a PoD guest */
            if ( p2m->pod.entry_count )
                break;

            rc = mem_event_enable(d, mec, med, _VPF_mem_paging,
                                    HVM_PARAM_PAGING_RING_PFN,
                                    mem_paging_notification);
        }
        break;

        case XEN_DOMCTL_MEM_EVENT_OP_PAGING_DISABLE:
        {
            if ( med->ring_page )
                rc = mem_event_disable(d, med);
        }
        break;

        default:
            rc = -ENOSYS;
            break;
        }
    }
    break;
#endif

#ifdef HAS_MEM_ACCESS
    case XEN_DOMCTL_MEM_EVENT_OP_ACCESS:
    {
        struct mem_event_domain *med = &d->mem_event->access;
        rc = -EINVAL;

        switch( mec->op )
        {
        case XEN_DOMCTL_MEM_EVENT_OP_ACCESS_ENABLE:
        case XEN_DOMCTL_MEM_EVENT_OP_ACCESS_ENABLE_INTROSPECTION:
        {
            rc = -ENODEV;
            if ( !p2m_mem_event_sanity_check(d) )
                break;

            rc = mem_event_enable(d, mec, med, _VPF_mem_access,
                                    HVM_PARAM_ACCESS_RING_PFN,
                                    mem_access_notification);

            if ( mec->op == XEN_DOMCTL_MEM_EVENT_OP_ACCESS_ENABLE_INTROSPECTION
                 && !rc )
                p2m_setup_introspection(d);

        }
        break;

        case XEN_DOMCTL_MEM_EVENT_OP_ACCESS_DISABLE:
        {
            if ( med->ring_page )
            {
                rc = mem_event_disable(d, med);
                d->arch.hvm_domain.introspection_enabled = 0;
            }
        }
        break;

        default:
            rc = -ENOSYS;
            break;
        }
    }
    break;
#endif

#ifdef HAS_MEM_SHARING
    case XEN_DOMCTL_MEM_EVENT_OP_SHARING:
    {
        struct mem_event_domain *med = &d->mem_event->share;
        rc = -EINVAL;

        switch( mec->op )
        {
        case XEN_DOMCTL_MEM_EVENT_OP_SHARING_ENABLE:
        {
            rc = -EOPNOTSUPP;
            /* pvh fixme: p2m_is_foreign types need addressing */
            if ( is_pvh_vcpu(current) || is_pvh_domain(hardware_domain) )
                break;

            rc = -ENODEV;
            /* Only HAP is supported */
            if ( !hap_enabled(d) )
                break;

            rc = mem_event_enable(d, mec, med, _VPF_mem_sharing,
                                    HVM_PARAM_SHARING_RING_PFN,
                                    mem_sharing_notification);
        }
        break;

        case XEN_DOMCTL_MEM_EVENT_OP_SHARING_DISABLE:
        {
            if ( med->ring_page )
                rc = mem_event_disable(d, med);
        }
        break;

        default:
            rc = -ENOSYS;
            break;
        }
    }
    break;
#endif

    default:
        rc = -ENOSYS;
    }

    return rc;
}

void mem_event_vcpu_pause(struct vcpu *v)
{
    ASSERT(v == current);

    atomic_inc(&v->mem_event_pause_count);
    vcpu_pause_nosync(v);
}

void mem_event_vcpu_unpause(struct vcpu *v)
{
    int old, new, prev = v->mem_event_pause_count.counter;

    /* All unpause requests as a result of toolstack responses.  Prevent
     * underflow of the vcpu pause count. */
    do
    {
        old = prev;
        new = old - 1;

        if ( new < 0 )
        {
            printk(XENLOG_G_WARNING
                   "%pv mem_event: Too many unpause attempts\n", v);
            return;
        }

        prev = cmpxchg(&v->mem_event_pause_count.counter, old, new);
    } while ( prev != old );

    vcpu_unpause(v);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
