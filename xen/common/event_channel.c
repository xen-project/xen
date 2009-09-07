/******************************************************************************
 * event_channel.c
 * 
 * Event notifications from VIRQs, PIRQs, and other domains.
 * 
 * Copyright (c) 2003-2006, K A Fraser.
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

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <xen/irq.h>
#include <xen/iocap.h>
#include <xen/compat.h>
#include <xen/guest_access.h>
#include <xen/keyhandler.h>
#include <asm/current.h>

#include <public/xen.h>
#include <public/event_channel.h>
#include <xsm/xsm.h>

#define bucket_from_port(d,p) \
    ((d)->evtchn[(p)/EVTCHNS_PER_BUCKET])
#define port_is_valid(d,p)    \
    (((p) >= 0) && ((p) < MAX_EVTCHNS(d)) && \
     (bucket_from_port(d,p) != NULL))
#define evtchn_from_port(d,p) \
    (&(bucket_from_port(d,p))[(p)&(EVTCHNS_PER_BUCKET-1)])

#define ERROR_EXIT(_errno)                                          \
    do {                                                            \
        gdprintk(XENLOG_WARNING,                                    \
                "EVTCHNOP failure: error %d\n",                     \
                (_errno));                                          \
        rc = (_errno);                                              \
        goto out;                                                   \
    } while ( 0 )
#define ERROR_EXIT_DOM(_errno, _dom)                                \
    do {                                                            \
        gdprintk(XENLOG_WARNING,                                    \
                "EVTCHNOP failure: domain %d, error %d\n",          \
                (_dom)->domain_id, (_errno));                       \
        rc = (_errno);                                              \
        goto out;                                                   \
    } while ( 0 )

static int evtchn_set_pending(struct vcpu *v, int port);

static int virq_is_global(int virq)
{
    int rc;

    ASSERT((virq >= 0) && (virq < NR_VIRQS));

    switch ( virq )
    {
    case VIRQ_TIMER:
    case VIRQ_DEBUG:
    case VIRQ_XENOPROF:
        rc = 0;
        break;
    case VIRQ_ARCH_0 ... VIRQ_ARCH_7:
        rc = arch_virq_is_global(virq);
        break;
    default:
        rc = 1;
        break;
    }

    return rc;
}


static int get_free_port(struct domain *d)
{
    struct evtchn *chn;
    int            port;
    int            i, j;

    if ( d->is_dying )
        return -EINVAL;

    for ( port = 0; port_is_valid(d, port); port++ )
        if ( evtchn_from_port(d, port)->state == ECS_FREE )
            return port;

    if ( port == MAX_EVTCHNS(d) )
        return -ENOSPC;

    chn = xmalloc_array(struct evtchn, EVTCHNS_PER_BUCKET);
    if ( unlikely(chn == NULL) )
        return -ENOMEM;
    memset(chn, 0, EVTCHNS_PER_BUCKET * sizeof(*chn));
    bucket_from_port(d, port) = chn;

    for ( i = 0; i < EVTCHNS_PER_BUCKET; i++ )
    {
        if ( xsm_alloc_security_evtchn(&chn[i]) )
        {
            for ( j = 0; j < i; j++ )
                xsm_free_security_evtchn(&chn[j]);
            xfree(chn);
            return -ENOMEM;
        }
    }

    return port;
}


static long evtchn_alloc_unbound(evtchn_alloc_unbound_t *alloc)
{
    struct evtchn *chn;
    struct domain *d;
    int            port;
    domid_t        dom = alloc->dom;
    long           rc;

    rc = rcu_lock_target_domain_by_id(dom, &d);
    if ( rc )
        return rc;

    spin_lock(&d->event_lock);

    if ( (port = get_free_port(d)) < 0 )
        ERROR_EXIT_DOM(port, d);
    chn = evtchn_from_port(d, port);

    rc = xsm_evtchn_unbound(d, chn, alloc->remote_dom);
    if ( rc )
        goto out;

    chn->state = ECS_UNBOUND;
    if ( (chn->u.unbound.remote_domid = alloc->remote_dom) == DOMID_SELF )
        chn->u.unbound.remote_domid = current->domain->domain_id;

    alloc->port = port;

 out:
    spin_unlock(&d->event_lock);
    rcu_unlock_domain(d);

    return rc;
}


static long evtchn_bind_interdomain(evtchn_bind_interdomain_t *bind)
{
    struct evtchn *lchn, *rchn;
    struct domain *ld = current->domain, *rd;
    int            lport, rport = bind->remote_port;
    domid_t        rdom = bind->remote_dom;
    long           rc;

    if ( rdom == DOMID_SELF )
        rdom = current->domain->domain_id;

    if ( (rd = rcu_lock_domain_by_id(rdom)) == NULL )
        return -ESRCH;

    /* Avoid deadlock by first acquiring lock of domain with smaller id. */
    if ( ld < rd )
    {
        spin_lock(&ld->event_lock);
        spin_lock(&rd->event_lock);
    }
    else
    {
        if ( ld != rd )
            spin_lock(&rd->event_lock);
        spin_lock(&ld->event_lock);
    }

    if ( (lport = get_free_port(ld)) < 0 )
        ERROR_EXIT(lport);
    lchn = evtchn_from_port(ld, lport);

    if ( !port_is_valid(rd, rport) )
        ERROR_EXIT_DOM(-EINVAL, rd);
    rchn = evtchn_from_port(rd, rport);
    if ( (rchn->state != ECS_UNBOUND) ||
         (rchn->u.unbound.remote_domid != ld->domain_id) )
        ERROR_EXIT_DOM(-EINVAL, rd);

    rc = xsm_evtchn_interdomain(ld, lchn, rd, rchn);
    if ( rc )
        goto out;

    lchn->u.interdomain.remote_dom  = rd;
    lchn->u.interdomain.remote_port = (u16)rport;
    lchn->state                     = ECS_INTERDOMAIN;
    
    rchn->u.interdomain.remote_dom  = ld;
    rchn->u.interdomain.remote_port = (u16)lport;
    rchn->state                     = ECS_INTERDOMAIN;

    /*
     * We may have lost notifications on the remote unbound port. Fix that up
     * here by conservatively always setting a notification on the local port.
     */
    evtchn_set_pending(ld->vcpu[lchn->notify_vcpu_id], lport);

    bind->local_port = lport;

 out:
    spin_unlock(&ld->event_lock);
    if ( ld != rd )
        spin_unlock(&rd->event_lock);
    
    rcu_unlock_domain(rd);

    return rc;
}


static long evtchn_bind_virq(evtchn_bind_virq_t *bind)
{
    struct evtchn *chn;
    struct vcpu   *v;
    struct domain *d = current->domain;
    int            port, virq = bind->virq, vcpu = bind->vcpu;
    long           rc = 0;

    if ( (virq < 0) || (virq >= ARRAY_SIZE(v->virq_to_evtchn)) )
        return -EINVAL;

    if ( virq_is_global(virq) && (vcpu != 0) )
        return -EINVAL;

    if ( (vcpu < 0) || (vcpu >= d->max_vcpus) ||
         ((v = d->vcpu[vcpu]) == NULL) )
        return -ENOENT;

    if ( unlikely(!v->vcpu_info) )
        return -EAGAIN;

    spin_lock(&d->event_lock);

    if ( v->virq_to_evtchn[virq] != 0 )
        ERROR_EXIT(-EEXIST);

    if ( (port = get_free_port(d)) < 0 )
        ERROR_EXIT(port);

    chn = evtchn_from_port(d, port);
    chn->state          = ECS_VIRQ;
    chn->notify_vcpu_id = vcpu;
    chn->u.virq         = virq;

    v->virq_to_evtchn[virq] = bind->port = port;

 out:
    spin_unlock(&d->event_lock);

    return rc;
}


static long evtchn_bind_ipi(evtchn_bind_ipi_t *bind)
{
    struct evtchn *chn;
    struct domain *d = current->domain;
    int            port, vcpu = bind->vcpu;
    long           rc = 0;

    if ( (vcpu < 0) || (vcpu >= d->max_vcpus) ||
         (d->vcpu[vcpu] == NULL) )
        return -ENOENT;

    if ( unlikely(!d->vcpu[vcpu]->vcpu_info) )
        return -EAGAIN;

    spin_lock(&d->event_lock);

    if ( (port = get_free_port(d)) < 0 )
        ERROR_EXIT(port);

    chn = evtchn_from_port(d, port);
    chn->state          = ECS_IPI;
    chn->notify_vcpu_id = vcpu;

    bind->port = port;

 out:
    spin_unlock(&d->event_lock);

    return rc;
}


static long evtchn_bind_pirq(evtchn_bind_pirq_t *bind)
{
    struct evtchn *chn;
    struct domain *d = current->domain;
    int            port, pirq = bind->pirq;
    long           rc;

    if ( (pirq < 0) || (pirq >= d->nr_pirqs) )
        return -EINVAL;

    if ( !irq_access_permitted(d, pirq) )
        return -EPERM;

    spin_lock(&d->event_lock);

    if ( d->pirq_to_evtchn[pirq] != 0 )
        ERROR_EXIT(-EEXIST);

    if ( (port = get_free_port(d)) < 0 )
        ERROR_EXIT(port);

    chn = evtchn_from_port(d, port);

    d->pirq_to_evtchn[pirq] = port;
    rc = pirq_guest_bind(d->vcpu[0], pirq, 
                         !!(bind->flags & BIND_PIRQ__WILL_SHARE));
    if ( rc != 0 )
    {
        d->pirq_to_evtchn[pirq] = 0;
        goto out;
    }

    chn->state  = ECS_PIRQ;
    chn->u.pirq = pirq;

    bind->port = port;

 out:
    spin_unlock(&d->event_lock);

    return rc;
}


static long __evtchn_close(struct domain *d1, int port1)
{
    struct domain *d2 = NULL;
    struct vcpu   *v;
    struct evtchn *chn1, *chn2;
    int            port2;
    long           rc = 0;

 again:
    spin_lock(&d1->event_lock);

    if ( !port_is_valid(d1, port1) )
    {
        rc = -EINVAL;
        goto out;
    }

    chn1 = evtchn_from_port(d1, port1);

    /* Guest cannot close a Xen-attached event channel. */
    if ( unlikely(chn1->consumer_is_xen) )
    {
        rc = -EINVAL;
        goto out;
    }

    switch ( chn1->state )
    {
    case ECS_FREE:
    case ECS_RESERVED:
        rc = -EINVAL;
        goto out;

    case ECS_UNBOUND:
        break;

    case ECS_PIRQ:
        pirq_guest_unbind(d1, chn1->u.pirq);
        d1->pirq_to_evtchn[chn1->u.pirq] = 0;
        break;

    case ECS_VIRQ:
        for_each_vcpu ( d1, v )
        {
            if ( v->virq_to_evtchn[chn1->u.virq] != port1 )
                continue;
            v->virq_to_evtchn[chn1->u.virq] = 0;
            spin_barrier_irq(&v->virq_lock);
        }
        break;

    case ECS_IPI:
        break;

    case ECS_INTERDOMAIN:
        if ( d2 == NULL )
        {
            d2 = chn1->u.interdomain.remote_dom;

            /* If we unlock d1 then we could lose d2. Must get a reference. */
            if ( unlikely(!get_domain(d2)) )
                BUG();

            if ( d1 < d2 )
            {
                spin_lock(&d2->event_lock);
            }
            else if ( d1 != d2 )
            {
                spin_unlock(&d1->event_lock);
                spin_lock(&d2->event_lock);
                goto again;
            }
        }
        else if ( d2 != chn1->u.interdomain.remote_dom )
        {
            /*
             * We can only get here if the port was closed and re-bound after
             * unlocking d1 but before locking d2 above. We could retry but
             * it is easier to return the same error as if we had seen the
             * port in ECS_CLOSED. It must have passed through that state for
             * us to end up here, so it's a valid error to return.
             */
            rc = -EINVAL;
            goto out;
        }

        port2 = chn1->u.interdomain.remote_port;
        BUG_ON(!port_is_valid(d2, port2));

        chn2 = evtchn_from_port(d2, port2);
        BUG_ON(chn2->state != ECS_INTERDOMAIN);
        BUG_ON(chn2->u.interdomain.remote_dom != d1);

        chn2->state = ECS_UNBOUND;
        chn2->u.unbound.remote_domid = d1->domain_id;
        break;

    default:
        BUG();
    }

    /* Clear pending event to avoid unexpected behavior on re-bind. */
    clear_bit(port1, &shared_info(d1, evtchn_pending));

    /* Reset binding to vcpu0 when the channel is freed. */
    chn1->state          = ECS_FREE;
    chn1->notify_vcpu_id = 0;

    xsm_evtchn_close_post(chn1);

 out:
    if ( d2 != NULL )
    {
        if ( d1 != d2 )
            spin_unlock(&d2->event_lock);
        put_domain(d2);
    }

    spin_unlock(&d1->event_lock);

    return rc;
}


static long evtchn_close(evtchn_close_t *close)
{
    return __evtchn_close(current->domain, close->port);
}

int evtchn_send(struct domain *d, unsigned int lport)
{
    struct evtchn *lchn, *rchn;
    struct domain *ld = d, *rd;
    struct vcpu   *rvcpu;
    int            rport, ret = 0;

    spin_lock(&ld->event_lock);

    if ( unlikely(!port_is_valid(ld, lport)) )
    {
        spin_unlock(&ld->event_lock);
        return -EINVAL;
    }

    lchn = evtchn_from_port(ld, lport);

    /* Guest cannot send via a Xen-attached event channel. */
    if ( unlikely(lchn->consumer_is_xen) )
    {
        spin_unlock(&ld->event_lock);
        return -EINVAL;
    }

    ret = xsm_evtchn_send(ld, lchn);
    if ( ret )
        goto out;

    switch ( lchn->state )
    {
    case ECS_INTERDOMAIN:
        rd    = lchn->u.interdomain.remote_dom;
        rport = lchn->u.interdomain.remote_port;
        rchn  = evtchn_from_port(rd, rport);
        rvcpu = rd->vcpu[rchn->notify_vcpu_id];
        if ( rchn->consumer_is_xen )
        {
            /* Xen consumers need notification only if they are blocked. */
            if ( test_and_clear_bit(_VPF_blocked_in_xen,
                                    &rvcpu->pause_flags) )
                vcpu_wake(rvcpu);
        }
        else
        {
            evtchn_set_pending(rvcpu, rport);
        }
        break;
    case ECS_IPI:
        evtchn_set_pending(ld->vcpu[lchn->notify_vcpu_id], lport);
        break;
    case ECS_UNBOUND:
        /* silently drop the notification */
        break;
    default:
        ret = -EINVAL;
    }

out:
    spin_unlock(&ld->event_lock);

    return ret;
}

static int evtchn_set_pending(struct vcpu *v, int port)
{
    struct domain *d = v->domain;
    int vcpuid;

    /*
     * The following bit operations must happen in strict order.
     * NB. On x86, the atomic bit operations also act as memory barriers.
     * There is therefore sufficiently strict ordering for this architecture --
     * others may require explicit memory barriers.
     */

    if ( test_and_set_bit(port, &shared_info(d, evtchn_pending)) )
        return 1;

    if ( !test_bit        (port, &shared_info(d, evtchn_mask)) &&
         !test_and_set_bit(port / BITS_PER_EVTCHN_WORD(d),
                           &vcpu_info(v, evtchn_pending_sel)) )
    {
        vcpu_mark_events_pending(v);
    }
    
    /* Check if some VCPU might be polling for this event. */
    if ( likely(bitmap_empty(d->poll_mask, d->max_vcpus)) )
        return 0;

    /* Wake any interested (or potentially interested) pollers. */
    for ( vcpuid = find_first_bit(d->poll_mask, d->max_vcpus);
          vcpuid < d->max_vcpus;
          vcpuid = find_next_bit(d->poll_mask, d->max_vcpus, vcpuid+1) )
    {
        v = d->vcpu[vcpuid];
        if ( ((v->poll_evtchn <= 0) || (v->poll_evtchn == port)) &&
             test_and_clear_bit(vcpuid, d->poll_mask) )
        {
            v->poll_evtchn = 0;
            vcpu_unblock(v);
        }
    }

    return 0;
}

int guest_enabled_event(struct vcpu *v, int virq)
{
    return ((v != NULL) && (v->virq_to_evtchn[virq] != 0));
}

void send_guest_vcpu_virq(struct vcpu *v, int virq)
{
    unsigned long flags;
    int port;

    ASSERT(!virq_is_global(virq));

    spin_lock_irqsave(&v->virq_lock, flags);

    port = v->virq_to_evtchn[virq];
    if ( unlikely(port == 0) )
        goto out;

    evtchn_set_pending(v, port);

 out:
    spin_unlock_irqrestore(&v->virq_lock, flags);
}

void send_guest_global_virq(struct domain *d, int virq)
{
    unsigned long flags;
    int port;
    struct vcpu *v;
    struct evtchn *chn;

    ASSERT(virq_is_global(virq));

    if ( unlikely(d == NULL) || unlikely(d->vcpu == NULL) )
        return;

    v = d->vcpu[0];
    if ( unlikely(v == NULL) )
        return;

    spin_lock_irqsave(&v->virq_lock, flags);

    port = v->virq_to_evtchn[virq];
    if ( unlikely(port == 0) )
        goto out;

    chn = evtchn_from_port(d, port);
    evtchn_set_pending(d->vcpu[chn->notify_vcpu_id], port);

 out:
    spin_unlock_irqrestore(&v->virq_lock, flags);
}

int send_guest_pirq(struct domain *d, int pirq)
{
    int port = d->pirq_to_evtchn[pirq];
    struct evtchn *chn;

    /*
     * It should not be possible to race with __evtchn_close():
     * The caller of this function must synchronise with pirq_guest_unbind().
     */
    ASSERT(port != 0);

    chn = evtchn_from_port(d, port);
    return evtchn_set_pending(d->vcpu[chn->notify_vcpu_id], port);
}


static long evtchn_status(evtchn_status_t *status)
{
    struct domain   *d;
    domid_t          dom = status->dom;
    int              port = status->port;
    struct evtchn   *chn;
    long             rc = 0;

    rc = rcu_lock_target_domain_by_id(dom, &d);
    if ( rc )
        return rc;

    spin_lock(&d->event_lock);

    if ( !port_is_valid(d, port) )
    {
        rc = -EINVAL;
        goto out;
    }

    chn = evtchn_from_port(d, port);

    rc = xsm_evtchn_status(d, chn);
    if ( rc )
        goto out;

    switch ( chn->state )
    {
    case ECS_FREE:
    case ECS_RESERVED:
        status->status = EVTCHNSTAT_closed;
        break;
    case ECS_UNBOUND:
        status->status = EVTCHNSTAT_unbound;
        status->u.unbound.dom = chn->u.unbound.remote_domid;
        break;
    case ECS_INTERDOMAIN:
        status->status = EVTCHNSTAT_interdomain;
        status->u.interdomain.dom  =
            chn->u.interdomain.remote_dom->domain_id;
        status->u.interdomain.port = chn->u.interdomain.remote_port;
        break;
    case ECS_PIRQ:
        status->status = EVTCHNSTAT_pirq;
        status->u.pirq = chn->u.pirq;
        break;
    case ECS_VIRQ:
        status->status = EVTCHNSTAT_virq;
        status->u.virq = chn->u.virq;
        break;
    case ECS_IPI:
        status->status = EVTCHNSTAT_ipi;
        break;
    default:
        BUG();
    }

    status->vcpu = chn->notify_vcpu_id;

 out:
    spin_unlock(&d->event_lock);
    rcu_unlock_domain(d);

    return rc;
}


long evtchn_bind_vcpu(unsigned int port, unsigned int vcpu_id)
{
    struct domain *d = current->domain;
    struct evtchn *chn;
    long           rc = 0;

    if ( (vcpu_id >= d->max_vcpus) || (d->vcpu[vcpu_id] == NULL) )
        return -ENOENT;

    if ( unlikely(!d->vcpu[vcpu_id]->vcpu_info) )
        return -EAGAIN;

    spin_lock(&d->event_lock);

    if ( !port_is_valid(d, port) )
    {
        rc = -EINVAL;
        goto out;
    }

    chn = evtchn_from_port(d, port);

    /* Guest cannot re-bind a Xen-attached event channel. */
    if ( unlikely(chn->consumer_is_xen) )
    {
        rc = -EINVAL;
        goto out;
    }

    switch ( chn->state )
    {
    case ECS_VIRQ:
        if ( virq_is_global(chn->u.virq) )
            chn->notify_vcpu_id = vcpu_id;
        else
            rc = -EINVAL;
        break;
    case ECS_UNBOUND:
    case ECS_INTERDOMAIN:
    case ECS_PIRQ:
        chn->notify_vcpu_id = vcpu_id;
        break;
    default:
        rc = -EINVAL;
        break;
    }

 out:
    spin_unlock(&d->event_lock);

    return rc;
}


int evtchn_unmask(unsigned int port)
{
    struct domain *d = current->domain;
    struct vcpu   *v;

    spin_lock(&d->event_lock);

    if ( unlikely(!port_is_valid(d, port)) )
    {
        spin_unlock(&d->event_lock);
        return -EINVAL;
    }

    v = d->vcpu[evtchn_from_port(d, port)->notify_vcpu_id];

    /*
     * These operations must happen in strict order. Based on
     * include/xen/event.h:evtchn_set_pending(). 
     */
    if ( test_and_clear_bit(port, &shared_info(d, evtchn_mask)) &&
         test_bit          (port, &shared_info(d, evtchn_pending)) &&
         !test_and_set_bit (port / BITS_PER_EVTCHN_WORD(d),
                            &vcpu_info(v, evtchn_pending_sel)) )
    {
        vcpu_mark_events_pending(v);
    }

    spin_unlock(&d->event_lock);

    return 0;
}


static long evtchn_reset(evtchn_reset_t *r)
{
    domid_t dom = r->dom;
    struct domain *d;
    int i, rc;

    rc = rcu_lock_target_domain_by_id(dom, &d);
    if ( rc )
        return rc;

    rc = xsm_evtchn_reset(current->domain, d);
    if ( rc )
        goto out;

    for ( i = 0; port_is_valid(d, i); i++ )
        (void)__evtchn_close(d, i);

    rc = 0;

out:
    rcu_unlock_domain(d);

    return rc;
}


long do_event_channel_op(int cmd, XEN_GUEST_HANDLE(void) arg)
{
    long rc;

    switch ( cmd )
    {
    case EVTCHNOP_alloc_unbound: {
        struct evtchn_alloc_unbound alloc_unbound;
        if ( copy_from_guest(&alloc_unbound, arg, 1) != 0 )
            return -EFAULT;
        rc = evtchn_alloc_unbound(&alloc_unbound);
        if ( (rc == 0) && (copy_to_guest(arg, &alloc_unbound, 1) != 0) )
            rc = -EFAULT; /* Cleaning up here would be a mess! */
        break;
    }

    case EVTCHNOP_bind_interdomain: {
        struct evtchn_bind_interdomain bind_interdomain;
        if ( copy_from_guest(&bind_interdomain, arg, 1) != 0 )
            return -EFAULT;
        rc = evtchn_bind_interdomain(&bind_interdomain);
        if ( (rc == 0) && (copy_to_guest(arg, &bind_interdomain, 1) != 0) )
            rc = -EFAULT; /* Cleaning up here would be a mess! */
        break;
    }

    case EVTCHNOP_bind_virq: {
        struct evtchn_bind_virq bind_virq;
        if ( copy_from_guest(&bind_virq, arg, 1) != 0 )
            return -EFAULT;
        rc = evtchn_bind_virq(&bind_virq);
        if ( (rc == 0) && (copy_to_guest(arg, &bind_virq, 1) != 0) )
            rc = -EFAULT; /* Cleaning up here would be a mess! */
        break;
    }

    case EVTCHNOP_bind_ipi: {
        struct evtchn_bind_ipi bind_ipi;
        if ( copy_from_guest(&bind_ipi, arg, 1) != 0 )
            return -EFAULT;
        rc = evtchn_bind_ipi(&bind_ipi);
        if ( (rc == 0) && (copy_to_guest(arg, &bind_ipi, 1) != 0) )
            rc = -EFAULT; /* Cleaning up here would be a mess! */
        break;
    }

    case EVTCHNOP_bind_pirq: {
        struct evtchn_bind_pirq bind_pirq;
        if ( copy_from_guest(&bind_pirq, arg, 1) != 0 )
            return -EFAULT;
        rc = evtchn_bind_pirq(&bind_pirq);
        if ( (rc == 0) && (copy_to_guest(arg, &bind_pirq, 1) != 0) )
            rc = -EFAULT; /* Cleaning up here would be a mess! */
        break;
    }

    case EVTCHNOP_close: {
        struct evtchn_close close;
        if ( copy_from_guest(&close, arg, 1) != 0 )
            return -EFAULT;
        rc = evtchn_close(&close);
        break;
    }

    case EVTCHNOP_send: {
        struct evtchn_send send;
        if ( copy_from_guest(&send, arg, 1) != 0 )
            return -EFAULT;
        rc = evtchn_send(current->domain, send.port);
        break;
    }

    case EVTCHNOP_status: {
        struct evtchn_status status;
        if ( copy_from_guest(&status, arg, 1) != 0 )
            return -EFAULT;
        rc = evtchn_status(&status);
        if ( (rc == 0) && (copy_to_guest(arg, &status, 1) != 0) )
            rc = -EFAULT;
        break;
    }

    case EVTCHNOP_bind_vcpu: {
        struct evtchn_bind_vcpu bind_vcpu;
        if ( copy_from_guest(&bind_vcpu, arg, 1) != 0 )
            return -EFAULT;
        rc = evtchn_bind_vcpu(bind_vcpu.port, bind_vcpu.vcpu);
        break;
    }

    case EVTCHNOP_unmask: {
        struct evtchn_unmask unmask;
        if ( copy_from_guest(&unmask, arg, 1) != 0 )
            return -EFAULT;
        rc = evtchn_unmask(unmask.port);
        break;
    }

    case EVTCHNOP_reset: {
        struct evtchn_reset reset;
        if ( copy_from_guest(&reset, arg, 1) != 0 )
            return -EFAULT;
        rc = evtchn_reset(&reset);
        break;
    }

    default:
        rc = -ENOSYS;
        break;
    }

    return rc;
}


int alloc_unbound_xen_event_channel(
    struct vcpu *local_vcpu, domid_t remote_domid)
{
    struct evtchn *chn;
    struct domain *d = local_vcpu->domain;
    int            port;

    if ( unlikely(!local_vcpu->vcpu_info) )
        return -EAGAIN;

    spin_lock(&d->event_lock);

    if ( (port = get_free_port(d)) < 0 )
        goto out;
    chn = evtchn_from_port(d, port);

    chn->state = ECS_UNBOUND;
    chn->consumer_is_xen = 1;
    chn->notify_vcpu_id = local_vcpu->vcpu_id;
    chn->u.unbound.remote_domid = remote_domid;

 out:
    spin_unlock(&d->event_lock);

    return port;
}


void free_xen_event_channel(
    struct vcpu *local_vcpu, int port)
{
    struct evtchn *chn;
    struct domain *d = local_vcpu->domain;

    spin_lock(&d->event_lock);

    if ( unlikely(d->is_dying) )
    {
        spin_unlock(&d->event_lock);
        return;
    }

    BUG_ON(!port_is_valid(d, port));
    chn = evtchn_from_port(d, port);
    BUG_ON(!chn->consumer_is_xen);
    chn->consumer_is_xen = 0;

    spin_unlock(&d->event_lock);

    (void)__evtchn_close(d, port);
}


void notify_via_xen_event_channel(int lport)
{
    struct evtchn *lchn, *rchn;
    struct domain *ld = current->domain, *rd;
    int            rport;

    spin_lock(&ld->event_lock);

    ASSERT(port_is_valid(ld, lport));
    lchn = evtchn_from_port(ld, lport);
    ASSERT(lchn->consumer_is_xen);

    if ( likely(lchn->state == ECS_INTERDOMAIN) )
    {
        rd    = lchn->u.interdomain.remote_dom;
        rport = lchn->u.interdomain.remote_port;
        rchn  = evtchn_from_port(rd, rport);
        evtchn_set_pending(rd->vcpu[rchn->notify_vcpu_id], rport);
    }

    spin_unlock(&ld->event_lock);
}


int evtchn_init(struct domain *d)
{
    spin_lock_init(&d->event_lock);
    if ( get_free_port(d) != 0 )
        return -EINVAL;
    evtchn_from_port(d, 0)->state = ECS_RESERVED;

#if MAX_VIRT_CPUS > BITS_PER_LONG
    d->poll_mask = xmalloc_array(unsigned long, BITS_TO_LONGS(MAX_VIRT_CPUS));
    if ( !d->poll_mask )
        return -ENOMEM;
    bitmap_zero(d->poll_mask, MAX_VIRT_CPUS);
#endif

    return 0;
}


void evtchn_destroy(struct domain *d)
{
    int i;

    /* After this barrier no new event-channel allocations can occur. */
    BUG_ON(!d->is_dying);
    spin_barrier(&d->event_lock);

    /* Close all existing event channels. */
    for ( i = 0; port_is_valid(d, i); i++ )
    {
        evtchn_from_port(d, i)->consumer_is_xen = 0;
        (void)__evtchn_close(d, i);
    }

    /* Free all event-channel buckets. */
    spin_lock(&d->event_lock);
    for ( i = 0; i < NR_EVTCHN_BUCKETS; i++ )
    {
        xsm_free_security_evtchn(d->evtchn[i]);
        xfree(d->evtchn[i]);
        d->evtchn[i] = NULL;
    }
    spin_unlock(&d->event_lock);

#if MAX_VIRT_CPUS > BITS_PER_LONG
    xfree(d->poll_mask);
    d->poll_mask = NULL;
#endif
}

static void domain_dump_evtchn_info(struct domain *d)
{
    unsigned int port;

    printk("Domain %d polling vCPUs: %08lx\n", d->domain_id, d->poll_mask[0]);

    if ( !spin_trylock(&d->event_lock) )
        return;

    printk("Event channel information for domain %d:\n"
           "    port [p/m]\n", d->domain_id);

    for ( port = 1; port < MAX_EVTCHNS(d); ++port )
    {
        const struct evtchn *chn;

        if ( !port_is_valid(d, port) )
            continue;
        chn = evtchn_from_port(d, port);
        if ( chn->state == ECS_FREE )
            continue;

        printk("    %4u [%d/%d]: s=%d n=%d",
               port,
               !!test_bit(port, &shared_info(d, evtchn_pending)),
               !!test_bit(port, &shared_info(d, evtchn_mask)),
               chn->state, chn->notify_vcpu_id);
        switch ( chn->state )
        {
        case ECS_UNBOUND:
            printk(" d=%d", chn->u.unbound.remote_domid);
            break;
        case ECS_INTERDOMAIN:
            printk(" d=%d p=%d",
                   chn->u.interdomain.remote_dom->domain_id,
                   chn->u.interdomain.remote_port);
            break;
        case ECS_PIRQ:
            printk(" p=%d", chn->u.pirq);
            break;
        case ECS_VIRQ:
            printk(" v=%d", chn->u.virq);
            break;
        }
        printk(" x=%d\n", chn->consumer_is_xen);
    }

    spin_unlock(&d->event_lock);
}

static void dump_evtchn_info(unsigned char key)
{
    struct domain *d;

    printk("'%c' pressed -> dumping event-channel info\n", key);

    rcu_read_lock(&domlist_read_lock);

    for_each_domain ( d )
        domain_dump_evtchn_info(d);

    rcu_read_unlock(&domlist_read_lock);
}

static struct keyhandler dump_evtchn_info_keyhandler = {
    .diagnostic = 1,
    .u.fn = dump_evtchn_info,
    .desc = "dump evtchn info"
};

static int __init dump_evtchn_info_key_init(void)
{
    register_keyhandler('e', &dump_evtchn_info_keyhandler);
    return 0;
}
__initcall(dump_evtchn_info_key_init);

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
