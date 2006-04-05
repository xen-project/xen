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
#include <xen/guest_access.h>
#include <asm/current.h>

#include <public/xen.h>
#include <public/event_channel.h>
#include <acm/acm_hooks.h>

#define bucket_from_port(d,p) \
    ((d)->evtchn[(p)/EVTCHNS_PER_BUCKET])
#define port_is_valid(d,p)    \
    (((p) >= 0) && ((p) < MAX_EVTCHNS) && \
     (bucket_from_port(d,p) != NULL))
#define evtchn_from_port(d,p) \
    (&(bucket_from_port(d,p))[(p)&(EVTCHNS_PER_BUCKET-1)])

#define ERROR_EXIT(_errno)                                          \
    do {                                                            \
        DPRINTK("EVTCHNOP failure: domain %d, error %d, line %d\n", \
                current->domain->domain_id, (_errno), __LINE__);    \
        rc = (_errno);                                              \
        goto out;                                                   \
    } while ( 0 )


static int virq_is_global(int virq)
{
    int rc;

    ASSERT((virq >= 0) && (virq < NR_VIRQS));

    switch ( virq )
    {
    case VIRQ_TIMER:
    case VIRQ_DEBUG:
        rc = 0;
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

    for ( port = 0; port_is_valid(d, port); port++ )
        if ( evtchn_from_port(d, port)->state == ECS_FREE )
            return port;

    if ( port == MAX_EVTCHNS )
        return -ENOSPC;

    chn = xmalloc_array(struct evtchn, EVTCHNS_PER_BUCKET);
    if ( unlikely(chn == NULL) )
        return -ENOMEM;
    memset(chn, 0, EVTCHNS_PER_BUCKET * sizeof(*chn));
    bucket_from_port(d, port) = chn;

    return port;
}


static long evtchn_alloc_unbound(evtchn_alloc_unbound_t *alloc)
{
    struct evtchn *chn;
    struct domain *d;
    int            port;
    domid_t        dom = alloc->dom;
    long           rc = 0;

    if ( dom == DOMID_SELF )
        dom = current->domain->domain_id;
    else if ( !IS_PRIV(current->domain) )
        return -EPERM;

    if ( (d = find_domain_by_id(dom)) == NULL )
        return -ESRCH;

    spin_lock(&d->evtchn_lock);

    if ( (port = get_free_port(d)) < 0 )
        ERROR_EXIT(port);
    chn = evtchn_from_port(d, port);

    chn->state = ECS_UNBOUND;
    if ( (chn->u.unbound.remote_domid = alloc->remote_dom) == DOMID_SELF )
        chn->u.unbound.remote_domid = current->domain->domain_id;

    alloc->port = port;

 out:
    spin_unlock(&d->evtchn_lock);

    put_domain(d);

    return rc;
}


static long evtchn_bind_interdomain(evtchn_bind_interdomain_t *bind)
{
    struct evtchn *lchn, *rchn;
    struct domain *ld = current->domain, *rd;
    int            lport, rport = bind->remote_port;
    domid_t        rdom = bind->remote_dom;
    long           rc = 0;

    if ( rdom == DOMID_SELF )
        rdom = current->domain->domain_id;

    if ( (rd = find_domain_by_id(rdom)) == NULL )
        return -ESRCH;

    /* Avoid deadlock by first acquiring lock of domain with smaller id. */
    if ( ld < rd )
    {
        spin_lock(&ld->evtchn_lock);
        spin_lock(&rd->evtchn_lock);
    }
    else
    {
        if ( ld != rd )
            spin_lock(&rd->evtchn_lock);
        spin_lock(&ld->evtchn_lock);
    }

    if ( (lport = get_free_port(ld)) < 0 )
        ERROR_EXIT(lport);
    lchn = evtchn_from_port(ld, lport);

    if ( !port_is_valid(rd, rport) )
        ERROR_EXIT(-EINVAL);
    rchn = evtchn_from_port(rd, rport);
    if ( (rchn->state != ECS_UNBOUND) ||
         (rchn->u.unbound.remote_domid != ld->domain_id) )
        ERROR_EXIT(-EINVAL);

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
    spin_unlock(&ld->evtchn_lock);
    if ( ld != rd )
        spin_unlock(&rd->evtchn_lock);
    
    put_domain(rd);

    return rc;
}


static long evtchn_bind_virq(evtchn_bind_virq_t *bind)
{
    struct evtchn *chn;
    struct vcpu   *v;
    struct domain *d = current->domain;
    int            port, virq = bind->virq, vcpu = bind->vcpu;
    long           rc = 0;

    if ( virq >= ARRAY_SIZE(v->virq_to_evtchn) )
        return -EINVAL;

    if ( virq_is_global(virq) && (vcpu != 0) )
        return -EINVAL;

    if ( (vcpu >= ARRAY_SIZE(d->vcpu)) || ((v = d->vcpu[vcpu]) == NULL) )
        return -ENOENT;

    spin_lock(&d->evtchn_lock);

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
    spin_unlock(&d->evtchn_lock);

    return rc;
}


static long evtchn_bind_ipi(evtchn_bind_ipi_t *bind)
{
    struct evtchn *chn;
    struct domain *d = current->domain;
    int            port, vcpu = bind->vcpu;
    long           rc = 0;

    if ( (vcpu >= ARRAY_SIZE(d->vcpu)) || (d->vcpu[vcpu] == NULL) )
        return -ENOENT;

    spin_lock(&d->evtchn_lock);

    if ( (port = get_free_port(d)) < 0 )
        ERROR_EXIT(port);

    chn = evtchn_from_port(d, port);
    chn->state          = ECS_IPI;
    chn->notify_vcpu_id = vcpu;

    bind->port = port;

 out:
    spin_unlock(&d->evtchn_lock);

    return rc;
}


static long evtchn_bind_pirq(evtchn_bind_pirq_t *bind)
{
    struct evtchn *chn;
    struct domain *d = current->domain;
    int            port, pirq = bind->pirq;
    long           rc;

    if ( pirq >= ARRAY_SIZE(d->pirq_to_evtchn) )
        return -EINVAL;

    if ( !irq_access_permitted(d, pirq) )
        return -EPERM;

    spin_lock(&d->evtchn_lock);

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
    spin_unlock(&d->evtchn_lock);

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
    spin_lock(&d1->evtchn_lock);

    if ( !port_is_valid(d1, port1) )
    {
        rc = -EINVAL;
        goto out;
    }

    chn1 = evtchn_from_port(d1, port1);
    switch ( chn1->state )
    {
    case ECS_FREE:
    case ECS_RESERVED:
        rc = -EINVAL;
        goto out;

    case ECS_UNBOUND:
        break;

    case ECS_PIRQ:
        if ( (rc = pirq_guest_unbind(d1, chn1->u.pirq)) == 0 )
            d1->pirq_to_evtchn[chn1->u.pirq] = 0;
        break;

    case ECS_VIRQ:
        for_each_vcpu ( d1, v )
            if ( v->virq_to_evtchn[chn1->u.virq] == port1 )
                v->virq_to_evtchn[chn1->u.virq] = 0;
        break;

    case ECS_IPI:
        break;

    case ECS_INTERDOMAIN:
        if ( d2 == NULL )
        {
            d2 = chn1->u.interdomain.remote_dom;

            /* If we unlock d1 then we could lose d2. Must get a reference. */
            if ( unlikely(!get_domain(d2)) )
            {
                /*
                 * Failed to obtain a reference. No matter: d2 must be dying
                 * and so will close this event channel for us.
                 */
                d2 = NULL;
                goto out;
            }

            if ( d1 < d2 )
            {
                spin_lock(&d2->evtchn_lock);
            }
            else if ( d1 != d2 )
            {
                spin_unlock(&d1->evtchn_lock);
                spin_lock(&d2->evtchn_lock);
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
            BUG_ON(d1 != current->domain);
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

    /* Reset binding to vcpu0 when the channel is freed. */
    chn1->state          = ECS_FREE;
    chn1->notify_vcpu_id = 0;

 out:
    if ( d2 != NULL )
    {
        if ( d1 != d2 )
            spin_unlock(&d2->evtchn_lock);
        put_domain(d2);
    }
    
    spin_unlock(&d1->evtchn_lock);

    return rc;
}


static long evtchn_close(evtchn_close_t *close)
{
    return __evtchn_close(current->domain, close->port);
}


long evtchn_send(unsigned int lport)
{
    struct evtchn *lchn, *rchn;
    struct domain *ld = current->domain, *rd;
    int            rport, ret = 0;

    spin_lock(&ld->evtchn_lock);

    if ( unlikely(!port_is_valid(ld, lport)) )
    {
        spin_unlock(&ld->evtchn_lock);
        return -EINVAL;
    }

    lchn = evtchn_from_port(ld, lport);
    switch ( lchn->state )
    {
    case ECS_INTERDOMAIN:
        rd    = lchn->u.interdomain.remote_dom;
        rport = lchn->u.interdomain.remote_port;
        rchn  = evtchn_from_port(rd, rport);
        evtchn_set_pending(rd->vcpu[rchn->notify_vcpu_id], rport);
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

    spin_unlock(&ld->evtchn_lock);

    return ret;
}


void evtchn_set_pending(struct vcpu *v, int port)
{
    struct domain *d = v->domain;
    shared_info_t *s = d->shared_info;

    /*
     * The following bit operations must happen in strict order.
     * NB. On x86, the atomic bit operations also act as memory barriers.
     * There is therefore sufficiently strict ordering for this architecture --
     * others may require explicit memory barriers.
     */

    if ( test_and_set_bit(port, &s->evtchn_pending[0]) )
        return;

    if ( !test_bit        (port, &s->evtchn_mask[0])    &&
         !test_and_set_bit(port / BITS_PER_LONG,
                           &v->vcpu_info->evtchn_pending_sel) &&
         !test_and_set_bit(0, &v->vcpu_info->evtchn_upcall_pending) )
    {
        evtchn_notify(v);
    }
    else if ( unlikely(test_bit(_VCPUF_blocked, &v->vcpu_flags) &&
                       v->vcpu_info->evtchn_upcall_mask) )
    {
        /*
         * Blocked and masked will usually mean that the VCPU executed 
         * SCHEDOP_poll. Kick the VCPU in case this port is in its poll list.
         */
        vcpu_unblock(v);
    }
}


void send_guest_vcpu_virq(struct vcpu *v, int virq)
{
    int port;

    ASSERT(!virq_is_global(virq));

    port = v->virq_to_evtchn[virq];
    if ( unlikely(port == 0) )
        return;

    evtchn_set_pending(v, port);
}

void send_guest_global_virq(struct domain *d, int virq)
{
    int port;
    struct evtchn *chn;

    ASSERT(virq_is_global(virq));

    port = d->vcpu[0]->virq_to_evtchn[virq];
    if ( unlikely(port == 0) )
        return;

    chn = evtchn_from_port(d, port);
    evtchn_set_pending(d->vcpu[chn->notify_vcpu_id], port);
}


void send_guest_pirq(struct domain *d, int pirq)
{
    int port = d->pirq_to_evtchn[pirq];
    struct evtchn *chn;

    ASSERT(port != 0);

    chn = evtchn_from_port(d, port);
    evtchn_set_pending(d->vcpu[chn->notify_vcpu_id], port);
}


static long evtchn_status(evtchn_status_t *status)
{
    struct domain   *d;
    domid_t          dom = status->dom;
    int              port = status->port;
    struct evtchn   *chn;
    long             rc = 0;

    if ( dom == DOMID_SELF )
        dom = current->domain->domain_id;
    else if ( !IS_PRIV(current->domain) )
        return -EPERM;

    if ( (d = find_domain_by_id(dom)) == NULL )
        return -ESRCH;

    spin_lock(&d->evtchn_lock);

    if ( !port_is_valid(d, port) )
    {
        rc = -EINVAL;
        goto out;
    }

    chn = evtchn_from_port(d, port);
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
    spin_unlock(&d->evtchn_lock);
    put_domain(d);
    return rc;
}


long evtchn_bind_vcpu(unsigned int port, unsigned int vcpu_id)
{
    struct domain *d = current->domain;
    struct evtchn *chn;
    long           rc = 0;

    if ( (vcpu_id >= ARRAY_SIZE(d->vcpu)) || (d->vcpu[vcpu_id] == NULL) )
        return -ENOENT;

    spin_lock(&d->evtchn_lock);

    if ( !port_is_valid(d, port) )
    {
        rc = -EINVAL;
        goto out;
    }

    chn = evtchn_from_port(d, port);
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
    spin_unlock(&d->evtchn_lock);
    return rc;
}


static long evtchn_unmask(evtchn_unmask_t *unmask)
{
    struct domain *d = current->domain;
    shared_info_t *s = d->shared_info;
    int            port = unmask->port;
    struct vcpu   *v;

    spin_lock(&d->evtchn_lock);

    if ( unlikely(!port_is_valid(d, port)) )
    {
        spin_unlock(&d->evtchn_lock);
        return -EINVAL;
    }

    v = d->vcpu[evtchn_from_port(d, port)->notify_vcpu_id];

    /*
     * These operations must happen in strict order. Based on
     * include/xen/event.h:evtchn_set_pending(). 
     */
    if ( test_and_clear_bit(port, &s->evtchn_mask[0]) &&
         test_bit          (port, &s->evtchn_pending[0]) &&
         !test_and_set_bit (port / BITS_PER_LONG,
                            &v->vcpu_info->evtchn_pending_sel) &&
         !test_and_set_bit (0, &v->vcpu_info->evtchn_upcall_pending) )
    {
        evtchn_notify(v);
    }

    spin_unlock(&d->evtchn_lock);

    return 0;
}


long do_event_channel_op(GUEST_HANDLE(evtchn_op_t) uop)
{
    long rc;
    struct evtchn_op op;

    if ( copy_from_guest(&op, uop, 1) != 0 )
        return -EFAULT;

    if (acm_pre_event_channel(&op))
        return -EACCES;

    switch ( op.cmd )
    {
    case EVTCHNOP_alloc_unbound:
        rc = evtchn_alloc_unbound(&op.u.alloc_unbound);
        if ( (rc == 0) && (copy_to_guest(uop, &op, 1) != 0) )
            rc = -EFAULT; /* Cleaning up here would be a mess! */
        break;

    case EVTCHNOP_bind_interdomain:
        rc = evtchn_bind_interdomain(&op.u.bind_interdomain);
        if ( (rc == 0) && (copy_to_guest(uop, &op, 1) != 0) )
            rc = -EFAULT; /* Cleaning up here would be a mess! */
        break;

    case EVTCHNOP_bind_virq:
        rc = evtchn_bind_virq(&op.u.bind_virq);
        if ( (rc == 0) && (copy_to_guest(uop, &op, 1) != 0) )
            rc = -EFAULT; /* Cleaning up here would be a mess! */
        break;

    case EVTCHNOP_bind_ipi:
        rc = evtchn_bind_ipi(&op.u.bind_ipi);
        if ( (rc == 0) && (copy_to_guest(uop, &op, 1) != 0) )
            rc = -EFAULT; /* Cleaning up here would be a mess! */
        break;

    case EVTCHNOP_bind_pirq:
        rc = evtchn_bind_pirq(&op.u.bind_pirq);
        if ( (rc == 0) && (copy_to_guest(uop, &op, 1) != 0) )
            rc = -EFAULT; /* Cleaning up here would be a mess! */
        break;

    case EVTCHNOP_close:
        rc = evtchn_close(&op.u.close);
        break;

    case EVTCHNOP_send:
        rc = evtchn_send(op.u.send.port);
        break;

    case EVTCHNOP_status:
        rc = evtchn_status(&op.u.status);
        if ( (rc == 0) && (copy_to_guest(uop, &op, 1) != 0) )
            rc = -EFAULT;
        break;

    case EVTCHNOP_bind_vcpu:
        rc = evtchn_bind_vcpu(op.u.bind_vcpu.port, op.u.bind_vcpu.vcpu);
        break;

    case EVTCHNOP_unmask:
        rc = evtchn_unmask(&op.u.unmask);
        break;

    default:
        rc = -ENOSYS;
        break;
    }

    return rc;
}


void evtchn_notify_reserved_port(struct domain *d, int port)
{
    struct evtchn *chn = evtchn_from_port(d, port);
    evtchn_set_pending(d->vcpu[chn->notify_vcpu_id], port);
}


int evtchn_init(struct domain *d)
{
    spin_lock_init(&d->evtchn_lock);
    if ( get_free_port(d) != 0 )
        return -EINVAL;
    evtchn_from_port(d, 0)->state = ECS_RESERVED;
    return 0;
}


void evtchn_destroy(struct domain *d)
{
    int i;

    for ( i = 0; port_is_valid(d, i); i++ )
            (void)__evtchn_close(d, i);

    for ( i = 0; i < NR_EVTCHN_BUCKETS; i++ )
        xfree(d->evtchn[i]);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
