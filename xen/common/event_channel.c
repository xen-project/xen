/******************************************************************************
 * event_channel.c
 * 
 * Event notifications from VIRQs, PIRQs, and other domains.
 * 
 * Copyright (c) 2003-2004, K A Fraser.
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

#define ERROR_EXIT(_errno) do { rc = (_errno); goto out; } while ( 0 )

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
    struct domain *d = current->domain;
    int            port = alloc->port;
    long           rc = 0;

    spin_lock(&d->evtchn_lock);

    /* Obtain, or ensure that we already have, a valid <port>. */
    if ( port == 0 )
    {
        if ( (port = get_free_port(d)) < 0 )
            ERROR_EXIT(port);
    }
    else if ( !port_is_valid(d, port) )
        ERROR_EXIT(-EINVAL);
    chn = evtchn_from_port(d, port);

    /* Validate channel's current state. */
    switch ( chn->state )
    {
    case ECS_FREE:
        chn->state = ECS_UNBOUND;
        chn->u.unbound.remote_domid = alloc->dom;
        break;

    case ECS_UNBOUND:
        if ( chn->u.unbound.remote_domid != alloc->dom )
            ERROR_EXIT(-EINVAL);
        break;

    default:
        ERROR_EXIT(-EINVAL);
    }

 out:
    spin_unlock(&d->evtchn_lock);

    alloc->port = port;
    return rc;
}


static long evtchn_bind_interdomain(evtchn_bind_interdomain_t *bind)
{
    struct evtchn *chn1, *chn2;
    struct domain *d1, *d2;
    int            port1 = bind->port1, port2 = bind->port2;
    domid_t        dom1 = bind->dom1, dom2 = bind->dom2;
    long           rc = 0;

    if ( !IS_PRIV(current->domain) && (dom1 != DOMID_SELF) )
        return -EPERM;

    if ( dom1 == DOMID_SELF )
        dom1 = current->domain->domain_id;
    if ( dom2 == DOMID_SELF )
        dom2 = current->domain->domain_id;

    if ( ((d1 = find_domain_by_id(dom1)) == NULL) ||
         ((d2 = find_domain_by_id(dom2)) == NULL) )
    {
        if ( d1 != NULL )
            put_domain(d1);
        return -ESRCH;
    }

    /* Avoid deadlock by first acquiring lock of domain with smaller id. */
    if ( d1 < d2 )
    {
        spin_lock(&d1->evtchn_lock);
        spin_lock(&d2->evtchn_lock);
    }
    else
    {
        if ( d1 != d2 )
            spin_lock(&d2->evtchn_lock);
        spin_lock(&d1->evtchn_lock);
    }

    /* Obtain, or ensure that we already have, a valid <port1>. */
    if ( port1 == 0 )
    {
        if ( (port1 = get_free_port(d1)) < 0 )
            ERROR_EXIT(port1);
    }
    else if ( !port_is_valid(d1, port1) )
        ERROR_EXIT(-EINVAL);
    chn1 = evtchn_from_port(d1, port1);

    /* Obtain, or ensure that we already have, a valid <port2>. */
    if ( port2 == 0 )
    {
        /* Make port1 non-free while we allocate port2 (in case dom1==dom2). */
        u16 state = chn1->state;
        chn1->state = ECS_INTERDOMAIN;
        port2 = get_free_port(d2);
        chn1->state = state;
        if ( port2 < 0 )
            ERROR_EXIT(port2);
    }
    else if ( !port_is_valid(d2, port2) )
        ERROR_EXIT(-EINVAL);
    chn2 = evtchn_from_port(d2, port2);

    /* Validate <dom1,port1>'s current state. */
    switch ( chn1->state )
    {
    case ECS_FREE:
        break;

    case ECS_UNBOUND:
        if ( chn1->u.unbound.remote_domid != dom2 )
            ERROR_EXIT(-EINVAL);
        break;

    case ECS_INTERDOMAIN:
        if ( chn1->u.interdomain.remote_dom != d2 )
            ERROR_EXIT(-EINVAL);
        if ( (chn1->u.interdomain.remote_port != port2) && (bind->port2 != 0) )
            ERROR_EXIT(-EINVAL);
        port2 = chn1->u.interdomain.remote_port;
        goto out;

    default:
        ERROR_EXIT(-EINVAL);
    }

    /* Validate <dom2,port2>'s current state. */
    switch ( chn2->state )
    {
    case ECS_FREE:
        if ( !IS_PRIV(current->domain) && (dom2 != DOMID_SELF) )
            ERROR_EXIT(-EPERM);
        break;

    case ECS_UNBOUND:
        if ( chn2->u.unbound.remote_domid != dom1 )
            ERROR_EXIT(-EINVAL);
        break;

    case ECS_INTERDOMAIN:
        if ( chn2->u.interdomain.remote_dom != d1 )
            ERROR_EXIT(-EINVAL);
        if ( (chn2->u.interdomain.remote_port != port1) && (bind->port1 != 0) )
            ERROR_EXIT(-EINVAL);
        port1 = chn2->u.interdomain.remote_port;
        goto out;

    default:
        ERROR_EXIT(-EINVAL);
    }

    /*
     * Everything checked out okay -- bind <dom1,port1> to <dom2,port2>.
     */

    chn1->u.interdomain.remote_dom  = d2;
    chn1->u.interdomain.remote_port = (u16)port2;
    chn1->notify_vcpu_id            = 0;
    chn1->state                     = ECS_INTERDOMAIN;
    
    chn2->u.interdomain.remote_dom  = d1;
    chn2->u.interdomain.remote_port = (u16)port1;
    chn2->notify_vcpu_id            = 0;
    chn2->state                     = ECS_INTERDOMAIN;

 out:
    spin_unlock(&d1->evtchn_lock);
    if ( d1 != d2 )
        spin_unlock(&d2->evtchn_lock);
    
    put_domain(d1);
    put_domain(d2);

    bind->port1 = port1;
    bind->port2 = port2;

    return rc;
}


static long evtchn_bind_virq(evtchn_bind_virq_t *bind)
{
    struct evtchn *chn;
    struct vcpu   *v = current;
    struct domain *d = v->domain;
    int            port, virq = bind->virq;

    if ( virq >= ARRAY_SIZE(v->virq_to_evtchn) )
        return -EINVAL;

    spin_lock(&d->evtchn_lock);

    /*
     * Port 0 is the fallback port for VIRQs that haven't been explicitly
     * bound yet.
     */
    if ( ((port = v->virq_to_evtchn[virq]) != 0) ||
         ((port = get_free_port(d)) < 0) )
        goto out;

    chn = evtchn_from_port(d, port);
    chn->state          = ECS_VIRQ;
    chn->notify_vcpu_id = v->vcpu_id;
    chn->u.virq         = virq;

    v->virq_to_evtchn[virq] = port;

 out:
    spin_unlock(&d->evtchn_lock);

    if ( port < 0 )
        return port;

    bind->port = port;
    return 0;
}


static long evtchn_bind_ipi(evtchn_bind_ipi_t *bind)
{
    struct evtchn *chn;
    struct domain *d = current->domain;
    int            port, ipi_vcpu = bind->ipi_vcpu;

    if ( (ipi_vcpu >= MAX_VIRT_CPUS) || (d->vcpu[ipi_vcpu] == NULL) )
        return -EINVAL;

    spin_lock(&d->evtchn_lock);

    if ( (port = get_free_port(d)) >= 0 )
    {
        chn = evtchn_from_port(d, port);
        chn->state          = ECS_IPI;
        chn->notify_vcpu_id = ipi_vcpu;
    }

    spin_unlock(&d->evtchn_lock);

    if ( port < 0 )
        return port;

    bind->port = port;
    return 0;
}


static long evtchn_bind_pirq(evtchn_bind_pirq_t *bind)
{
    struct evtchn *chn;
    struct domain *d = current->domain;
    int            port, rc, pirq = bind->pirq;

    if ( pirq >= ARRAY_SIZE(d->pirq_to_evtchn) )
        return -EINVAL;

    spin_lock(&d->evtchn_lock);

    if ( ((rc = port = d->pirq_to_evtchn[pirq]) != 0) ||
         ((rc = port = get_free_port(d)) < 0) )
        goto out;

    chn = evtchn_from_port(d, port);

    chn->notify_vcpu_id = 0;

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

 out:
    spin_unlock(&d->evtchn_lock);

    if ( rc < 0 )
        return rc;

    bind->port = port;
    return 0;
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

    chn1->state = ECS_FREE;

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
    struct domain *d;
    long           rc;
    domid_t        dom = close->dom;

    if ( dom == DOMID_SELF )
        dom = current->domain->domain_id;
    else if ( !IS_PRIV(current->domain) )
        return -EPERM;

    if ( (d = find_domain_by_id(dom)) == NULL )
        return -ESRCH;

    rc = __evtchn_close(d, close->port);

    put_domain(d);
    return rc;
}


long evtchn_send(int lport)
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
    default:
        ret = -EINVAL;
    }

    spin_unlock(&ld->evtchn_lock);

    return ret;
}

void send_guest_pirq(struct domain *d, int pirq)
{
    int port = d->pirq_to_evtchn[pirq];
    struct evtchn *chn = evtchn_from_port(d, port);
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
        status->status     = EVTCHNSTAT_ipi;
        status->u.ipi_vcpu = chn->notify_vcpu_id;
        break;
    default:
        BUG();
    }

 out:
    spin_unlock(&d->evtchn_lock);
    put_domain(d);
    return rc;
}


long do_event_channel_op(evtchn_op_t *uop)
{
    long rc;
    evtchn_op_t op;

    if ( copy_from_user(&op, uop, sizeof(op)) != 0 )
        return -EFAULT;

    if (acm_pre_event_channel(&op))
        return -EACCES;

    switch ( op.cmd )
    {
    case EVTCHNOP_alloc_unbound:
        rc = evtchn_alloc_unbound(&op.u.alloc_unbound);
        if ( (rc == 0) && (copy_to_user(uop, &op, sizeof(op)) != 0) )
            rc = -EFAULT; /* Cleaning up here would be a mess! */
        break;

    case EVTCHNOP_bind_interdomain:
        rc = evtchn_bind_interdomain(&op.u.bind_interdomain);
        if ( (rc == 0) && (copy_to_user(uop, &op, sizeof(op)) != 0) )
            rc = -EFAULT; /* Cleaning up here would be a mess! */
        break;

    case EVTCHNOP_bind_virq:
        rc = evtchn_bind_virq(&op.u.bind_virq);
        if ( (rc == 0) && (copy_to_user(uop, &op, sizeof(op)) != 0) )
            rc = -EFAULT; /* Cleaning up here would be a mess! */
        break;

    case EVTCHNOP_bind_ipi:
        rc = evtchn_bind_ipi(&op.u.bind_ipi);
        if ( (rc == 0) && (copy_to_user(uop, &op, sizeof(op)) != 0) )
            rc = -EFAULT; /* Cleaning up here would be a mess! */
        break;

    case EVTCHNOP_bind_pirq:
        rc = evtchn_bind_pirq(&op.u.bind_pirq);
        if ( (rc == 0) && (copy_to_user(uop, &op, sizeof(op)) != 0) )
            rc = -EFAULT; /* Cleaning up here would be a mess! */
        break;

    case EVTCHNOP_close:
        rc = evtchn_close(&op.u.close);
        break;

    case EVTCHNOP_send:
        rc = evtchn_send(op.u.send.local_port);
        break;

    case EVTCHNOP_status:
        rc = evtchn_status(&op.u.status);
        if ( (rc == 0) && (copy_to_user(uop, &op, sizeof(op)) != 0) )
            rc = -EFAULT;
        break;

    default:
        rc = -ENOSYS;
        break;
    }

    return rc;
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
        if ( d->evtchn[i] != NULL )
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
