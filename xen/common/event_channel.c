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

#include <public/xen.h>
#include <public/event_channel.h>

#define INIT_EVENT_CHANNELS   16
#define MAX_EVENT_CHANNELS  1024
#define EVENT_CHANNELS_SPREAD 32


static int get_free_port(struct exec_domain *ed)
{
    struct domain *d = ed->domain;
    int max, port;
    event_channel_t *chn;

    max = d->max_event_channel;
    chn = d->event_channel;

    for ( port = ed->eid * EVENT_CHANNELS_SPREAD; port < max; port++ )
        if ( chn[port].state == ECS_FREE )
            break;

    if ( port >= max )
    {
        if ( max == MAX_EVENT_CHANNELS )
            return -ENOSPC;
        
        max = port + EVENT_CHANNELS_SPREAD;
        
        chn = xmalloc(max * sizeof(event_channel_t));
        if ( unlikely(chn == NULL) )
            return -ENOMEM;

        memset(chn, 0, max * sizeof(event_channel_t));

        if ( d->event_channel != NULL )
        {
            memcpy(chn, d->event_channel, d->max_event_channel *
                   sizeof(event_channel_t));
            xfree(d->event_channel);
        }

        d->event_channel     = chn;
        d->max_event_channel = max;
    }

    return port;
}


static long evtchn_alloc_unbound(evtchn_alloc_unbound_t *alloc)
{
    struct domain *d = current->domain;
    int            port;

    spin_lock(&d->event_channel_lock);

    if ( (port = get_free_port(current)) >= 0 )
    {
        d->event_channel[port].state = ECS_UNBOUND;
        d->event_channel[port].u.unbound.remote_domid = alloc->dom;
    }

    spin_unlock(&d->event_channel_lock);

    if ( port < 0 )
        return port;

    alloc->port = port;
    return 0;
}


static long evtchn_bind_interdomain(evtchn_bind_interdomain_t *bind)
{
#define ERROR_EXIT(_errno) do { rc = (_errno); goto out; } while ( 0 )
    struct domain *d1, *d2;
    struct exec_domain *ed1, *ed2;
    int            port1 = bind->port1, port2 = bind->port2;
    domid_t        dom1 = bind->dom1, dom2 = bind->dom2;
    long           rc = 0;

    if ( !IS_PRIV(current->domain) && (dom1 != DOMID_SELF) )
        return -EPERM;

    if ( (port1 < 0) || (port2 < 0) )
        return -EINVAL;

    if ( dom1 == DOMID_SELF )
        dom1 = current->domain->id;
    if ( dom2 == DOMID_SELF )
        dom2 = current->domain->id;

    if ( ((d1 = find_domain_by_id(dom1)) == NULL) ||
         ((d2 = find_domain_by_id(dom2)) == NULL) )
    {
        if ( d1 != NULL )
            put_domain(d1);
        return -ESRCH;
    }

    ed1 = d1->exec_domain[0];   /* XXX */
    ed2 = d2->exec_domain[0];   /* XXX */

    /* Avoid deadlock by first acquiring lock of domain with smaller id. */
    if ( d1 < d2 )
    {
        spin_lock(&d1->event_channel_lock);
        spin_lock(&d2->event_channel_lock);
    }
    else
    {
        if ( d1 != d2 )
            spin_lock(&d2->event_channel_lock);
        spin_lock(&d1->event_channel_lock);
    }

    /* Obtain, or ensure that we already have, a valid <port1>. */
    if ( port1 == 0 )
    {
        if ( (port1 = get_free_port(ed1)) < 0 )
            ERROR_EXIT(port1);
    }
    else if ( port1 >= d1->max_event_channel )
        ERROR_EXIT(-EINVAL);

    /* Obtain, or ensure that we already have, a valid <port2>. */
    if ( port2 == 0 )
    {
        /* Make port1 non-free while we allocate port2 (in case dom1==dom2). */
        u16 tmp = d1->event_channel[port1].state;
        d1->event_channel[port1].state = ECS_INTERDOMAIN;
        port2 = get_free_port(ed2);
        d1->event_channel[port1].state = tmp;
        if ( port2 < 0 )
            ERROR_EXIT(port2);
    }
    else if ( port2 >= d2->max_event_channel )
        ERROR_EXIT(-EINVAL);

    /* Validate <dom1,port1>'s current state. */
    switch ( d1->event_channel[port1].state )
    {
    case ECS_FREE:
        break;

    case ECS_UNBOUND:
        if ( d1->event_channel[port1].u.unbound.remote_domid != dom2 )
            ERROR_EXIT(-EINVAL);
        break;

    case ECS_INTERDOMAIN:
        if ( d1->event_channel[port1].u.interdomain.remote_dom != ed2 )
            ERROR_EXIT(-EINVAL);
        if ( (d1->event_channel[port1].u.interdomain.remote_port != port2) &&
             (bind->port2 != 0) )
            ERROR_EXIT(-EINVAL);
        port2 = d1->event_channel[port1].u.interdomain.remote_port;
        goto out;

    default:
        ERROR_EXIT(-EINVAL);
    }

    /* Validate <dom2,port2>'s current state. */
    switch ( d2->event_channel[port2].state )
    {
    case ECS_FREE:
        if ( !IS_PRIV(current->domain) && (dom2 != DOMID_SELF) )
            ERROR_EXIT(-EPERM);
        break;

    case ECS_UNBOUND:
        if ( d2->event_channel[port2].u.unbound.remote_domid != dom1 )
            ERROR_EXIT(-EINVAL);
        break;

    case ECS_INTERDOMAIN:
        if ( d2->event_channel[port2].u.interdomain.remote_dom != ed1 )
            ERROR_EXIT(-EINVAL);
        if ( (d2->event_channel[port2].u.interdomain.remote_port != port1) &&
             (bind->port1 != 0) )
            ERROR_EXIT(-EINVAL);
        port1 = d2->event_channel[port2].u.interdomain.remote_port;
        goto out;

    default:
        ERROR_EXIT(-EINVAL);
    }

    /*
     * Everything checked out okay -- bind <dom1,port1> to <dom2,port2>.
     */

    d1->event_channel[port1].u.interdomain.remote_dom  = ed2;
    d1->event_channel[port1].u.interdomain.remote_port = (u16)port2;
    d1->event_channel[port1].state                     = ECS_INTERDOMAIN;
    
    d2->event_channel[port2].u.interdomain.remote_dom  = ed1;
    d2->event_channel[port2].u.interdomain.remote_port = (u16)port1;
    d2->event_channel[port2].state                     = ECS_INTERDOMAIN;

 out:
    spin_unlock(&d1->event_channel_lock);
    if ( d1 != d2 )
        spin_unlock(&d2->event_channel_lock);
    
    put_domain(d1);
    put_domain(d2);

    bind->port1 = port1;
    bind->port2 = port2;

    return rc;
#undef ERROR_EXIT
}


static long evtchn_bind_virq(evtchn_bind_virq_t *bind)
{
    struct exec_domain *ed = current;
    struct domain *d = ed->domain;
    int            port, virq = bind->virq;

    if ( virq >= ARRAY_SIZE(ed->virq_to_evtchn) )
        return -EINVAL;

    spin_lock(&d->event_channel_lock);

    /*
     * Port 0 is the fallback port for VIRQs that haven't been explicitly
     * bound yet. The exception is the 'misdirect VIRQ', which is permanently 
     * bound to port 0.
     */
    if ( ((port = ed->virq_to_evtchn[virq]) != 0) ||
         (virq == VIRQ_MISDIRECT) ||
         ((port = get_free_port(ed)) < 0) )
        goto out;

    d->event_channel[port].state  = ECS_VIRQ;
    d->event_channel[port].u.virq = virq;

    ed->virq_to_evtchn[virq] = port;

 out:
    spin_unlock(&d->event_channel_lock);

    if ( port < 0 )
        return port;

    bind->port = port;
    printk("evtchn_bind_virq %d/%d virq %d -> %d\n",
           d->id, ed->eid, virq, port);
    return 0;
}

static long evtchn_bind_ipi(evtchn_bind_ipi_t *bind)
{
    struct exec_domain *ed = current;
    struct domain *d = ed->domain;
    int            port, ipi_edom = bind->ipi_edom;

    spin_lock(&d->event_channel_lock);

    if ( (port = get_free_port(ed)) >= 0 )
    {
        d->event_channel[port].state      = ECS_IPI;
        d->event_channel[port].u.ipi_edom = ipi_edom;
    }

    spin_unlock(&d->event_channel_lock);

    if ( port < 0 )
        return port;

    bind->port = port;
    printk("evtchn_bind_ipi %d/%d ipi_edom %d -> %d\n",
           d->id, current->eid, ipi_edom, port);
    return 0;
}


static long evtchn_bind_pirq(evtchn_bind_pirq_t *bind)
{
    struct domain *d = current->domain;
    int            port, rc, pirq = bind->pirq;

    if ( pirq >= ARRAY_SIZE(d->pirq_to_evtchn) )
        return -EINVAL;

    spin_lock(&d->event_channel_lock);

    if ( ((rc = port = d->pirq_to_evtchn[pirq]) != 0) ||
         ((rc = port = get_free_port(current)) < 0) )
        goto out;

    d->pirq_to_evtchn[pirq] = port;
    rc = pirq_guest_bind(current, pirq, 
                         !!(bind->flags & BIND_PIRQ__WILL_SHARE));
    if ( rc != 0 )
    {
        d->pirq_to_evtchn[pirq] = 0;
        goto out;
    }

    d->event_channel[port].state  = ECS_PIRQ;
    d->event_channel[port].u.pirq = pirq;

 out:
    spin_unlock(&d->event_channel_lock);

    if ( rc < 0 )
        return rc;

    bind->port = port;
    printk("evtchn_bind_pirq %d/%d pirq %d -> port %d\n",
           d->id, current->eid, pirq, port);
    return 0;
}


static long __evtchn_close(struct domain *d1, int port1)
{
    struct domain   *d2 = NULL;
    struct exec_domain *ed;
    event_channel_t *chn1, *chn2;
    int              port2;
    long             rc = 0;

 again:
    spin_lock(&d1->event_channel_lock);

    chn1 = d1->event_channel;

    /* NB. Port 0 is special (VIRQ_MISDIRECT). Never let it be closed. */
    if ( (port1 <= 0) || (port1 >= d1->max_event_channel) )
    {
        rc = -EINVAL;
        goto out;
    }

    switch ( chn1[port1].state )
    {
    case ECS_FREE:
        rc = -EINVAL;
        goto out;

    case ECS_UNBOUND:
        break;

    case ECS_PIRQ:
        if ( (rc = pirq_guest_unbind(d1, chn1[port1].u.pirq)) == 0 )
            d1->pirq_to_evtchn[chn1[port1].u.pirq] = 0;
        break;

    case ECS_VIRQ:
        /* XXX could store exec_domain in chn1[port1].u */
        for_each_exec_domain(d1, ed)
            if (ed->virq_to_evtchn[chn1[port1].u.virq] == port1)
                ed->virq_to_evtchn[chn1[port1].u.virq] = 0;
        break;

    case ECS_IPI:
        break;

    case ECS_INTERDOMAIN:
        if ( d2 == NULL )
        {
            d2 = chn1[port1].u.interdomain.remote_dom->domain;

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
                spin_lock(&d2->event_channel_lock);
            }
            else if ( d1 != d2 )
            {
                spin_unlock(&d1->event_channel_lock);
                spin_lock(&d2->event_channel_lock);
                goto again;
            }
        }
        else if ( d2 != chn1[port1].u.interdomain.remote_dom->domain )
        {
            rc = -EINVAL;
            goto out;
        }
    
        chn2  = d2->event_channel;
        port2 = chn1[port1].u.interdomain.remote_port;

        if ( port2 >= d2->max_event_channel )
            BUG();
        if ( chn2[port2].state != ECS_INTERDOMAIN )
            BUG();
        if ( chn2[port2].u.interdomain.remote_dom->domain != d1 )
            BUG();

        chn2[port2].state = ECS_UNBOUND;
        chn2[port2].u.unbound.remote_domid = d1->id;
        break;

    default:
        BUG();
    }

    chn1[port1].state = ECS_FREE;

 out:
    if ( d2 != NULL )
    {
        if ( d1 != d2 )
            spin_unlock(&d2->event_channel_lock);
        put_domain(d2);
    }
    
    spin_unlock(&d1->event_channel_lock);

    return rc;
}


static long evtchn_close(evtchn_close_t *close)
{
    struct domain *d;
    long           rc;
    domid_t        dom = close->dom;

    if ( dom == DOMID_SELF )
        dom = current->domain->id;
    else if ( !IS_PRIV(current->domain) )
        return -EPERM;

    if ( (d = find_domain_by_id(dom)) == NULL )
        return -ESRCH;

    rc = __evtchn_close(d, close->port);

    put_domain(d);
    return rc;
}


static long evtchn_send(int lport)
{
    struct domain *ld = current->domain;
    struct exec_domain *rd;
    int            rport, ret = 0;

    spin_lock(&ld->event_channel_lock);

    if ( unlikely(lport < 0) ||
         unlikely(lport >= ld->max_event_channel))
    {
        spin_unlock(&ld->event_channel_lock);
        return -EINVAL;
    }

    switch ( ld->event_channel[lport].state )
    {
    case ECS_INTERDOMAIN:
        rd    = ld->event_channel[lport].u.interdomain.remote_dom;
        rport = ld->event_channel[lport].u.interdomain.remote_port;

        evtchn_set_pending(rd, rport);
        break;
    case ECS_IPI:
        rd = ld->exec_domain[ld->event_channel[lport].u.ipi_edom];
        if ( rd  )
            evtchn_set_pending(rd, lport);
        else
            ret = -EINVAL;
        break;
    default:
        ret = -EINVAL;
    }

    spin_unlock(&ld->event_channel_lock);

    return ret;
}


static long evtchn_status(evtchn_status_t *status)
{
    struct domain   *d;
    domid_t          dom = status->dom;
    int              port = status->port;
    event_channel_t *chn;
    long             rc = 0;

    if ( dom == DOMID_SELF )
        dom = current->domain->id;
    else if ( !IS_PRIV(current->domain) )
        return -EPERM;

    if ( (d = find_domain_by_id(dom)) == NULL )
        return -ESRCH;

    spin_lock(&d->event_channel_lock);

    chn = d->event_channel;

    if ( (port < 0) || (port >= d->max_event_channel) )
    {
        rc = -EINVAL;
        goto out;
    }

    switch ( chn[port].state )
    {
    case ECS_FREE:
        status->status = EVTCHNSTAT_closed;
        break;
    case ECS_UNBOUND:
        status->status = EVTCHNSTAT_unbound;
        status->u.unbound.dom = chn[port].u.unbound.remote_domid;
        break;
    case ECS_INTERDOMAIN:
        status->status = EVTCHNSTAT_interdomain;
        status->u.interdomain.dom  =
            chn[port].u.interdomain.remote_dom->domain->id;
        status->u.interdomain.port = chn[port].u.interdomain.remote_port;
        break;
    case ECS_PIRQ:
        status->status = EVTCHNSTAT_pirq;
        status->u.pirq = chn[port].u.pirq;
        break;
    case ECS_VIRQ:
        status->status = EVTCHNSTAT_virq;
        status->u.virq = chn[port].u.virq;
        break;
    case ECS_IPI:
        status->status     = EVTCHNSTAT_ipi;
        status->u.ipi_edom = chn[port].u.ipi_edom;
        break;
    default:
        BUG();
    }

 out:
    spin_unlock(&d->event_channel_lock);
    put_domain(d);
    return rc;
}


long do_event_channel_op(evtchn_op_t *uop)
{
    long rc;
    evtchn_op_t op;

    if ( copy_from_user(&op, uop, sizeof(op)) != 0 )
        return -EFAULT;

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


int init_event_channels(struct domain *d)
{
    spin_lock_init(&d->event_channel_lock);
    d->event_channel = xmalloc(INIT_EVENT_CHANNELS * sizeof(event_channel_t));
    if ( unlikely(d->event_channel == NULL) )
        return -ENOMEM;
    d->max_event_channel = INIT_EVENT_CHANNELS;
    memset(d->event_channel, 0, INIT_EVENT_CHANNELS * sizeof(event_channel_t));
    d->event_channel[0].state  = ECS_VIRQ;
    d->event_channel[0].u.virq = VIRQ_MISDIRECT;
    return 0;
}


void destroy_event_channels(struct domain *d)
{
    int i;
    if ( d->event_channel != NULL )
    {
        for ( i = 0; i < d->max_event_channel; i++ )
            (void)__evtchn_close(d, i);
        xfree(d->event_channel);
    }
}
