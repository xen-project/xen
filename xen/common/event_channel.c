/******************************************************************************
 * event_channel.c
 * 
 * Event channels between domains.
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

#include <hypervisor-ifs/hypervisor-if.h>
#include <hypervisor-ifs/event_channel.h>

#define INIT_EVENT_CHANNELS   16
#define MAX_EVENT_CHANNELS  1024

static int get_free_port(struct task_struct *p)
{
    int max, port;
    event_channel_t *chn;

    max = p->max_event_channel;
    chn = p->event_channel;

    for ( port = 0; port < max; port++ )
        if ( chn[port].state == ECS_FREE )
            break;

    if ( port == max )
    {
        if ( max == MAX_EVENT_CHANNELS )
            return -ENOSPC;
        
        max *= 2;
        
        chn = kmalloc(max * sizeof(event_channel_t), GFP_KERNEL);
        if ( unlikely(chn == NULL) )
            return -ENOMEM;

        memset(chn, 0, max * sizeof(event_channel_t));

        if ( p->event_channel != NULL )
        {
            memcpy(chn, p->event_channel, (max/2) * sizeof(event_channel_t));
            kfree(p->event_channel);
        }

        p->event_channel     = chn;
        p->max_event_channel = max;
    }

    return port;
}

static long evtchn_bind_interdomain(evtchn_bind_interdomain_t *bind)
{
    struct task_struct *p1, *p2;
    int                 port1 = 0, port2 = 0;
    domid_t             dom1 = bind->dom1, dom2 = bind->dom2;
    long                rc = 0;

    if ( !IS_PRIV(current) )
        return -EPERM;

    if ( dom1 == DOMID_SELF )
        dom1 = current->domain;
    if ( dom2 == DOMID_SELF )
        dom2 = current->domain;

    if ( ((p1 = find_domain_by_id(dom1)) == NULL) ||
         ((p2 = find_domain_by_id(dom2)) == NULL) )
    {
        if ( p1 != NULL )
            put_task_struct(p1);
        return -ESRCH;
    }

    /* Avoid deadlock by first acquiring lock of domain with smaller id. */
    if ( dom1 < dom2 )
    {
        spin_lock(&p1->event_channel_lock);
        spin_lock(&p2->event_channel_lock);
    }
    else
    {
        if ( p1 != p2 )
            spin_lock(&p2->event_channel_lock);
        spin_lock(&p1->event_channel_lock);
    }

    if ( (port1 = get_free_port(p1)) < 0 )
    {
        rc = port1;
        goto out;
    }

    /* 'Allocate' port1 before searching for a free port2. */
    p1->event_channel[port1].state = ECS_INTERDOMAIN;

    if ( (port2 = get_free_port(p2)) < 0 )
    {
        p1->event_channel[port1].state = ECS_FREE;
        rc = port2;
        goto out;
    }

    p1->event_channel[port1].u.remote.dom  = p2;
    p1->event_channel[port1].u.remote.port = (u16)port2;

    p2->event_channel[port2].u.remote.dom  = p1;
    p2->event_channel[port2].u.remote.port = (u16)port1;
    p2->event_channel[port2].state         = ECS_INTERDOMAIN;

    evtchn_set_pending(p1, port1);
    evtchn_set_pending(p2, port2);
    
 out:
    spin_unlock(&p1->event_channel_lock);
    if ( p1 != p2 )
        spin_unlock(&p2->event_channel_lock);
    
    put_task_struct(p1);
    put_task_struct(p2);

    bind->port1 = port1;
    bind->port2 = port2;

    return rc;
}


static long evtchn_bind_virq(evtchn_bind_virq_t *bind)
{
    struct task_struct *p = current;
    int virq = bind->virq;
    int port;

    if ( virq >= ARRAY_SIZE(p->virq_to_evtchn) )
        return -EINVAL;

    spin_lock(&p->event_channel_lock);

    /*
     * Port 0 is the fallback port for VIRQs that haven't been explicitly
     * bound yet. The exception is the 'misdirect VIRQ', which is permanently 
     * bound to port 0.
     */
    if ( ((port = p->virq_to_evtchn[virq]) != 0) ||
         (virq == VIRQ_MISDIRECT) ||
         ((port = get_free_port(p)) < 0) )
        goto out;

    p->event_channel[port].state  = ECS_VIRQ;
    p->event_channel[port].u.virq = virq;

    p->virq_to_evtchn[virq] = port;

 out:
    spin_unlock(&p->event_channel_lock);

    if ( port < 0 )
        return port;

    bind->port = port;
    return 0;
}


static long evtchn_bind_pirq(evtchn_bind_pirq_t *bind)
{
    struct task_struct *p = current;
    int pirq = bind->pirq;
    int port, rc;

    if ( pirq >= ARRAY_SIZE(p->pirq_to_evtchn) )
        return -EINVAL;

    spin_lock(&p->event_channel_lock);

    if ( ((rc = port = p->pirq_to_evtchn[pirq]) != 0) ||
         ((rc = port = get_free_port(p)) < 0) )
        goto out;

    p->pirq_to_evtchn[pirq] = port;
    rc = pirq_guest_bind(p, pirq, 
                         !!(bind->flags & BIND_PIRQ__WILL_SHARE));
    if ( rc != 0 )
    {
        p->pirq_to_evtchn[pirq] = 0;
        DPRINTK("Couldn't bind to PIRQ %d (error=%d)\n", pirq, rc);
        goto out;
    }

    p->event_channel[port].state  = ECS_PIRQ;
    p->event_channel[port].u.pirq = pirq;

 out:
    spin_unlock(&p->event_channel_lock);

    if ( rc < 0 )
        return rc;

    bind->port = port;
    return 0;
}


static long __evtchn_close(struct task_struct *p1, int port1)
{
    struct task_struct *p2 = NULL;
    event_channel_t    *chn1, *chn2;
    int                 port2;
    long                rc = 0;

 again:
    spin_lock(&p1->event_channel_lock);

    chn1 = p1->event_channel;

    /* NB. Port 0 is special (VIRQ_MISDIRECT). Never let it be closed. */
    if ( (port1 <= 0) || (port1 >= p1->max_event_channel) )
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
        if ( (rc = pirq_guest_unbind(p1, chn1[port1].u.pirq)) == 0 )
            p1->pirq_to_evtchn[chn1[port1].u.pirq] = 0;
        break;

    case ECS_VIRQ:
        p1->virq_to_evtchn[chn1[port1].u.virq] = 0;
        break;

    case ECS_INTERDOMAIN:
        if ( p2 == NULL )
        {
            p2 = chn1[port1].u.remote.dom;
            get_task_struct(p2);

            if ( p1->domain < p2->domain )
            {
                spin_lock(&p2->event_channel_lock);
            }
            else if ( p1 != p2 )
            {
                spin_unlock(&p1->event_channel_lock);
                spin_lock(&p2->event_channel_lock);
                goto again;
            }
        }
        else if ( p2 != chn1[port1].u.remote.dom )
        {
            rc = -EINVAL;
            goto out;
        }
        
        chn2  = p2->event_channel;
        port2 = chn1[port1].u.remote.port;

        if ( port2 >= p2->max_event_channel )
            BUG();
        if ( chn2[port2].state != ECS_INTERDOMAIN )
            BUG();
        if ( chn2[port2].u.remote.dom != p1 )
            BUG();

        chn2[port2].state = ECS_UNBOUND;
        evtchn_set_exception(p2, port2);

        break;

    default:
        BUG();
    }

    chn1[port1].state = ECS_FREE;
    evtchn_set_exception(p1, port1);

 out:
    if ( p2 != NULL )
    {
        if ( p1 != p2 )
            spin_unlock(&p2->event_channel_lock);
        put_task_struct(p2);
    }
    
    spin_unlock(&p1->event_channel_lock);

    return rc;
}


static long evtchn_close(evtchn_close_t *close)
{
    struct task_struct *p;
    long                rc;
    domid_t             dom = close->dom;

    if ( dom == DOMID_SELF )
        dom = current->domain;
    else if ( !IS_PRIV(current) )
        return -EPERM;

    if ( (p = find_domain_by_id(dom)) == NULL )
        return -ESRCH;

    rc = __evtchn_close(p, close->port);

    put_task_struct(p);
    return rc;
}


static long evtchn_send(int lport)
{
    struct task_struct *lp = current, *rp;
    int                 rport;

    spin_lock(&lp->event_channel_lock);

    if ( unlikely(lport < 0) ||
         unlikely(lport >= lp->max_event_channel) || 
         unlikely(lp->event_channel[lport].state != ECS_INTERDOMAIN) )
    {
        spin_unlock(&lp->event_channel_lock);
        return -EINVAL;
    }

    rp    = lp->event_channel[lport].u.remote.dom;
    rport = lp->event_channel[lport].u.remote.port;

    get_task_struct(rp);

    spin_unlock(&lp->event_channel_lock);

    evtchn_set_pending(rp, rport);

    put_task_struct(rp);

    return 0;
}


static long evtchn_status(evtchn_status_t *status)
{
    struct task_struct *p;
    domid_t             dom = status->dom;
    int                 port = status->port;
    event_channel_t    *chn;
    long                rc = 0;

    if ( dom == DOMID_SELF )
        dom = current->domain;
    else if ( !IS_PRIV(current) )
        return -EPERM;

    if ( (p = find_domain_by_id(dom)) == NULL )
        return -ESRCH;

    spin_lock(&p->event_channel_lock);

    chn = p->event_channel;

    if ( (port < 0) || (port >= p->max_event_channel) )
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
        break;
    case ECS_INTERDOMAIN:
        status->status = EVTCHNSTAT_interdomain;
        status->u.interdomain.dom  = chn[port].u.remote.dom->domain;
        status->u.interdomain.port = chn[port].u.remote.port;
        break;
    case ECS_PIRQ:
        status->status = EVTCHNSTAT_pirq;
        status->u.pirq = chn[port].u.pirq;
        break;
    case ECS_VIRQ:
        status->status = EVTCHNSTAT_virq;
        status->u.virq = chn[port].u.virq;
        break;
    default:
        BUG();
    }

 out:
    spin_unlock(&p->event_channel_lock);
    put_task_struct(p);
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


int init_event_channels(struct task_struct *p)
{
    spin_lock_init(&p->event_channel_lock);
    p->event_channel = kmalloc(INIT_EVENT_CHANNELS * sizeof(event_channel_t), 
                               GFP_KERNEL);
    if ( unlikely(p->event_channel == NULL) )
        return -ENOMEM;
    p->max_event_channel = INIT_EVENT_CHANNELS;
    memset(p->event_channel, 0, INIT_EVENT_CHANNELS * sizeof(event_channel_t));
    p->event_channel[0].state  = ECS_VIRQ;
    p->event_channel[0].u.virq = VIRQ_MISDIRECT;
    return 0;
}


void destroy_event_channels(struct task_struct *p)
{
    int i;
    if ( p->event_channel != NULL )
    {
        for ( i = 0; i < p->max_event_channel; i++ )
            (void)__evtchn_close(p, i);
        kfree(p->event_channel);
    }
}
