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

#include <xeno/config.h>
#include <xeno/init.h>
#include <xeno/lib.h>
#include <xeno/errno.h>
#include <xeno/sched.h>
#include <xeno/event.h>

#include <hypervisor-ifs/hypervisor-if.h>
#include <hypervisor-ifs/event_channel.h>

#define MAX_EVENT_CHANNELS 1024

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
        
        max = (max == 0) ? 4 : (max * 2);
        
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

static inline unsigned long set_event_pending(struct task_struct *p, int port)
{
    if ( !test_and_set_bit(port,    &p->shared_info->event_channel_pend[0]) &&
         !test_and_set_bit(port>>5, &p->shared_info->event_channel_pend_sel) )
        return mark_guest_event(p, _EVENT_EVTCHN);
    return 0;
}

static inline unsigned long set_event_disc(struct task_struct *p, int port)
{
    if ( !test_and_set_bit(port,    &p->shared_info->event_channel_disc[0]) &&
         !test_and_set_bit(port>>5, &p->shared_info->event_channel_disc_sel) )
        return mark_guest_event(p, _EVENT_EVTCHN);
    return 0;
}

static long event_channel_open(evtchn_open_t *open)
{
    struct task_struct *p1, *p2;
    int                 port1 = 0, port2 = 0;
    unsigned long       cpu_mask;
    domid_t             dom1 = open->dom1, dom2 = open->dom2;
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

    if ( (port2 = get_free_port(p2)) < 0 )
    {
        rc = port2;
        goto out;
    }

    p1->event_channel[port1].remote_dom  = p2;
    p1->event_channel[port1].remote_port = (u16)port2;
    p1->event_channel[port1].state       = ECS_CONNECTED;

    p2->event_channel[port2].remote_dom  = p1;
    p2->event_channel[port2].remote_port = (u16)port1;
    p2->event_channel[port2].state       = ECS_CONNECTED;

    /* Ensure that the disconnect signal is not asserted. */
    clear_bit(port1, &p1->shared_info->event_channel_disc[0]);
    clear_bit(port2, &p2->shared_info->event_channel_disc[0]);

    cpu_mask  = set_event_pending(p1, port1);
    cpu_mask |= set_event_pending(p2, port2);
    guest_event_notify(cpu_mask);
    
 out:
    spin_unlock(&p1->event_channel_lock);
    if ( p1 != p2 )
        spin_unlock(&p2->event_channel_lock);
    
    put_task_struct(p1);
    put_task_struct(p2);

    open->port1 = port1;
    open->port2 = port2;

    return rc;
}


static long __event_channel_close(struct task_struct *p1, int port1)
{
    struct task_struct *p2 = NULL;
    event_channel_t    *chn1, *chn2;
    int                 port2;
    unsigned long       cpu_mask = 0;
    long                rc = 0;

 again:
    spin_lock(&p1->event_channel_lock);

    chn1 = p1->event_channel;

    if ( (port1 < 0) || (port1 >= p1->max_event_channel) || 
         (chn1[port1].state == ECS_FREE) )
    {
        rc = -EINVAL;
        goto out;
    }

    if ( chn1[port1].state == ECS_CONNECTED )
    {
        if ( p2 == NULL )
        {
            p2 = chn1[port1].remote_dom;
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
        else if ( p2 != chn1[port1].remote_dom )
        {
            rc = -EINVAL;
            goto out;
        }
        
        chn2  = p2->event_channel;
        port2 = chn1[port1].remote_port;

        if ( port2 >= p2->max_event_channel )
            BUG();
        if ( chn2[port2].state != ECS_CONNECTED )
            BUG();
        if ( chn2[port2].remote_dom != p1 )
            BUG();

        chn2[port2].state       = ECS_DISCONNECTED;
        chn2[port2].remote_dom  = NULL;
        chn2[port2].remote_port = 0xFFFF;

        cpu_mask |= set_event_disc(p2, port2);
    }

    chn1[port1].state       = ECS_FREE;
    chn1[port1].remote_dom  = NULL;
    chn1[port1].remote_port = 0xFFFF;
    
    cpu_mask |= set_event_disc(p1, port1);
    guest_event_notify(cpu_mask);

 out:
    spin_unlock(&p1->event_channel_lock);
    put_task_struct(p1);

    if ( p2 != NULL )
    {
        if ( p1 != p2 )
            spin_unlock(&p2->event_channel_lock);
        put_task_struct(p2);
    }
    
    return rc;
}


static long event_channel_close(evtchn_close_t *close)
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

    rc = __event_channel_close(p, close->port);

    put_task_struct(p);
    return rc;
}


static long event_channel_send(int lport)
{
    struct task_struct *lp = current, *rp;
    int                 rport;
    unsigned long       cpu_mask;

    spin_lock(&lp->event_channel_lock);

    if ( unlikely(lport < 0) ||
         unlikely(lport >= lp->max_event_channel) || 
         unlikely(lp->event_channel[lport].state != ECS_CONNECTED) )
    {
        spin_unlock(&lp->event_channel_lock);
        return -EINVAL;
    }

    rp    = lp->event_channel[lport].remote_dom;
    rport = lp->event_channel[lport].remote_port;

    get_task_struct(rp);

    spin_unlock(&lp->event_channel_lock);

    cpu_mask = set_event_pending(rp, rport);
    guest_event_notify(cpu_mask);

    put_task_struct(rp);

    return 0;
}


static long event_channel_status(evtchn_status_t *status)
{
    struct task_struct *p;
    domid_t             dom = status->dom1;
    int                 port = status->port1;
    event_channel_t    *chn;

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
        spin_unlock(&p->event_channel_lock);
        return -EINVAL;
    }

    switch ( chn[port].state )
    {
    case ECS_FREE:
        status->status = EVTCHNSTAT_closed;
        break;
    case ECS_DISCONNECTED:
        status->status = EVTCHNSTAT_disconnected;
        break;
    case ECS_CONNECTED:
        status->status = EVTCHNSTAT_connected;
        status->dom2   = chn[port].remote_dom->domain;
        status->port2  = chn[port].remote_port;
        break;
    default:
        BUG();
    }

    spin_unlock(&p->event_channel_lock);
    return 0;
}


long do_event_channel_op(evtchn_op_t *uop)
{
    long rc;
    evtchn_op_t op;

    if ( copy_from_user(&op, uop, sizeof(op)) != 0 )
        return -EFAULT;

    switch ( op.cmd )
    {
    case EVTCHNOP_open:
        rc = event_channel_open(&op.u.open);
        if ( copy_to_user(uop, &op, sizeof(op)) != 0 )
            rc = -EFAULT; /* Cleaning up here would be a mess! */
        break;

    case EVTCHNOP_close:
        rc = event_channel_close(&op.u.close);
        break;

    case EVTCHNOP_send:
        rc = event_channel_send(op.u.send.local_port);
        break;

    case EVTCHNOP_status:
        rc = event_channel_status(&op.u.status);
        if ( copy_to_user(uop, &op, sizeof(op)) != 0 )
            rc = -EFAULT;
        break;

    default:
        rc = -ENOSYS;
        break;
    }

    return rc;
}


void destroy_event_channels(struct task_struct *p)
{
    int i;
    if ( p->event_channel != NULL )
    {
        for ( i = 0; i < p->max_event_channel; i++ )
            (void)__event_channel_close(p, i);
        kfree(p->event_channel);
    }
}
