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
    struct task_struct *lp, *rp;
    int                 lport = 0, rport = 0;
    unsigned long       cpu_mask;
    domid_t             ldom = open->local_dom, rdom = open->remote_dom;
    long                rc = 0;

    if ( !IS_PRIV(current) )
        return -EPERM;

    /* 'local_dom' may be DOMID_SELF. 'remote_dom' cannot be.*/
    if ( ldom == DOMID_SELF )
        ldom = current->domain;

    /* Event channel must connect distinct domains. */
    if ( ldom == rdom )
        return -EINVAL;

    if ( ((lp = find_domain_by_id(ldom)) == NULL) ||
         ((rp = find_domain_by_id(rdom)) == NULL) )
    {
        if ( lp != NULL )
            put_task_struct(lp);
        return -ESRCH;
    }

    /* Avoid deadlock by first acquiring lock of domain with smaller id. */
    if ( ldom < rdom )
    {
        spin_lock(&lp->event_channel_lock);
        spin_lock(&rp->event_channel_lock);
    }
    else
    {
        spin_lock(&rp->event_channel_lock);
        spin_lock(&lp->event_channel_lock);
    }

    if ( (lport = get_free_port(lp)) < 0 )
    {
        rc = lport;
        goto out;
    }

    if ( (rport = get_free_port(rp)) < 0 )
    {
        rc = rport;
        goto out;
    }

    lp->event_channel[lport].remote_dom  = rp;
    lp->event_channel[lport].remote_port = (u16)rport;
    lp->event_channel[lport].state       = ECS_CONNECTED;

    rp->event_channel[rport].remote_dom  = lp;
    rp->event_channel[rport].remote_port = (u16)lport;
    rp->event_channel[rport].state       = ECS_CONNECTED;

    cpu_mask  = set_event_pending(lp, lport);
    cpu_mask |= set_event_pending(rp, rport);
    guest_event_notify(cpu_mask);
    
 out:
    spin_unlock(&lp->event_channel_lock);
    spin_unlock(&rp->event_channel_lock);
    
    put_task_struct(lp);
    put_task_struct(rp);

    open->local_port  = lport;
    open->remote_port = rport;

    return rc;
}


static long __event_channel_close(struct task_struct *lp, int lport)
{
    struct task_struct *rp = NULL;
    event_channel_t    *lchn, *rchn;
    int                 rport;
    unsigned long       cpu_mask;
    long                rc = 0;

 again:
    spin_lock(&lp->event_channel_lock);

    lchn = lp->event_channel;

    if ( (lport < 0) || (lport >= lp->max_event_channel) || 
         (lchn[lport].state == ECS_FREE) )
    {
        rc = -EINVAL;
        goto out;
    }

    if ( lchn[lport].state == ECS_CONNECTED )
    {
        if ( rp == NULL )
        {
            rp = lchn[lport].remote_dom;
            get_task_struct(rp);

            if ( lp->domain < rp->domain )
            {
                spin_lock(&rp->event_channel_lock);
            }
            else
            {
                spin_unlock(&lp->event_channel_lock);
                spin_lock(&rp->event_channel_lock);
                goto again;
            }
        }
        else if ( rp != lchn[lport].remote_dom )
        {
            rc = -EINVAL;
            goto out;
        }
        
        rchn  = rp->event_channel;
        rport = lchn[lport].remote_port;

        if ( rport >= rp->max_event_channel )
            BUG();
        if ( rchn[rport].state != ECS_CONNECTED )
            BUG();
        if ( rchn[rport].remote_dom != lp )
            BUG();

        rchn[rport].state       = ECS_ZOMBIE;
        rchn[rport].remote_dom  = NULL;
        rchn[rport].remote_port = 0xFFFF;

        cpu_mask  = set_event_disc(lp, lport);
        cpu_mask |= set_event_disc(rp, rport);
        guest_event_notify(cpu_mask);
    }

    lchn[lport].state       = ECS_FREE;
    lchn[lport].remote_dom  = NULL;
    lchn[lport].remote_port = 0xFFFF;
    
 out:
    spin_unlock(&lp->event_channel_lock);
    put_task_struct(lp);

    if ( rp != NULL )
    {
        spin_unlock(&rp->event_channel_lock);
        put_task_struct(rp);
    }
    
    return rc;
}


static long event_channel_close(evtchn_close_t *close)
{
    struct task_struct *lp;
    int                 lport = close->local_port;
    long                rc;
    domid_t             ldom = close->local_dom;

    if ( ldom == DOMID_SELF )
        ldom = current->domain;
    else if ( !IS_PRIV(current) )
        return -EPERM;

    if ( (lp = find_domain_by_id(ldom)) == NULL )
        return -ESRCH;

    rc = __event_channel_close(lp, lport);

    put_task_struct(lp);
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
    struct task_struct *lp;
    domid_t             ldom = status->local_dom;
    int                 lport = status->local_port;
    event_channel_t    *lchn;

    if ( ldom == DOMID_SELF )
        ldom = current->domain;
    else if ( !IS_PRIV(current) )
        return -EPERM;

    if ( (lp = find_domain_by_id(ldom)) == NULL )
        return -ESRCH;

    spin_lock(&lp->event_channel_lock);

    lchn = lp->event_channel;

    if ( (lport < 0) || (lport >= lp->max_event_channel) )
    {
        spin_unlock(&lp->event_channel_lock);
        return -EINVAL;
    }

    switch ( lchn[lport].state )
    {
    case ECS_FREE:
        status->status = EVTCHNSTAT_closed;
        break;
    case ECS_ZOMBIE:
        status->status = EVTCHNSTAT_disconnected;
        break;
    case ECS_CONNECTED:
        status->status = EVTCHNSTAT_connected;
        status->remote_dom  = lchn[lport].remote_dom->domain;
        status->remote_port = lchn[lport].remote_port;
        break;
    default:
        BUG();
    }

    spin_unlock(&lp->event_channel_lock);
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
