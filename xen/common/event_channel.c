/******************************************************************************
 * event_channel.c
 * 
 * Event channels between domains.
 * 
 * Copyright (c) 2003, K A Fraser.
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


static long event_channel_open(u16 target_dom)
{
    struct task_struct *lp = current, *rp;
    int                 i, lmax, rmax, lid, rid;
    event_channel_t    *lchn, *rchn;
    shared_info_t      *rsi;
    unsigned long       cpu_mask;
    long                rc = 0;

    rp = find_domain_by_id(target_dom);

    /*
     * We need locks at both ends to make a connection. We avoid deadlock
     * by acquiring the locks in address order.
     */
    if ( (unsigned long)lp < (unsigned long)rp )
    {
        spin_lock(&lp->event_channel_lock);
        spin_lock(&rp->event_channel_lock);
    }
    else
    {
        if ( likely(rp != NULL) )
            spin_lock(&rp->event_channel_lock);
        spin_lock(&lp->event_channel_lock);
    }

    lmax = lp->max_event_channel;
    lchn = lp->event_channel;
    lid  = -1;

    /*
     * Find the first unused event channel. Also ensure bo channel already
     * exists to the specified target domain.
     */
    for ( i = 0; i < lmax; i++ )
    {
        if ( (lid == -1) && !(lchn[i].flags & ECF_INUSE) )
        {
            lid = i;
        }
        else if ( unlikely(lchn[i].target_dom == target_dom) )
        {
            rc = -EEXIST;
            goto out;
        }
    }
    
    /* If there is no free slot we need to allocate a bigger channel list. */
    if ( unlikely(lid == -1) )
    {
        /* Reached maximum channel count? */
        if ( unlikely(lmax == 1024) )
        {
            rc = -ENOSPC;
            goto out;
        }
        
        lmax = (lmax == 0) ? 4 : (lmax * 2);
        
        lchn = kmalloc(lmax * sizeof(event_channel_t), GFP_KERNEL);
        if ( unlikely(lchn == NULL) )
        {
            rc = -ENOMEM;
            goto out;
        }

        memset(lchn, 0, lmax * sizeof(event_channel_t));
        
        if ( likely(lp->event_channel != NULL) )
            kfree(lp->event_channel);

        lp->event_channel     = lchn;
        lp->max_event_channel = lmax;
    }

    lchn[lid].target_dom = target_dom;
    lchn[lid].flags      = ECF_INUSE;

    if ( likely(rp != NULL) )
    {
        rchn = rp->event_channel;
        rmax = rp->max_event_channel;
        
        for ( rid = 0; rid < rmax; rid++ )
        {
            if ( (rchn[rid].target_dom == lp->domain) &&
                 (rchn[rid].flags & ECF_INUSE) )
            {
                /*
                 * The target was awaiting a connection. We make the connection
                 * and send a connection-made event to the remote end.
                 */
                rchn[rid].flags = ECF_INUSE | ECF_CONNECTED | lid;
                lchn[lid].flags = ECF_INUSE | ECF_CONNECTED | rid;

                rsi = rp->shared_info;
                if ( !test_and_set_bit(rid,    &rsi->event_channel_pend[0]) &&
                     !test_and_set_bit(rid>>5, &rsi->event_channel_pend_sel) )
                {
                    cpu_mask = mark_guest_event(rp, _EVENT_EVTCHN);
                    guest_event_notify(cpu_mask);
                }

                break;
            }
        }
    }
    
 out:
    spin_unlock(&lp->event_channel_lock);
    if ( rp != NULL )
    {
        spin_unlock(&rp->event_channel_lock);
        put_task_struct(rp);
    }

    return rc;
}


static long event_channel_close(u16 lid)
{
    struct task_struct *lp = current, *rp = NULL;
    event_channel_t    *lchn, *rchn;
    u16                 rid;
    shared_info_t      *rsi;
    unsigned long       cpu_mask;
    long                rc = 0;

 again:
    spin_lock(&lp->event_channel_lock);

    lchn = lp->event_channel;

    if ( unlikely(lid >= lp->max_event_channel) || 
         unlikely(!(lchn[lid].flags & ECF_INUSE)) )
    {
        rc = -EINVAL;
        goto out;
    }

    if ( lchn[lid].flags & ECF_CONNECTED )
    {
        if ( rp == NULL )
        {
            rp = find_domain_by_id(lchn[lid].target_dom);
            ASSERT(rp != NULL);
            
            if ( (unsigned long)lp < (unsigned long)rp )
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
        else if ( rp->domain != lchn[lid].target_dom )
        {
            rc = -EINVAL;
            goto out;
        }
        
        rchn = rp->event_channel;
        rid  = lchn[lid].flags & ECF_TARGET_ID;
        ASSERT(rid < rp->max_event_channel);
        ASSERT(rchn[rid].flags == (ECF_INUSE | ECF_CONNECTED | lid));
        ASSERT(rchn[rid].target_dom == lp->domain);

        rchn[rid].flags = ECF_INUSE;

        rsi = rp->shared_info;
        if ( !test_and_set_bit(rid,    &rsi->event_channel_disc[0]) &&
             !test_and_set_bit(rid>>5, &rsi->event_channel_disc_sel) )
        {
            cpu_mask = mark_guest_event(rp, _EVENT_EVTCHN);
            guest_event_notify(cpu_mask);
        }
    }

    lchn[lid].target_dom = 0;
    lchn[lid].flags      = 0;
    
 out:
    spin_unlock(&lp->event_channel_lock);
    if ( rp != NULL )
    {
        spin_unlock(&rp->event_channel_lock);
        put_task_struct(rp);
    }
    
    return rc;
}


static long event_channel_send(u16 lid)
{
    struct task_struct *lp = current, *rp;
    event_channel_t    *lchn, *rchn;
    u16                 rid;
    shared_info_t      *rsi;
    unsigned long       cpu_mask;

    spin_lock(&lp->event_channel_lock);

    lchn = lp->event_channel;

    if ( unlikely(lid >= lp->max_event_channel) || 
         unlikely((lchn[lid].flags & (ECF_INUSE|ECF_CONNECTED)) !=
                  (ECF_INUSE|ECF_CONNECTED)) )
    {
        spin_unlock(&lp->event_channel_lock);
        return -EINVAL;
    }

    rid  = lchn[lid].flags & ECF_TARGET_ID;
    rp   = find_domain_by_id(lchn[lid].target_dom);
    ASSERT(rp != NULL);

    spin_unlock(&lp->event_channel_lock);

    spin_lock(&rp->event_channel_lock);

    rchn = rp->event_channel;

    if ( unlikely(rid >= rp->max_event_channel) )
    {
        spin_unlock(&rp->event_channel_lock);
        put_task_struct(rp);
        return -EINVAL;
    }

    rsi = rp->shared_info;
    if ( !test_and_set_bit(rid,    &rsi->event_channel_pend[0]) &&
         !test_and_set_bit(rid>>5, &rsi->event_channel_pend_sel) )
    {
        cpu_mask = mark_guest_event(rp, _EVENT_EVTCHN);
        guest_event_notify(cpu_mask);
    }

    spin_unlock(&rp->event_channel_lock);
    put_task_struct(rp);
    return 0;
}


static long event_channel_status(u16 lid)
{
    struct task_struct *lp = current;
    event_channel_t    *lchn;
    long                rc = EVTCHNSTAT_closed;

    spin_lock(&lp->event_channel_lock);

    lchn = lp->event_channel;

    if ( lid < lp->max_event_channel )
    {
        if ( (lchn[lid].flags & (ECF_INUSE|ECF_CONNECTED)) == ECF_INUSE )
            rc = EVTCHNSTAT_connected;        
        else if ( lchn[lid].flags & ECF_INUSE )
            rc = EVTCHNSTAT_disconnected;
    }

    spin_unlock(&lp->event_channel_lock);
    return rc;
}


long do_event_channel_op(unsigned int cmd, unsigned int id)
{
    long rc;

    switch ( cmd )
    {
    case EVTCHNOP_open:
        rc = event_channel_open((u16)id);
        break;

    case EVTCHNOP_close:
        rc = event_channel_close((u16)id);
        break;

    case EVTCHNOP_send:
        rc = event_channel_send((u16)id);
        break;

    case EVTCHNOP_status:
        rc = event_channel_status((u16)id);
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
            (void)event_channel_close((u16)i);
        kfree(p->event_channel);
    }
}
