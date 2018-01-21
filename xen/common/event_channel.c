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
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

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
#include <xen/event_fifo.h>
#include <asm/current.h>

#include <public/xen.h>
#include <public/event_channel.h>
#include <xsm/xsm.h>

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

#define consumer_is_xen(e) (!!(e)->xen_consumer)

/*
 * The function alloc_unbound_xen_event_channel() allows an arbitrary
 * notifier function to be specified. However, very few unique functions
 * are specified in practice, so to prevent bloating the evtchn structure
 * with a pointer, we stash them dynamically in a small lookup array which
 * can be indexed by a small integer.
 */
static xen_event_channel_notification_t xen_consumers[NR_XEN_CONSUMERS];

/* Default notification action: wake up from wait_on_xen_event_channel(). */
static void default_xen_notification_fn(struct vcpu *v, unsigned int port)
{
    /* Consumer needs notification only if blocked. */
    if ( test_and_clear_bit(_VPF_blocked_in_xen, &v->pause_flags) )
        vcpu_wake(v);
}

/*
 * Given a notification function, return the value to stash in
 * the evtchn->xen_consumer field.
 */
static uint8_t get_xen_consumer(xen_event_channel_notification_t fn)
{
    unsigned int i;

    if ( fn == NULL )
        fn = default_xen_notification_fn;

    for ( i = 0; i < ARRAY_SIZE(xen_consumers); i++ )
    {
        if ( xen_consumers[i] == NULL )
            xen_consumers[i] = fn;
        if ( xen_consumers[i] == fn )
            break;
    }

    BUG_ON(i >= ARRAY_SIZE(xen_consumers));
    return i+1;
}

/* Get the notification function for a given Xen-bound event channel. */
#define xen_notification_fn(e) (xen_consumers[(e)->xen_consumer-1])

static bool virq_is_global(unsigned int virq)
{
    switch ( virq )
    {
    case VIRQ_TIMER:
    case VIRQ_DEBUG:
    case VIRQ_XENOPROF:
    case VIRQ_XENPMU:
        return false;

    case VIRQ_ARCH_0 ... VIRQ_ARCH_7:
        return arch_virq_is_global(virq);
    }

    ASSERT(virq < NR_VIRQS);
    return true;
}


static struct evtchn *alloc_evtchn_bucket(struct domain *d, unsigned int port)
{
    struct evtchn *chn;
    unsigned int i;

    chn = xzalloc_array(struct evtchn, EVTCHNS_PER_BUCKET);
    if ( !chn )
        return NULL;

    for ( i = 0; i < EVTCHNS_PER_BUCKET; i++ )
    {
        if ( xsm_alloc_security_evtchn(&chn[i]) )
        {
            while ( i-- )
                xsm_free_security_evtchn(&chn[i]);
            xfree(chn);
            return NULL;
        }
        chn[i].port = port + i;
        spin_lock_init(&chn[i].lock);
    }
    return chn;
}

static void free_evtchn_bucket(struct domain *d, struct evtchn *bucket)
{
    unsigned int i;

    if ( !bucket )
        return;

    for ( i = 0; i < EVTCHNS_PER_BUCKET; i++ )
        xsm_free_security_evtchn(bucket + i);

    xfree(bucket);
}

int evtchn_allocate_port(struct domain *d, evtchn_port_t port)
{
    if ( port > d->max_evtchn_port || port >= d->max_evtchns )
        return -ENOSPC;

    if ( port_is_valid(d, port) )
    {
        if ( evtchn_from_port(d, port)->state != ECS_FREE ||
             evtchn_port_is_busy(d, port) )
            return -EBUSY;
    }
    else
    {
        struct evtchn *chn;
        struct evtchn **grp;

        if ( !group_from_port(d, port) )
        {
            grp = xzalloc_array(struct evtchn *, BUCKETS_PER_GROUP);
            if ( !grp )
                return -ENOMEM;
            group_from_port(d, port) = grp;
        }

        chn = alloc_evtchn_bucket(d, port);
        if ( !chn )
            return -ENOMEM;
        bucket_from_port(d, port) = chn;

        write_atomic(&d->valid_evtchns, d->valid_evtchns + EVTCHNS_PER_BUCKET);
    }

    return 0;
}

static int get_free_port(struct domain *d)
{
    int            port;

    if ( d->is_dying )
        return -EINVAL;

    for ( port = 0; port <= d->max_evtchn_port; port++ )
    {
        int rc = evtchn_allocate_port(d, port);

        if ( rc == -EBUSY )
            continue;

        return port;
    }

    return -ENOSPC;
}

void evtchn_free(struct domain *d, struct evtchn *chn)
{
    /* Clear pending event to avoid unexpected behavior on re-bind. */
    evtchn_port_clear_pending(d, chn);

    /* Reset binding to vcpu0 when the channel is freed. */
    chn->state          = ECS_FREE;
    chn->notify_vcpu_id = 0;
    chn->xen_consumer   = 0;

    xsm_evtchn_close_post(chn);
}

static long evtchn_alloc_unbound(evtchn_alloc_unbound_t *alloc)
{
    struct evtchn *chn;
    struct domain *d;
    int            port;
    domid_t        dom = alloc->dom;
    long           rc;

    d = rcu_lock_domain_by_any_id(dom);
    if ( d == NULL )
        return -ESRCH;

    spin_lock(&d->event_lock);

    if ( (port = get_free_port(d)) < 0 )
        ERROR_EXIT_DOM(port, d);
    chn = evtchn_from_port(d, port);

    rc = xsm_evtchn_unbound(XSM_TARGET, d, chn, alloc->remote_dom);
    if ( rc )
        goto out;

    spin_lock(&chn->lock);

    chn->state = ECS_UNBOUND;
    if ( (chn->u.unbound.remote_domid = alloc->remote_dom) == DOMID_SELF )
        chn->u.unbound.remote_domid = current->domain->domain_id;
    evtchn_port_init(d, chn);

    spin_unlock(&chn->lock);

    alloc->port = port;

 out:
    spin_unlock(&d->event_lock);
    rcu_unlock_domain(d);

    return rc;
}


static void double_evtchn_lock(struct evtchn *lchn, struct evtchn *rchn)
{
    if ( lchn < rchn )
    {
        spin_lock(&lchn->lock);
        spin_lock(&rchn->lock);
    }
    else
    {
        if ( lchn != rchn )
            spin_lock(&rchn->lock);
        spin_lock(&lchn->lock);
    }
}

static void double_evtchn_unlock(struct evtchn *lchn, struct evtchn *rchn)
{
    spin_unlock(&lchn->lock);
    if ( lchn != rchn )
        spin_unlock(&rchn->lock);
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

    rc = xsm_evtchn_interdomain(XSM_HOOK, ld, lchn, rd, rchn);
    if ( rc )
        goto out;

    double_evtchn_lock(lchn, rchn);

    lchn->u.interdomain.remote_dom  = rd;
    lchn->u.interdomain.remote_port = rport;
    lchn->state                     = ECS_INTERDOMAIN;
    evtchn_port_init(ld, lchn);
    
    rchn->u.interdomain.remote_dom  = ld;
    rchn->u.interdomain.remote_port = lport;
    rchn->state                     = ECS_INTERDOMAIN;

    /*
     * We may have lost notifications on the remote unbound port. Fix that up
     * here by conservatively always setting a notification on the local port.
     */
    evtchn_port_set_pending(ld, lchn->notify_vcpu_id, lchn);

    double_evtchn_unlock(lchn, rchn);

    bind->local_port = lport;

 out:
    spin_unlock(&ld->event_lock);
    if ( ld != rd )
        spin_unlock(&rd->event_lock);
    
    rcu_unlock_domain(rd);

    return rc;
}


int evtchn_bind_virq(evtchn_bind_virq_t *bind, evtchn_port_t port)
{
    struct evtchn *chn;
    struct vcpu   *v;
    struct domain *d = current->domain;
    int            virq = bind->virq, vcpu = bind->vcpu;
    int            rc = 0;

    if ( (virq < 0) || (virq >= ARRAY_SIZE(v->virq_to_evtchn)) )
        return -EINVAL;

    if ( virq_is_global(virq) && (vcpu != 0) )
        return -EINVAL;

    if ( (vcpu < 0) || (vcpu >= d->max_vcpus) ||
         ((v = d->vcpu[vcpu]) == NULL) )
        return -ENOENT;

    spin_lock(&d->event_lock);

    if ( v->virq_to_evtchn[virq] != 0 )
        ERROR_EXIT(-EEXIST);

    if ( port != 0 )
    {
        if ( (rc = evtchn_allocate_port(d, port)) != 0 )
            ERROR_EXIT(rc);
    }
    else
    {
        int alloc_port = get_free_port(d);

        if ( alloc_port < 0 )
            ERROR_EXIT(alloc_port);
        port = alloc_port;
    }

    chn = evtchn_from_port(d, port);

    spin_lock(&chn->lock);

    chn->state          = ECS_VIRQ;
    chn->notify_vcpu_id = vcpu;
    chn->u.virq         = virq;
    evtchn_port_init(d, chn);

    spin_unlock(&chn->lock);

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

    spin_lock(&d->event_lock);

    if ( (port = get_free_port(d)) < 0 )
        ERROR_EXIT(port);

    chn = evtchn_from_port(d, port);

    spin_lock(&chn->lock);

    chn->state          = ECS_IPI;
    chn->notify_vcpu_id = vcpu;
    evtchn_port_init(d, chn);

    spin_unlock(&chn->lock);

    bind->port = port;

 out:
    spin_unlock(&d->event_lock);

    return rc;
}


static void link_pirq_port(int port, struct evtchn *chn, struct vcpu *v)
{
    chn->u.pirq.prev_port = 0;
    chn->u.pirq.next_port = v->pirq_evtchn_head;
    if ( v->pirq_evtchn_head )
        evtchn_from_port(v->domain, v->pirq_evtchn_head)
            ->u.pirq.prev_port = port;
    v->pirq_evtchn_head = port;
}

static void unlink_pirq_port(struct evtchn *chn, struct vcpu *v)
{
    struct domain *d = v->domain;

    if ( chn->u.pirq.prev_port )
        evtchn_from_port(d, chn->u.pirq.prev_port)->u.pirq.next_port =
            chn->u.pirq.next_port;
    else
        v->pirq_evtchn_head = chn->u.pirq.next_port;
    if ( chn->u.pirq.next_port )
        evtchn_from_port(d, chn->u.pirq.next_port)->u.pirq.prev_port =
            chn->u.pirq.prev_port;
}


static long evtchn_bind_pirq(evtchn_bind_pirq_t *bind)
{
    struct evtchn *chn;
    struct domain *d = current->domain;
    struct vcpu   *v = d->vcpu[0];
    struct pirq   *info;
    int            port, pirq = bind->pirq;
    long           rc;

    if ( (pirq < 0) || (pirq >= d->nr_pirqs) )
        return -EINVAL;

    if ( !is_hvm_domain(d) && !pirq_access_permitted(d, pirq) )
        return -EPERM;

    spin_lock(&d->event_lock);

    if ( pirq_to_evtchn(d, pirq) != 0 )
        ERROR_EXIT(-EEXIST);

    if ( (port = get_free_port(d)) < 0 )
        ERROR_EXIT(port);

    chn = evtchn_from_port(d, port);

    info = pirq_get_info(d, pirq);
    if ( !info )
        ERROR_EXIT(-ENOMEM);
    info->evtchn = port;
    rc = (!is_hvm_domain(d)
          ? pirq_guest_bind(v, info,
                            !!(bind->flags & BIND_PIRQ__WILL_SHARE))
          : 0);
    if ( rc != 0 )
    {
        info->evtchn = 0;
        pirq_cleanup_check(info, d);
        goto out;
    }

    spin_lock(&chn->lock);

    chn->state  = ECS_PIRQ;
    chn->u.pirq.irq = pirq;
    link_pirq_port(port, chn, v);
    evtchn_port_init(d, chn);

    spin_unlock(&chn->lock);

    bind->port = port;

    arch_evtchn_bind_pirq(d, pirq);

 out:
    spin_unlock(&d->event_lock);

    return rc;
}


int evtchn_close(struct domain *d1, int port1, bool guest)
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
    if ( unlikely(consumer_is_xen(chn1)) && guest )
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

    case ECS_PIRQ: {
        struct pirq *pirq = pirq_info(d1, chn1->u.pirq.irq);

        if ( !pirq )
            break;
        if ( !is_hvm_domain(d1) )
            pirq_guest_unbind(d1, pirq);
        pirq->evtchn = 0;
        pirq_cleanup_check(pirq, d1);
        unlink_pirq_port(chn1, d1->vcpu[chn1->notify_vcpu_id]);
#ifdef CONFIG_X86
        if ( is_hvm_domain(d1) && domain_pirq_to_irq(d1, pirq->pirq) > 0 )
            unmap_domain_pirq_emuirq(d1, pirq->pirq);
#endif
        break;
    }

    case ECS_VIRQ:
        for_each_vcpu ( d1, v )
        {
            if ( v->virq_to_evtchn[chn1->u.virq] != port1 )
                continue;
            v->virq_to_evtchn[chn1->u.virq] = 0;
            spin_barrier(&v->virq_lock);
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

        double_evtchn_lock(chn1, chn2);

        evtchn_free(d1, chn1);

        chn2->state = ECS_UNBOUND;
        chn2->u.unbound.remote_domid = d1->domain_id;

        double_evtchn_unlock(chn1, chn2);

        goto out;

    default:
        BUG();
    }

    spin_lock(&chn1->lock);
    evtchn_free(d1, chn1);
    spin_unlock(&chn1->lock);

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

int evtchn_send(struct domain *ld, unsigned int lport)
{
    struct evtchn *lchn, *rchn;
    struct domain *rd;
    int            rport, ret = 0;

    if ( !port_is_valid(ld, lport) )
        return -EINVAL;

    lchn = evtchn_from_port(ld, lport);

    spin_lock(&lchn->lock);

    /* Guest cannot send via a Xen-attached event channel. */
    if ( unlikely(consumer_is_xen(lchn)) )
    {
        ret = -EINVAL;
        goto out;
    }

    ret = xsm_evtchn_send(XSM_HOOK, ld, lchn);
    if ( ret )
        goto out;

    switch ( lchn->state )
    {
    case ECS_INTERDOMAIN:
        rd    = lchn->u.interdomain.remote_dom;
        rport = lchn->u.interdomain.remote_port;
        rchn  = evtchn_from_port(rd, rport);
        if ( consumer_is_xen(rchn) )
            xen_notification_fn(rchn)(rd->vcpu[rchn->notify_vcpu_id], rport);
        else
            evtchn_port_set_pending(rd, rchn->notify_vcpu_id, rchn);
        break;
    case ECS_IPI:
        evtchn_port_set_pending(ld, lchn->notify_vcpu_id, lchn);
        break;
    case ECS_UNBOUND:
        /* silently drop the notification */
        break;
    default:
        ret = -EINVAL;
    }

out:
    spin_unlock(&lchn->lock);

    return ret;
}

int guest_enabled_event(struct vcpu *v, uint32_t virq)
{
    return ((v != NULL) && (v->virq_to_evtchn[virq] != 0));
}

void send_guest_vcpu_virq(struct vcpu *v, uint32_t virq)
{
    unsigned long flags;
    int port;
    struct domain *d;

    ASSERT(!virq_is_global(virq));

    spin_lock_irqsave(&v->virq_lock, flags);

    port = v->virq_to_evtchn[virq];
    if ( unlikely(port == 0) )
        goto out;

    d = v->domain;
    evtchn_port_set_pending(d, v->vcpu_id, evtchn_from_port(d, port));

 out:
    spin_unlock_irqrestore(&v->virq_lock, flags);
}

static void send_guest_global_virq(struct domain *d, uint32_t virq)
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
    evtchn_port_set_pending(d, chn->notify_vcpu_id, chn);

 out:
    spin_unlock_irqrestore(&v->virq_lock, flags);
}

void send_guest_pirq(struct domain *d, const struct pirq *pirq)
{
    int port;
    struct evtchn *chn;

    /*
     * PV guests: It should not be possible to race with __evtchn_close(). The
     *     caller of this function must synchronise with pirq_guest_unbind().
     * HVM guests: Port is legitimately zero when the guest disables the
     *     emulated interrupt/evtchn.
     */
    if ( pirq == NULL || (port = pirq->evtchn) == 0 )
    {
        BUG_ON(!is_hvm_domain(d));
        return;
    }

    chn = evtchn_from_port(d, port);
    evtchn_port_set_pending(d, chn->notify_vcpu_id, chn);
}

static struct domain *global_virq_handlers[NR_VIRQS] __read_mostly;

static DEFINE_SPINLOCK(global_virq_handlers_lock);

void send_global_virq(uint32_t virq)
{
    ASSERT(virq_is_global(virq));

    send_guest_global_virq(global_virq_handlers[virq] ?: hardware_domain, virq);
}

int set_global_virq_handler(struct domain *d, uint32_t virq)
{
    struct domain *old;

    if (virq >= NR_VIRQS)
        return -EINVAL;
    if (!virq_is_global(virq))
        return -EINVAL;

    if (global_virq_handlers[virq] == d)
        return 0;

    if (unlikely(!get_domain(d)))
        return -EINVAL;

    spin_lock(&global_virq_handlers_lock);
    old = global_virq_handlers[virq];
    global_virq_handlers[virq] = d;
    spin_unlock(&global_virq_handlers_lock);

    if (old != NULL)
        put_domain(old);

    return 0;
}

static void clear_global_virq_handlers(struct domain *d)
{
    uint32_t virq;
    int put_count = 0;

    spin_lock(&global_virq_handlers_lock);

    for (virq = 0; virq < NR_VIRQS; virq++)
    {
        if (global_virq_handlers[virq] == d)
        {
            global_virq_handlers[virq] = NULL;
            put_count++;
        }
    }

    spin_unlock(&global_virq_handlers_lock);

    while (put_count)
    {
        put_domain(d);
        put_count--;
    }
}

int evtchn_status(evtchn_status_t *status)
{
    struct domain   *d;
    domid_t          dom = status->dom;
    int              port = status->port;
    struct evtchn   *chn;
    long             rc = 0;

    d = rcu_lock_domain_by_any_id(dom);
    if ( d == NULL )
        return -ESRCH;

    spin_lock(&d->event_lock);

    if ( !port_is_valid(d, port) )
    {
        rc = -EINVAL;
        goto out;
    }

    chn = evtchn_from_port(d, port);

    rc = xsm_evtchn_status(XSM_TARGET, d, chn);
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
        status->u.pirq = chn->u.pirq.irq;
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

    spin_lock(&d->event_lock);

    if ( !port_is_valid(d, port) )
    {
        rc = -EINVAL;
        goto out;
    }

    chn = evtchn_from_port(d, port);

    /* Guest cannot re-bind a Xen-attached event channel. */
    if ( unlikely(consumer_is_xen(chn)) )
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
        chn->notify_vcpu_id = vcpu_id;
        break;
    case ECS_PIRQ:
        if ( chn->notify_vcpu_id == vcpu_id )
            break;
        unlink_pirq_port(chn, d->vcpu[chn->notify_vcpu_id]);
        chn->notify_vcpu_id = vcpu_id;
        pirq_set_affinity(d, chn->u.pirq.irq,
                          cpumask_of(d->vcpu[vcpu_id]->processor));
        link_pirq_port(port, chn, d->vcpu[vcpu_id]);
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
    struct evtchn *evtchn;

    if ( unlikely(!port_is_valid(d, port)) )
        return -EINVAL;

    evtchn = evtchn_from_port(d, port);
    evtchn_port_unmask(d, evtchn);

    return 0;
}


int evtchn_reset(struct domain *d)
{
    unsigned int i;

    if ( d != current->domain && !d->controller_pause_count )
        return -EINVAL;

    for ( i = 0; port_is_valid(d, i); i++ )
        evtchn_close(d, i, 1);

    spin_lock(&d->event_lock);

    if ( d->evtchn_fifo )
    {
        /* Switching back to 2-level ABI. */
        evtchn_fifo_destroy(d);
        evtchn_2l_init(d);
    }

    spin_unlock(&d->event_lock);

    return 0;
}

static long evtchn_set_priority(const struct evtchn_set_priority *set_priority)
{
    struct domain *d = current->domain;
    unsigned int port = set_priority->port;
    long ret;

    spin_lock(&d->event_lock);

    if ( !port_is_valid(d, port) )
    {
        spin_unlock(&d->event_lock);
        return -EINVAL;
    }

    ret = evtchn_port_set_priority(d, evtchn_from_port(d, port),
                                   set_priority->priority);

    spin_unlock(&d->event_lock);

    return ret;
}

long do_event_channel_op(int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    long rc;

    switch ( cmd )
    {
    case EVTCHNOP_alloc_unbound: {
        struct evtchn_alloc_unbound alloc_unbound;
        if ( copy_from_guest(&alloc_unbound, arg, 1) != 0 )
            return -EFAULT;
        rc = evtchn_alloc_unbound(&alloc_unbound);
        if ( !rc && __copy_to_guest(arg, &alloc_unbound, 1) )
            rc = -EFAULT; /* Cleaning up here would be a mess! */
        break;
    }

    case EVTCHNOP_bind_interdomain: {
        struct evtchn_bind_interdomain bind_interdomain;
        if ( copy_from_guest(&bind_interdomain, arg, 1) != 0 )
            return -EFAULT;
        rc = evtchn_bind_interdomain(&bind_interdomain);
        if ( !rc && __copy_to_guest(arg, &bind_interdomain, 1) )
            rc = -EFAULT; /* Cleaning up here would be a mess! */
        break;
    }

    case EVTCHNOP_bind_virq: {
        struct evtchn_bind_virq bind_virq;
        if ( copy_from_guest(&bind_virq, arg, 1) != 0 )
            return -EFAULT;
        rc = evtchn_bind_virq(&bind_virq, 0);
        if ( !rc && __copy_to_guest(arg, &bind_virq, 1) )
            rc = -EFAULT; /* Cleaning up here would be a mess! */
        break;
    }

    case EVTCHNOP_bind_ipi: {
        struct evtchn_bind_ipi bind_ipi;
        if ( copy_from_guest(&bind_ipi, arg, 1) != 0 )
            return -EFAULT;
        rc = evtchn_bind_ipi(&bind_ipi);
        if ( !rc && __copy_to_guest(arg, &bind_ipi, 1) )
            rc = -EFAULT; /* Cleaning up here would be a mess! */
        break;
    }

    case EVTCHNOP_bind_pirq: {
        struct evtchn_bind_pirq bind_pirq;
        if ( copy_from_guest(&bind_pirq, arg, 1) != 0 )
            return -EFAULT;
        rc = evtchn_bind_pirq(&bind_pirq);
        if ( !rc && __copy_to_guest(arg, &bind_pirq, 1) )
            rc = -EFAULT; /* Cleaning up here would be a mess! */
        break;
    }

    case EVTCHNOP_close: {
        struct evtchn_close close;
        if ( copy_from_guest(&close, arg, 1) != 0 )
            return -EFAULT;
        rc = evtchn_close(current->domain, close.port, 1);
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
        if ( !rc && __copy_to_guest(arg, &status, 1) )
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
        struct domain *d;

        if ( copy_from_guest(&reset, arg, 1) != 0 )
            return -EFAULT;

        d = rcu_lock_domain_by_any_id(reset.dom);
        if ( d == NULL )
            return -ESRCH;

        rc = xsm_evtchn_reset(XSM_TARGET, current->domain, d);
        if ( !rc )
            rc = evtchn_reset(d);

        rcu_unlock_domain(d);
        break;
    }

    case EVTCHNOP_init_control: {
        struct evtchn_init_control init_control;
        if ( copy_from_guest(&init_control, arg, 1) != 0 )
            return -EFAULT;
        rc = evtchn_fifo_init_control(&init_control);
        if ( !rc && __copy_to_guest(arg, &init_control, 1) )
            rc = -EFAULT;
        break;
    }

    case EVTCHNOP_expand_array: {
        struct evtchn_expand_array expand_array;
        if ( copy_from_guest(&expand_array, arg, 1) != 0 )
            return -EFAULT;
        rc = evtchn_fifo_expand_array(&expand_array);
        break;
    }

    case EVTCHNOP_set_priority: {
        struct evtchn_set_priority set_priority;
        if ( copy_from_guest(&set_priority, arg, 1) != 0 )
            return -EFAULT;
        rc = evtchn_set_priority(&set_priority);
        break;
    }

    default:
        rc = -ENOSYS;
        break;
    }

    return rc;
}


int alloc_unbound_xen_event_channel(
    struct domain *ld, unsigned int lvcpu, domid_t remote_domid,
    xen_event_channel_notification_t notification_fn)
{
    struct evtchn *chn;
    int            port, rc;

    spin_lock(&ld->event_lock);

    rc = get_free_port(ld);
    if ( rc < 0 )
        goto out;
    port = rc;
    chn = evtchn_from_port(ld, port);

    rc = xsm_evtchn_unbound(XSM_TARGET, ld, chn, remote_domid);
    if ( rc )
        goto out;

    spin_lock(&chn->lock);

    chn->state = ECS_UNBOUND;
    chn->xen_consumer = get_xen_consumer(notification_fn);
    chn->notify_vcpu_id = lvcpu;
    chn->u.unbound.remote_domid = remote_domid;

    spin_unlock(&chn->lock);

 out:
    spin_unlock(&ld->event_lock);

    return rc < 0 ? rc : port;
}

void free_xen_event_channel(struct domain *d, int port)
{
    BUG_ON(!port_is_valid(d, port));

    evtchn_close(d, port, 0);
}


void notify_via_xen_event_channel(struct domain *ld, int lport)
{
    struct evtchn *lchn, *rchn;
    struct domain *rd;

    ASSERT(port_is_valid(ld, lport));
    lchn = evtchn_from_port(ld, lport);

    spin_lock(&lchn->lock);

    if ( likely(lchn->state == ECS_INTERDOMAIN) )
    {
        ASSERT(consumer_is_xen(lchn));
        rd    = lchn->u.interdomain.remote_dom;
        rchn  = evtchn_from_port(rd, lchn->u.interdomain.remote_port);
        evtchn_port_set_pending(rd, rchn->notify_vcpu_id, rchn);
    }

    spin_unlock(&lchn->lock);
}

void evtchn_check_pollers(struct domain *d, unsigned int port)
{
    struct vcpu *v;
    unsigned int vcpuid;

    /* Check if some VCPU might be polling for this event. */
    if ( likely(bitmap_empty(d->poll_mask, d->max_vcpus)) )
        return;

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
}

int evtchn_init(struct domain *d)
{
    evtchn_2l_init(d);
    d->max_evtchn_port = INT_MAX;

    d->evtchn = alloc_evtchn_bucket(d, 0);
    if ( !d->evtchn )
        return -ENOMEM;
    d->valid_evtchns = EVTCHNS_PER_BUCKET;

    spin_lock_init_prof(d, event_lock);
    if ( get_free_port(d) != 0 )
    {
        free_evtchn_bucket(d, d->evtchn);
        return -EINVAL;
    }
    evtchn_from_port(d, 0)->state = ECS_RESERVED;

#if MAX_VIRT_CPUS > BITS_PER_LONG
    d->poll_mask = xzalloc_array(unsigned long,
                                 BITS_TO_LONGS(domain_max_vcpus(d)));
    if ( !d->poll_mask )
    {
        free_evtchn_bucket(d, d->evtchn);
        return -ENOMEM;
    }
#endif

    return 0;
}


void evtchn_destroy(struct domain *d)
{
    unsigned int i;

    /* After this barrier no new event-channel allocations can occur. */
    BUG_ON(!d->is_dying);
    spin_barrier(&d->event_lock);

    /* Close all existing event channels. */
    for ( i = 0; port_is_valid(d, i); i++ )
        evtchn_close(d, i, 0);

    clear_global_virq_handlers(d);

    evtchn_fifo_destroy(d);
}


void evtchn_destroy_final(struct domain *d)
{
    unsigned int i, j;

    /* Free all event-channel buckets. */
    for ( i = 0; i < NR_EVTCHN_GROUPS; i++ )
    {
        if ( !d->evtchn_group[i] )
            continue;
        for ( j = 0; j < BUCKETS_PER_GROUP; j++ )
            free_evtchn_bucket(d, d->evtchn_group[i][j]);
        xfree(d->evtchn_group[i]);
    }
    free_evtchn_bucket(d, d->evtchn);

#if MAX_VIRT_CPUS > BITS_PER_LONG
    xfree(d->poll_mask);
    d->poll_mask = NULL;
#endif
}


void evtchn_move_pirqs(struct vcpu *v)
{
    struct domain *d = v->domain;
    const cpumask_t *mask = cpumask_of(v->processor);
    unsigned int port;
    struct evtchn *chn;

    spin_lock(&d->event_lock);
    for ( port = v->pirq_evtchn_head; port; port = chn->u.pirq.next_port )
    {
        chn = evtchn_from_port(d, port);
        pirq_set_affinity(d, chn->u.pirq.irq, mask);
    }
    spin_unlock(&d->event_lock);
}


static void domain_dump_evtchn_info(struct domain *d)
{
    unsigned int port;
    int irq;

    bitmap_scnlistprintf(keyhandler_scratch, sizeof(keyhandler_scratch),
                         d->poll_mask, d->max_vcpus);
    printk("Event channel information for domain %d:\n"
           "Polling vCPUs: {%s}\n"
           "    port [p/m/s]\n", d->domain_id, keyhandler_scratch);

    spin_lock(&d->event_lock);

    for ( port = 1; port < d->max_evtchns; ++port )
    {
        const struct evtchn *chn;
        char *ssid;

        if ( !port_is_valid(d, port) )
            continue;
        chn = evtchn_from_port(d, port);
        if ( chn->state == ECS_FREE )
            continue;

        printk("    %4u [%d/%d/",
               port,
               evtchn_port_is_pending(d, port),
               evtchn_port_is_masked(d, port));
        evtchn_port_print_state(d, chn);
        printk("]: s=%d n=%d x=%d",
               chn->state, chn->notify_vcpu_id, chn->xen_consumer);

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
            irq = domain_pirq_to_irq(d, chn->u.pirq.irq);
            printk(" p=%d i=%d", chn->u.pirq.irq, irq);
            break;
        case ECS_VIRQ:
            printk(" v=%d", chn->u.virq);
            break;
        }

        ssid = xsm_show_security_evtchn(d, chn);
        if (ssid) {
            printk(" Z=%s\n", ssid);
            xfree(ssid);
        } else {
            printk("\n");
        }
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

static int __init dump_evtchn_info_key_init(void)
{
    register_keyhandler('e', dump_evtchn_info, "dump evtchn info", 1);
    return 0;
}
__initcall(dump_evtchn_info_key_init);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
