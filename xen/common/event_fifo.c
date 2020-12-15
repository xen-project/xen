/*
 * FIFO event channel management.
 *
 * Copyright (C) 2013 Citrix Systems R&D Ltd.
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2 or later.  See the file COPYING for more details.
 */

#include "event_channel.h"

#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/paging.h>
#include <xen/mm.h>
#include <xen/domain_page.h>

#include <asm/guest_atomics.h>

#include <public/event_channel.h>

struct evtchn_fifo_queue {
    uint32_t *head; /* points into control block */
    uint32_t tail;
    uint8_t priority;
    spinlock_t lock;
};

struct evtchn_fifo_vcpu {
    struct evtchn_fifo_control_block *control_block;
    struct evtchn_fifo_queue queue[EVTCHN_FIFO_MAX_QUEUES];
};

#define EVTCHN_FIFO_EVENT_WORDS_PER_PAGE (PAGE_SIZE / sizeof(event_word_t))
#define EVTCHN_FIFO_MAX_EVENT_ARRAY_PAGES \
    (EVTCHN_FIFO_NR_CHANNELS / EVTCHN_FIFO_EVENT_WORDS_PER_PAGE)

struct evtchn_fifo_domain {
    event_word_t *event_array[EVTCHN_FIFO_MAX_EVENT_ARRAY_PAGES];
    unsigned int num_evtchns;
};

union evtchn_fifo_lastq {
    uint32_t raw;
    struct {
        uint8_t last_priority;
        uint16_t last_vcpu_id;
    };
};

static inline event_word_t *evtchn_fifo_word_from_port(const struct domain *d,
                                                       unsigned int port)
{
    unsigned int p, w;

    /*
     * Callers aren't required to hold d->event_lock, so we need to synchronize
     * with evtchn_fifo_init_control() setting d->evtchn_port_ops /after/
     * d->evtchn_fifo.
     */
    smp_rmb();

    if ( unlikely(port >= d->evtchn_fifo->num_evtchns) )
        return NULL;

    /*
     * Callers aren't required to hold d->event_lock, so we need to synchronize
     * with add_page_to_event_array().
     */
    smp_rmb();

    p = array_index_nospec(port / EVTCHN_FIFO_EVENT_WORDS_PER_PAGE,
                           d->evtchn_fifo->num_evtchns);
    w = port % EVTCHN_FIFO_EVENT_WORDS_PER_PAGE;

    return d->evtchn_fifo->event_array[p] + w;
}

static void evtchn_fifo_init(struct domain *d, struct evtchn *evtchn)
{
    event_word_t *word;

    evtchn->priority = EVTCHN_FIFO_PRIORITY_DEFAULT;

    /*
     * If this event is still linked, the first event may be delivered
     * on the wrong VCPU or with an unexpected priority.
     */
    word = evtchn_fifo_word_from_port(d, evtchn->port);
    if ( word && guest_test_bit(d, EVTCHN_FIFO_LINKED, word) )
        gdprintk(XENLOG_WARNING, "domain %d, port %d already on a queue\n",
                 d->domain_id, evtchn->port);
}

static int try_set_link(event_word_t *word, event_word_t *w, uint32_t link)
{
    event_word_t new, old;

    if ( !(*w & (1 << EVTCHN_FIFO_LINKED)) )
        return 0;

    old = *w;
    new = (old & ~((1 << EVTCHN_FIFO_BUSY) | EVTCHN_FIFO_LINK_MASK)) | link;
    *w = cmpxchg(word, old, new);
    if ( *w == old )
        return 1;

    return -EAGAIN;
}

/*
 * Atomically set the LINK field iff it is still LINKED.
 *
 * The guest is only permitted to make the following changes to a
 * LINKED event.
 *
 * - set MASKED
 * - clear MASKED
 * - clear PENDING
 * - clear LINKED (and LINK)
 *
 * We block unmasking by the guest by marking the tail word as BUSY,
 * therefore, the cmpxchg() may fail at most 4 times.
 */
static bool_t evtchn_fifo_set_link(struct domain *d, event_word_t *word,
                                   uint32_t link)
{
    event_word_t w;
    unsigned int try;
    int ret;

    w = read_atomic(word);

    ret = try_set_link(word, &w, link);
    if ( ret >= 0 )
        return ret;

    /* Lock the word to prevent guest unmasking. */
    guest_set_bit(d, EVTCHN_FIFO_BUSY, word);

    w = read_atomic(word);

    for ( try = 0; try < 4; try++ )
    {
        ret = try_set_link(word, &w, link);
        if ( ret >= 0 )
        {
            if ( ret == 0 )
                guest_clear_bit(d, EVTCHN_FIFO_BUSY, word);
            return ret;
        }
    }
    gdprintk(XENLOG_WARNING, "domain %d, port %d not linked\n",
             d->domain_id, link);
    guest_clear_bit(d, EVTCHN_FIFO_BUSY, word);
    return 1;
}

static void evtchn_fifo_set_pending(struct vcpu *v, struct evtchn *evtchn)
{
    struct domain *d = v->domain;
    unsigned int port;
    event_word_t *word;
    unsigned long flags;
    bool_t was_pending;
    struct evtchn_fifo_queue *q, *old_q;
    unsigned int try;
    bool linked = true;

    port = evtchn->port;
    word = evtchn_fifo_word_from_port(d, port);

    /*
     * Event array page may not exist yet, save the pending state for
     * when the page is added.
     */
    if ( unlikely(!word) )
    {
        evtchn->pending = true;
        return;
    }

    /*
     * Lock all queues related to the event channel (in case of a queue change
     * this might be two).
     * It is mandatory to do that before setting and testing the PENDING bit
     * and to hold the current queue lock until the event has been put into the
     * list of pending events in order to avoid waking up a guest without the
     * event being visibly pending in the guest.
     */
    for ( try = 0; try < 3; try++ )
    {
        union evtchn_fifo_lastq lastq;
        const struct vcpu *old_v;

        lastq.raw = read_atomic(&evtchn->fifo_lastq);
        old_v = d->vcpu[lastq.last_vcpu_id];

        q = &v->evtchn_fifo->queue[evtchn->priority];
        old_q = &old_v->evtchn_fifo->queue[lastq.last_priority];

        if ( q == old_q )
            spin_lock_irqsave(&q->lock, flags);
        else if ( q < old_q )
        {
            spin_lock_irqsave(&q->lock, flags);
            spin_lock(&old_q->lock);
        }
        else
        {
            spin_lock_irqsave(&old_q->lock, flags);
            spin_lock(&q->lock);
        }

        lastq.raw = read_atomic(&evtchn->fifo_lastq);
        old_v = d->vcpu[lastq.last_vcpu_id];
        if ( q == &v->evtchn_fifo->queue[evtchn->priority] &&
             old_q == &old_v->evtchn_fifo->queue[lastq.last_priority] )
            break;

        if ( q != old_q )
            spin_unlock(&old_q->lock);
        spin_unlock_irqrestore(&q->lock, flags);
    }

    was_pending = guest_test_and_set_bit(d, EVTCHN_FIFO_PENDING, word);

    /* If we didn't get the lock bail out. */
    if ( try == 3 )
    {
        gprintk(XENLOG_WARNING,
                "%pd port %u lost event (too many queue changes)\n",
                d, evtchn->port);
        goto done;
    }

    /*
     * Control block not mapped.  The guest must not unmask an
     * event until the control block is initialized, so we can
     * just drop the event.
     */
    if ( unlikely(!v->evtchn_fifo->control_block) )
    {
        printk(XENLOG_G_WARNING
               "%pv has no FIFO event channel control block\n", v);
        goto unlock;
    }

    /*
     * Link the event if it unmasked and not already linked.
     */
    if ( !guest_test_bit(d, EVTCHN_FIFO_MASKED, word) &&
         /*
          * This also acts as the read counterpart of the smp_wmb() in
          * map_control_block().
          */
         !guest_test_and_set_bit(d, EVTCHN_FIFO_LINKED, word) )
    {
        /*
         * If this event was a tail, the old queue is now empty and
         * its tail must be invalidated to prevent adding an event to
         * the old queue from corrupting the new queue.
         */
        if ( old_q->tail == port )
            old_q->tail = 0;

        /* Moved to a different queue? */
        if ( old_q != q )
        {
            union evtchn_fifo_lastq lastq = { };

            lastq.last_vcpu_id = v->vcpu_id;
            lastq.last_priority = q->priority;
            write_atomic(&evtchn->fifo_lastq, lastq.raw);

            spin_unlock(&old_q->lock);
            old_q = q;
        }

        /*
         * Atomically link the tail to port iff the tail is linked.
         * If the tail is unlinked the queue is empty.
         *
         * If port is the same as tail, the queue is empty but q->tail
         * will appear linked as we just set LINKED above.
         *
         * If the queue is empty (i.e., we haven't linked to the new
         * event), head must be updated.
         */
        linked = false;
        if ( q->tail )
        {
            event_word_t *tail_word;

            tail_word = evtchn_fifo_word_from_port(d, q->tail);
            linked = evtchn_fifo_set_link(d, tail_word, port);
        }
        if ( !linked )
            write_atomic(q->head, port);
        q->tail = port;
    }

 unlock:
    if ( q != old_q )
        spin_unlock(&old_q->lock);
    spin_unlock_irqrestore(&q->lock, flags);

 done:
    if ( !linked &&
         !guest_test_and_set_bit(d, q->priority,
                                 &v->evtchn_fifo->control_block->ready) )
        vcpu_mark_events_pending(v);

    if ( !was_pending )
        evtchn_check_pollers(d, port);
}

static void evtchn_fifo_clear_pending(struct domain *d, struct evtchn *evtchn)
{
    event_word_t *word;

    word = evtchn_fifo_word_from_port(d, evtchn->port);
    if ( unlikely(!word) )
        return;

    /*
     * Just clear the P bit.
     *
     * No need to unlink as the guest will unlink and ignore
     * non-pending events.
     */
    guest_clear_bit(d, EVTCHN_FIFO_PENDING, word);
}

static void evtchn_fifo_unmask(struct domain *d, struct evtchn *evtchn)
{
    struct vcpu *v = d->vcpu[evtchn->notify_vcpu_id];
    event_word_t *word;

    word = evtchn_fifo_word_from_port(d, evtchn->port);
    if ( unlikely(!word) )
        return;

    guest_clear_bit(d, EVTCHN_FIFO_MASKED, word);

    /* Relink if pending. */
    if ( guest_test_bit(d, EVTCHN_FIFO_PENDING, word) )
        evtchn_fifo_set_pending(v, evtchn);
}

static bool evtchn_fifo_is_pending(const struct domain *d,
                                   const struct evtchn *evtchn)
{
    const event_word_t *word = evtchn_fifo_word_from_port(d, evtchn->port);

    return word && guest_test_bit(d, EVTCHN_FIFO_PENDING, word);
}

static bool_t evtchn_fifo_is_masked(const struct domain *d,
                                    const struct evtchn *evtchn)
{
    const event_word_t *word = evtchn_fifo_word_from_port(d, evtchn->port);

    return !word || guest_test_bit(d, EVTCHN_FIFO_MASKED, word);
}

static bool_t evtchn_fifo_is_busy(const struct domain *d,
                                  const struct evtchn *evtchn)
{
    const event_word_t *word = evtchn_fifo_word_from_port(d, evtchn->port);

    return word && guest_test_bit(d, EVTCHN_FIFO_LINKED, word);
}

static int evtchn_fifo_set_priority(struct domain *d, struct evtchn *evtchn,
                                    unsigned int priority)
{
    if ( priority > EVTCHN_FIFO_PRIORITY_MIN )
        return -EINVAL;

    /*
     * Only need to switch to the new queue for future events. If the
     * event is already pending or in the process of being linked it
     * will be on the old queue -- this is fine.
     */
    evtchn->priority = priority;

    return 0;
}

static void evtchn_fifo_print_state(struct domain *d,
                                    const struct evtchn *evtchn)
{
    event_word_t *word;

    word = evtchn_fifo_word_from_port(d, evtchn->port);
    if ( !word )
        printk("?     ");
    else if ( guest_test_bit(d, EVTCHN_FIFO_LINKED, word) )
        printk("%c %-4u", guest_test_bit(d, EVTCHN_FIFO_BUSY, word) ? 'B' : ' ',
               *word & EVTCHN_FIFO_LINK_MASK);
    else
        printk("%c -   ", guest_test_bit(d, EVTCHN_FIFO_BUSY, word) ? 'B' : ' ');
}

static const struct evtchn_port_ops evtchn_port_ops_fifo =
{
    .init          = evtchn_fifo_init,
    .set_pending   = evtchn_fifo_set_pending,
    .clear_pending = evtchn_fifo_clear_pending,
    .unmask        = evtchn_fifo_unmask,
    .is_pending    = evtchn_fifo_is_pending,
    .is_masked     = evtchn_fifo_is_masked,
    .is_busy       = evtchn_fifo_is_busy,
    .set_priority  = evtchn_fifo_set_priority,
    .print_state   = evtchn_fifo_print_state,
};

static int map_guest_page(struct domain *d, uint64_t gfn, void **virt)
{
    struct page_info *p;

    p = get_page_from_gfn(d, gfn, NULL, P2M_ALLOC);
    if ( !p )
        return -EINVAL;

    if ( !get_page_type(p, PGT_writable_page) )
    {
        put_page(p);
        return -EINVAL;
    }

    *virt = __map_domain_page_global(p);
    if ( !*virt )
    {
        put_page_and_type(p);
        return -ENOMEM;
    }
    return 0;
}

static void unmap_guest_page(void *virt)
{
    struct page_info *page;

    if ( !virt )
        return;

    virt = (void *)((unsigned long)virt & PAGE_MASK);
    page = mfn_to_page(domain_page_map_to_mfn(virt));

    unmap_domain_page_global(virt);
    put_page_and_type(page);
}

static void init_queue(struct vcpu *v, struct evtchn_fifo_queue *q,
                       unsigned int i)
{
    spin_lock_init(&q->lock);
    q->priority = i;
}

static int setup_control_block(struct vcpu *v)
{
    struct evtchn_fifo_vcpu *efv;
    unsigned int i;

    efv = xzalloc(struct evtchn_fifo_vcpu);
    if ( !efv )
        return -ENOMEM;

    for ( i = 0; i <= EVTCHN_FIFO_PRIORITY_MIN; i++ )
        init_queue(v, &efv->queue[i], i);

    v->evtchn_fifo = efv;

    return 0;
}

static int map_control_block(struct vcpu *v, uint64_t gfn, uint32_t offset)
{
    void *virt;
    struct evtchn_fifo_control_block *control_block;
    unsigned int i;
    int rc;

    if ( v->evtchn_fifo->control_block )
        return -EINVAL;

    rc = map_guest_page(v->domain, gfn, &virt);
    if ( rc < 0 )
        return rc;

    control_block = virt + offset;

    for ( i = 0; i <= EVTCHN_FIFO_PRIORITY_MIN; i++ )
        v->evtchn_fifo->queue[i].head = &control_block->head[i];

    /* All queue heads must have been set before setting the control block. */
    smp_wmb();

    v->evtchn_fifo->control_block = control_block;

    return 0;
}

static void cleanup_control_block(struct vcpu *v)
{
    if ( !v->evtchn_fifo )
        return;

    unmap_guest_page(v->evtchn_fifo->control_block);
    xfree(v->evtchn_fifo);
    v->evtchn_fifo = NULL;
}

/*
 * Setup an event array with no pages.
 */
static int setup_event_array(struct domain *d)
{
    d->evtchn_fifo = xzalloc(struct evtchn_fifo_domain);
    if ( !d->evtchn_fifo )
        return -ENOMEM;

    return 0;
}

static void cleanup_event_array(struct domain *d)
{
    unsigned int i;

    if ( !d->evtchn_fifo )
        return;

    for ( i = 0; i < EVTCHN_FIFO_MAX_EVENT_ARRAY_PAGES; i++ )
        unmap_guest_page(d->evtchn_fifo->event_array[i]);
    xfree(d->evtchn_fifo);
    d->evtchn_fifo = NULL;
}

static void setup_ports(struct domain *d, unsigned int prev_evtchns)
{
    unsigned int port;

    /*
     * For each port that is already bound:
     *
     * - save its pending state.
     * - set default priority.
     */
    for ( port = 1; port < prev_evtchns; port++ )
    {
        struct evtchn *evtchn;

        if ( !port_is_valid(d, port) )
            break;

        evtchn = evtchn_from_port(d, port);

        if ( guest_test_bit(d, port, &shared_info(d, evtchn_pending)) )
            evtchn->pending = true;

        evtchn_fifo_set_priority(d, evtchn, EVTCHN_FIFO_PRIORITY_DEFAULT);
    }
}

int evtchn_fifo_init_control(struct evtchn_init_control *init_control)
{
    struct domain *d = current->domain;
    uint32_t vcpu_id;
    uint64_t gfn;
    uint32_t offset;
    struct vcpu *v;
    int rc;

    init_control->link_bits = EVTCHN_FIFO_LINK_BITS;

    vcpu_id = init_control->vcpu;
    gfn     = init_control->control_gfn;
    offset  = init_control->offset;

    if ( (v = domain_vcpu(d, vcpu_id)) == NULL )
        return -ENOENT;

    /* Must not cross page boundary. */
    if ( offset > (PAGE_SIZE - sizeof(evtchn_fifo_control_block_t)) )
        return -EINVAL;

    /*
     * Make sure the guest controlled value offset is bounded even during
     * speculative execution.
     */
    offset = array_index_nospec(offset,
                           PAGE_SIZE - sizeof(evtchn_fifo_control_block_t) + 1);

    /* Must be 8-bytes aligned. */
    if ( offset & (8 - 1) )
        return -EINVAL;

    spin_lock(&d->event_lock);

    /*
     * If this is the first control block, setup an empty event array
     * and switch to the fifo port ops.
     */
    if ( !d->evtchn_fifo )
    {
        struct vcpu *vcb;
        /* Latch the value before it changes during setup_event_array(). */
        unsigned int prev_evtchns = max_evtchns(d);

        for_each_vcpu ( d, vcb ) {
            rc = setup_control_block(vcb);
            if ( rc < 0 )
                goto error;
        }

        rc = setup_event_array(d);
        if ( rc < 0 )
            goto error;

        /*
         * This call, as a side effect, synchronizes with
         * evtchn_fifo_word_from_port().
         */
        rc = map_control_block(v, gfn, offset);
        if ( rc < 0 )
            goto error;

        d->evtchn_port_ops = &evtchn_port_ops_fifo;
        setup_ports(d, prev_evtchns);
    }
    else
        rc = map_control_block(v, gfn, offset);

    spin_unlock(&d->event_lock);

    return rc;

 error:
    evtchn_fifo_destroy(d);
    spin_unlock(&d->event_lock);
    return rc;
}

static int add_page_to_event_array(struct domain *d, unsigned long gfn)
{
    void *virt;
    unsigned int slot;
    unsigned int port = d->evtchn_fifo->num_evtchns;
    int rc;

    slot = d->evtchn_fifo->num_evtchns / EVTCHN_FIFO_EVENT_WORDS_PER_PAGE;
    if ( slot >= EVTCHN_FIFO_MAX_EVENT_ARRAY_PAGES )
        return -ENOSPC;

    rc = map_guest_page(d, gfn, &virt);
    if ( rc < 0 )
        return rc;

    d->evtchn_fifo->event_array[slot] = virt;

    /* Synchronize with evtchn_fifo_word_from_port(). */
    smp_wmb();

    d->evtchn_fifo->num_evtchns += EVTCHN_FIFO_EVENT_WORDS_PER_PAGE;

    /*
     * Re-raise any events that were pending while this array page was
     * missing.
     */
    for ( ; port < d->evtchn_fifo->num_evtchns; port++ )
    {
        struct evtchn *evtchn;

        if ( !port_is_valid(d, port) )
            break;

        evtchn = evtchn_from_port(d, port);
        if ( evtchn->pending )
            evtchn_fifo_set_pending(d->vcpu[evtchn->notify_vcpu_id], evtchn);
    }

    return 0;
}

int evtchn_fifo_expand_array(const struct evtchn_expand_array *expand_array)
{
    struct domain *d = current->domain;
    int rc;

    if ( !d->evtchn_fifo )
        return -EOPNOTSUPP;

    spin_lock(&d->event_lock);
    rc = add_page_to_event_array(d, expand_array->array_gfn);
    spin_unlock(&d->event_lock);

    return rc;
}

void evtchn_fifo_destroy(struct domain *d)
{
    struct vcpu *v;

    for_each_vcpu( d, v )
        cleanup_control_block(v);
    cleanup_event_array(d);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
