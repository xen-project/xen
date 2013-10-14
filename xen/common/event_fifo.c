/*
 * FIFO event channel management.
 *
 * Copyright (C) 2013 Citrix Systems R&D Ltd.
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2 or later.  See the file COPYING for more details.
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <xen/event_fifo.h>
#include <xen/paging.h>
#include <xen/mm.h>

#include <public/event_channel.h>

static inline event_word_t *evtchn_fifo_word_from_port(struct domain *d,
                                                       unsigned int port)
{
    unsigned int p, w;

    if ( unlikely(port >= d->evtchn_fifo->num_evtchns) )
        return NULL;

    p = port / EVTCHN_FIFO_EVENT_WORDS_PER_PAGE;
    w = port % EVTCHN_FIFO_EVENT_WORDS_PER_PAGE;

    return d->evtchn_fifo->event_array[p] + w;
}

static bool_t evtchn_fifo_set_link(event_word_t *word, uint32_t link)
{
    event_word_t n, o, w;

    w = *word;

    do {
        if ( !(w & (1 << EVTCHN_FIFO_LINKED)) )
            return 0;
        o = w;
        n = (w & ~EVTCHN_FIFO_LINK_MASK) | link;
    } while ( (w = cmpxchg(word, o, n)) != o );

    return 1;
}

static void evtchn_fifo_set_pending(struct vcpu *v, struct evtchn *evtchn)
{
    struct domain *d = v->domain;
    unsigned int port;
    event_word_t *word;
    struct evtchn_fifo_queue *q;
    unsigned long flags;
    bool_t was_pending;

    port = evtchn->port;
    word = evtchn_fifo_word_from_port(d, port);
    if ( unlikely(!word) )
        return;

    /*
     * No locking around getting the queue. This may race with
     * changing the priority but we are allowed to signal the event
     * once on the old priority.
     */
    q = &v->evtchn_fifo->queue[evtchn->priority];

    was_pending = test_and_set_bit(EVTCHN_FIFO_PENDING, word);

    /*
     * Link the event if it unmasked and not already linked.
     */
    if ( !test_bit(EVTCHN_FIFO_MASKED, word)
         && !test_and_set_bit(EVTCHN_FIFO_LINKED, word) )
    {
        event_word_t *tail_word;
        bool_t linked = 0;

        spin_lock_irqsave(&q->lock, flags);

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
        if ( port != q->tail )
        {
            tail_word = evtchn_fifo_word_from_port(d, q->tail);
            linked = evtchn_fifo_set_link(tail_word, port);
        }
        if ( !linked )
            write_atomic(q->head, port);
        q->tail = port;

        spin_unlock_irqrestore(&q->lock, flags);

        if ( !test_and_set_bit(q->priority,
                               &v->evtchn_fifo->control_block->ready) )
            vcpu_mark_events_pending(v);
    }

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
    clear_bit(EVTCHN_FIFO_PENDING, word);
}

static void evtchn_fifo_unmask(struct domain *d, struct evtchn *evtchn)
{
    struct vcpu *v = d->vcpu[evtchn->notify_vcpu_id];
    event_word_t *word;

    word = evtchn_fifo_word_from_port(d, evtchn->port);
    if ( unlikely(!word) )
        return;

    clear_bit(EVTCHN_FIFO_MASKED, word);

    /* Relink if pending. */
    if ( test_bit(EVTCHN_FIFO_PENDING, word) )
        evtchn_fifo_set_pending(v, evtchn);
}

static bool_t evtchn_fifo_is_pending(struct domain *d,
                                     const struct evtchn *evtchn)
{
    event_word_t *word;

    word = evtchn_fifo_word_from_port(d, evtchn->port);
    if ( unlikely(!word) )
        return 0;

    return test_bit(EVTCHN_FIFO_PENDING, word);
}

static bool_t evtchn_fifo_is_masked(struct domain *d,
                                    const struct evtchn *evtchn)
{
    event_word_t *word;

    word = evtchn_fifo_word_from_port(d, evtchn->port);
    if ( unlikely(!word) )
        return 1;

    return test_bit(EVTCHN_FIFO_MASKED, word);
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
        printk("?   ");
    else if ( test_bit(EVTCHN_FIFO_LINKED, word) )
        printk("%-4u", *word & EVTCHN_FIFO_LINK_MASK);
    else
        printk("-   ");
}

static const struct evtchn_port_ops evtchn_port_ops_fifo =
{
    .set_pending   = evtchn_fifo_set_pending,
    .clear_pending = evtchn_fifo_clear_pending,
    .unmask        = evtchn_fifo_unmask,
    .is_pending    = evtchn_fifo_is_pending,
    .is_masked     = evtchn_fifo_is_masked,
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

    *virt = map_domain_page_global(gfn);
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
    q->head = &v->evtchn_fifo->control_block->head[i];
}

static int setup_control_block(struct vcpu *v, uint64_t gfn, uint32_t offset)
{
    struct domain *d = v->domain;
    struct evtchn_fifo_vcpu *efv;
    void *virt;
    unsigned int i;
    int rc;

    if ( v->evtchn_fifo )
        return -EINVAL;

    efv = xzalloc(struct evtchn_fifo_vcpu);
    if ( !efv )
        return -ENOMEM;

    rc = map_guest_page(d, gfn, &virt);
    if ( rc < 0 )
    {
        xfree(efv);
        return rc;
    }

    v->evtchn_fifo = efv;
    v->evtchn_fifo->control_block = virt + offset;

    for ( i = 0; i <= EVTCHN_FIFO_PRIORITY_MIN; i++ )
        init_queue(v, &v->evtchn_fifo->queue[i], i);

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
}

static void set_priority_all(struct domain *d, unsigned int priority)
{
    unsigned int port;

    for ( port = 1; port < d->max_evtchns; port++ )
    {
        if ( !port_is_valid(d, port) )
            break;

        evtchn_port_set_priority(d, evtchn_from_port(d, port), priority);
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

    if ( vcpu_id >= d->max_vcpus || !d->vcpu[vcpu_id] )
        return -ENOENT;
    v = d->vcpu[vcpu_id];

    /* Must not cross page boundary. */
    if ( offset > (PAGE_SIZE - sizeof(evtchn_fifo_control_block_t)) )
        return -EINVAL;

    /* Must be 8-bytes aligned. */
    if ( offset & (8 - 1) )
        return -EINVAL;

    spin_lock(&d->event_lock);

    rc = setup_control_block(v, gfn, offset);

    /*
     * If this is the first control block, setup an empty event array
     * and switch to the fifo port ops.
     *
     * Any ports currently bound will have their priority set to the
     * default.
     */
    if ( rc == 0 && !d->evtchn_fifo )
    {
        rc = setup_event_array(d);
        if ( rc < 0 )
            cleanup_control_block(v);
        else
        {
            d->evtchn_port_ops = &evtchn_port_ops_fifo;
            d->max_evtchns = EVTCHN_FIFO_NR_CHANNELS;
            set_priority_all(d, EVTCHN_FIFO_PRIORITY_DEFAULT);
        }
    }

    spin_unlock(&d->event_lock);

    return rc;
}

static int add_page_to_event_array(struct domain *d, unsigned long gfn)
{
    void *virt;
    unsigned int slot;
    int rc;

    slot = d->evtchn_fifo->num_evtchns / EVTCHN_FIFO_EVENT_WORDS_PER_PAGE;
    if ( slot >= EVTCHN_FIFO_MAX_EVENT_ARRAY_PAGES )
        return -ENOSPC;

    rc = map_guest_page(d, gfn, &virt);
    if ( rc < 0 )
        return rc;

    d->evtchn_fifo->event_array[slot] = virt;
    d->evtchn_fifo->num_evtchns += EVTCHN_FIFO_EVENT_WORDS_PER_PAGE;

    return 0;
}

int evtchn_fifo_expand_array(const struct evtchn_expand_array *expand_array)
{
    struct domain *d = current->domain;
    int rc;

    if ( !d->evtchn_fifo )
        return -ENOSYS;

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
