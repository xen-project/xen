/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/event.h>
#include <xen/mm.h>
#include <xen/pfn.h>
#include <xen/sched.h>
#include <xen/vm_event.h>
#include <xen/xmalloc.h>

#include <asm/p2m.h>
#include <asm/system.h>

#include <public/domctl.h>
#include <public/vm_event.h>

#define ASYNC_SLOT_ALIGN 64
#define ASYNC_REGION_MAX_PAGES 128

static unsigned int vm_event_async_compute_layout(
    uint32_t async_ring_pages,
    unsigned int *header_size_out,
    unsigned int *slot_size_out,
    unsigned int *slot_array_offset_out,
    unsigned int *nr_slots_out)
{
    unsigned int header_size = sizeof(struct vm_event_async_header);
    unsigned int slot_size =
        ROUNDUP(sizeof(struct vm_event_async_slot), ASYNC_SLOT_ALIGN);
    unsigned int slot_array_offset = ROUNDUP(header_size, ASYNC_SLOT_ALIGN);
    unsigned int total_bytes = async_ring_pages * PAGE_SIZE;
    unsigned int nr_slots;

    if ( total_bytes <= slot_array_offset )
        return 0;

    nr_slots = (total_bytes - slot_array_offset) / slot_size;

    *header_size_out       = header_size;
    *slot_size_out         = slot_size;
    *slot_array_offset_out = slot_array_offset;
    *nr_slots_out          = nr_slots;
    return async_ring_pages;
}

static void cf_check async_consumer_notification(struct vcpu *v,
                                                 unsigned int port)
{
    struct domain *d = v->domain;
    struct vm_event_domain *ved = d->vm_event_monitor;
    struct vm_event_async_header *hdr;
    struct vcpu *target;
    uint32_t prod, cons;

    if ( !vm_event_has_async_ring(ved) )
        return;

    /*
     * Serialise against the producer's backpressure pause via ved->lock, so
     * the flag-clear+unpause here cannot interleave with the producer's
     * flag-set+pause and strand a vCPU.  The same lock guards teardown:
     * vm_event_async_disable() clears async_region under it before freeing
     * the pages, so re-check inside the lock before dereferencing.
     */
    spin_lock(&ved->lock);

    if ( !ved->async_region )
    {
        spin_unlock(&ved->lock);
        return;
    }
    hdr = ved->async_region;

    prod = read_atomic(&hdr->prod_idx);
    cons = read_atomic(&hdr->cons_idx);

    /*
     * Mirror of the producer's pause threshold: a paused vCPU was put to
     * sleep when free_after_write < max_outstanding.  Release it once the
     * consumer has drained enough that free is back at the threshold.
     * Same condition both directions = no pause/unpause thrashing.  Layout
     * (nr_slots, max_outstanding) comes from the private cache, not the
     * consumer-writable header.
     */
    if ( ved->async_nr_slots - (prod - cons) >= ved->async_max_outstanding )
    {
        for_each_vcpu ( d, target )
        {
            if ( target->vm_event_async_paused )
            {
                target->vm_event_async_paused = false;
                vm_event_vcpu_unpause(target);
            }
        }
    }

    spin_unlock(&ved->lock);
}

int vm_event_async_enable(struct domain *d, uint32_t async_ring_pages)
{
    struct vm_event_domain *ved = d->vm_event_monitor;
    struct page_info *pg = NULL;
    void *region = NULL;
    struct vm_event_async_header *hdr;
    unsigned int hs, ss, sao, nr_slots, order = 0;
    unsigned int j, refs_taken = 0;
    evtchn_port_t port = 0;
    int rc;

    /*
     * The async ring attaches to the monitor created by the SETUP dispatcher.
     * It is independent of the sync slots: a monitor may bring up async only,
     * sync only, or both.  Reject a redundant request rather than
     * re-initialising a live async ring.
     */
    if ( !vm_event_has_new_api(ved) )
        return -EINVAL;

    if ( vm_event_has_async_ring(ved) )
        return -EBUSY;

    if ( async_ring_pages == 0 )
        return -EINVAL;

    /*
     * alloc_domheap_pages() hands out a power-of-two block.  Use the whole
     * allocation as the ring and ref-count every page, so teardown can drop
     * refs on all of them; otherwise the tail pages between async_ring_pages
     * and (1 << order) would never be referenced or freed.
     */
    order = get_order_from_pages(async_ring_pages);
    async_ring_pages = 1u << order;
    if ( async_ring_pages > ASYNC_REGION_MAX_PAGES )
        return -EINVAL;

    if ( vm_event_async_compute_layout(async_ring_pages, &hs, &ss,
                                       &sao, &nr_slots) == 0 )
        return -EINVAL;

    /*
     * Structural no-loss invariant: with nr_slots >= d->max_vcpus AND
     * max_outstanding = d->max_vcpus, the producer can always reserve a slot
     * without sleeping, so events are never dropped -- the ring size is a
     * latency budget, not an overflow risk.
     */
    if ( nr_slots < d->max_vcpus )
        return -EINVAL;

    pg = alloc_domheap_pages(d, order, MEMF_no_refcount);
    if ( !pg )
        return -ENOMEM;

    for ( j = 0; j < async_ring_pages; j++ )
    {
        if ( !get_page_and_type(&pg[j], d, PGT_writable_page) )
        {
            rc = -ENODATA;
            goto fail;
        }
        refs_taken++;
    }

    region = page_to_virt(pg);
    memset(region, 0, (unsigned long)async_ring_pages << PAGE_SHIFT);

    rc = alloc_unbound_xen_event_channel(d, 0,
                                         current->domain->domain_id,
                                         async_consumer_notification);
    if ( rc < 0 )
        goto fail;
    port = rc;

    hdr = region;
    hdr->magic             = VM_EVENT_ASYNC_MAGIC;
    hdr->version           = VM_EVENT_ASYNC_VERSION;
    hdr->header_size       = hs;
    hdr->slot_size         = ss;
    hdr->slot_array_offset = sao;
    hdr->nr_slots          = nr_slots;
    hdr->max_outstanding   = d->max_vcpus;
    hdr->flags             = 0;
    hdr->evtchn_port       = port;

    ved->async_port           = port;
    ved->async_region_nr_pages = async_ring_pages;

    /* Cache the trusted layout privately; never trust the shared header. */
    ved->async_slot_size         = ss;
    ved->async_slot_array_offset = sao;
    ved->async_nr_slots          = nr_slots;
    ved->async_max_outstanding   = d->max_vcpus;

    smp_wmb();
    ved->async_region         = region;
    return 0;

 fail:
    if ( port )
        free_xen_event_channel(d, port);
    /* Drop both refs taken by get_page_and_type(), as vmtrace does. */
    while ( refs_taken-- )
    {
        put_page_alloc_ref(&pg[refs_taken]);
        put_page_and_type(&pg[refs_taken]);
    }
    return rc;
}

int vm_event_async_disable(struct domain *d)
{
    struct vm_event_domain *ved = d->vm_event_monitor;
    struct vcpu *v;
    struct page_info *pg;
    void *region;
    unsigned int k, nr_pages;
    evtchn_port_t port;

    if ( !vm_event_has_async_ring(ved) )
        return 0;

    /*
     * Under ved->lock: release any vCPU still flagged async-paused by the
     * producer's backpressure path, then detach the region so a drain
     * notification racing this teardown either completes before us or, once
     * we have cleared async_region, bails in its under-lock re-check rather
     * than dereferencing memory we are about to free.  The event channel and
     * pages are freed after dropping the lock, using the captured values.
     */
    spin_lock(&ved->lock);

    for_each_vcpu ( d, v )
    {
        if ( v->vm_event_async_paused )
        {
            v->vm_event_async_paused = false;
            vm_event_vcpu_unpause(v);
        }
    }

    region   = ved->async_region;
    nr_pages = ved->async_region_nr_pages;
    port     = ved->async_port;

    ved->async_region          = NULL;
    ved->async_region_nr_pages = 0;
    ved->async_port            = 0;

    spin_unlock(&ved->lock);

    if ( port )
        free_xen_event_channel(d, port);

    /*
     * Drop both refs taken at enable time (allocation ref + writable type
     * ref) for every page of the power-of-two allocation, as vmtrace does.
     */
    pg = virt_to_page(region);
    for ( k = 0; k < nr_pages; k++ )
    {
        put_page_alloc_ref(&pg[k]);
        put_page_and_type(&pg[k]);
    }

    return 0;
}

int vm_event_async_put(struct vcpu *v, const vm_event_request_t *req)
{
    struct domain *d = v->domain;
    struct vm_event_domain *ved = d->vm_event_monitor;
    struct vm_event_async_header *hdr;
    struct vm_event_async_slot *slot;
    char *slot_array;
    uint32_t idx;

    ASSERT(v == current);
    ASSERT(vm_event_has_async_ring(ved));

    hdr = ved->async_region;
    /* Slot arithmetic uses the private layout cache, never the header. */
    slot_array = (char *)ved->async_region + ved->async_slot_array_offset;

    /*
     * Reserve a slot.  Atomic fetch-add (LOCK XADD on x86) gives each
     * concurrent producer a distinct prod_idx.  The structural no-loss
     * invariant (nr_slots >= d->max_vcpus AND max_outstanding ==
     * d->max_vcpus, with the post-write pause check added by the next
     * patch) guarantees the reserved slot is free for use.  The cached
     * nr_slots keeps the index in bounds even if the consumer corrupts
     * prod_idx in the shared header.
     */
    idx = arch_fetch_and_add(&hdr->prod_idx, 1);

    slot = (struct vm_event_async_slot *)
        (slot_array + (idx % ved->async_nr_slots) * ved->async_slot_size);

    /*
     * Linux-style seqcount publication.  Mark in-progress (odd) with
     * a release barrier so the consumer can't observe a torn body as
     * "published".  Then fill, barrier, and mark published (even,
     * next generation).
     */
    slot->seqcount++;
    smp_wmb();
    slot->req = *req;
    /* Stamp the interface version, as vm_event_put_request() does for v1. */
    slot->req.version = VM_EVENT_INTERFACE_VERSION;
    smp_wmb();
    slot->seqcount++;

    /*
     * Always signal -- no coalescing.  This trades one event-channel upcall
     * per published slot for simpler correctness; a coalesced "signal only on
     * empty -> non-empty" scheme is a possible future optimisation.
     */
    notify_via_xen_event_channel(d, ved->async_port);

    /*
     * Post-write backpressure check (the structural no-loss invariant).
     * Compute outstanding events using the prod_idx value WE just
     * advanced -- (idx + 1) is our new prod_idx.  Modular subtraction
     * gives the correct count across uint32_t wrap.
     *
     * If the ring's remaining free space dropped below max_outstanding
     * (= d->max_vcpus, set at enable time), pause the producing vCPU.
     * Combined with nr_slots >= d->max_vcpus enforced at enable, no producer
     * can ever reserve a slot that isn't free.  The drain notification
     * (async_consumer_notification) auto-unpauses once the consumer catches
     * up.
     */
    {
        uint32_t cons = read_atomic(&hdr->cons_idx);
        uint32_t free_after_write = ved->async_nr_slots - ((idx + 1) - cons);

        if ( free_after_write < ved->async_max_outstanding )
        {
            /*
             * Pause under ved->lock, which also serialises the drain
             * notification's unpause.  Without it, a notify landing between
             * setting the flag and pausing could clear the flag and unpause
             * before the pause registered, stranding the vCPU.  Re-check the
             * threshold under the lock against the current cons_idx so we do
             * not pause after the consumer has already drained -- which would
             * leave nothing left to wake us.
             */
            spin_lock(&ved->lock);
            cons = read_atomic(&hdr->cons_idx);
            if ( !v->vm_event_async_paused &&
                 ved->async_nr_slots - ((idx + 1) - cons) <
                     ved->async_max_outstanding )
            {
                v->vm_event_async_paused = true;
                vm_event_vcpu_pause(v);
            }
            spin_unlock(&ved->lock);
        }
    }

    return 0;
}

unsigned int vm_event_async_resource_max_frames(const struct domain *d)
{
    const struct vm_event_domain *ved = d->vm_event_monitor;

    return vm_event_has_async_ring(ved) ? ved->async_region_nr_pages : 0;
}

int vm_event_acquire_async_resource(struct domain *d, unsigned int id,
                                    unsigned int frame, unsigned int nr_frames,
                                    xen_pfn_t mfn_list[])
{
    const struct vm_event_domain *ved = d->vm_event_monitor;
    mfn_t base_mfn;
    unsigned int i;

    if ( id != 0 )
        return -EINVAL;

    if ( !vm_event_has_async_ring(ved) )
        return -ENOENT;

    if ( nr_frames == 0 ||
         frame + nr_frames > ved->async_region_nr_pages )
        return -EINVAL;

    base_mfn = page_to_mfn(virt_to_page(ved->async_region));
    for ( i = 0; i < nr_frames; i++ )
        mfn_list[i] = mfn_x(base_mfn) + frame + i;

    return nr_frames;
}
