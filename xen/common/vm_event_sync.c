/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/event.h>
#include <xen/mm.h>
#include <xen/pfn.h>
#include <xen/sched.h>
#include <xen/vm_event.h>
#include <xen/xmalloc.h>

#include <asm/p2m.h>
#include <asm/vm_event.h>

#include <public/domctl.h>
#include <public/vm_event.h>

#define SYNC_SLOT_ALIGN 64
#define SYNC_REGION_MAX_PAGES 32

static unsigned int vm_event_sync_compute_layout(
    unsigned int nr_vcpus, uint32_t slot_size,
    unsigned int *header_size_out,
    unsigned int *port_array_size_out,
    unsigned int *slot_array_offset_out,
    unsigned int *total_size_out)
{
    unsigned int header_size = sizeof(struct vm_event_sync_header);
    unsigned int port_array_size = nr_vcpus * sizeof(evtchn_port_t);
    unsigned int slot_array_offset =
        ROUNDUP(header_size + port_array_size, SYNC_SLOT_ALIGN);
    unsigned int total_size = slot_array_offset + nr_vcpus * slot_size;

    *header_size_out = header_size;
    *port_array_size_out = port_array_size;
    *slot_array_offset_out = slot_array_offset;
    *total_size_out = total_size;
    return PFN_UP(total_size);
}

static struct vm_event_sync_slot *sync_slot_ptr(
    const struct vm_event_domain *ved, unsigned int vcpu_id)
{
    /*
     * Layout comes from Xen's private cache, never from the
     * consumer-writable shared header.  ved->sync_region is Xen's own
     * trusted mapping, so it is safe as the base address.
     */
    return (struct vm_event_sync_slot *)
        ((char *)ved->sync_region + ved->sync_slot_array_offset +
         vcpu_id * ved->sync_slot_size);
}

static void cf_check sync_slot_notification(struct vcpu *v,
                                            unsigned int port)
{
    struct vm_event_domain *ved = v->domain->vm_event_monitor;
    struct vm_event_sync_slot *slot;

    if ( !vm_event_has_sync_slots(ved) || v->vcpu_id >= ved->sync_nr_vcpus )
        return;

    slot = sync_slot_ptr(ved, v->vcpu_id);

    /*
     * Only release the vCPU once the consumer has actually published a
     * response.  Gating on RESPONSE -- rather than unpausing on any notify
     * -- means a spurious or early event-channel signal cannot resume the
     * guest while the slot is still in REQUEST, which would otherwise trip
     * the non-IDLE check in vm_event_sync_put() and crash the domain.  It
     * also closes the pause/unpause ordering race against the producer: the
     * slot cannot read RESPONSE until after the producer has published the
     * request and paused the vCPU.  The response is validated (seq, version)
     * in vm_event_sync_pickup() before the guest runs.
     */
    if ( read_atomic(&slot->state) != VM_EVENT_SYNC_STATE_RESPONSE )
        return;

    if ( v->vm_event_sync_paused )
    {
        v->vm_event_sync_paused = false;
        vm_event_vcpu_unpause(v);
    }
}

int vm_event_sync_enable(struct domain *d,
                         struct xen_domctl_vm_event_op *vec)
{
    struct vm_event_domain *ved = d->vm_event_monitor;
    struct page_info *pg = NULL;
    void *region = NULL;
    struct vm_event_sync_header *hdr;
    evtchn_port_t *ports = NULL;
    unsigned int nr_vcpus, hs, pas, sao, ts, nr_pages, order = 0;
    unsigned int j, refs_taken = 0;
    uint32_t slot_size;
    struct vcpu *v;
    int rc;

    /*
     * The monitor was created by the SETUP dispatcher; attach the sync slots
     * to it.  Reject a redundant request rather than re-initialising a live
     * sync transport.
     */
    if ( vm_event_has_sync_slots(ved) )
        return -EBUSY;

    /* flags and reserved are validated by the SETUP dispatcher. */
    slot_size = vec->u.setup.sync_slot_size;
    if ( slot_size < sizeof(struct vm_event_sync_slot) ||
         slot_size > PAGE_SIZE )
        return -EINVAL;

    nr_vcpus = d->max_vcpus;
    if ( nr_vcpus == 0 )
        return -EINVAL;

    nr_pages = vm_event_sync_compute_layout(nr_vcpus, slot_size,
                                            &hs, &pas, &sao, &ts);
    if ( nr_pages == 0 )
        return -EINVAL;

    /*
     * alloc_domheap_pages() hands out a power-of-two block.  Treat the
     * whole allocation as the region and ref-count every page, so the
     * teardown path can drop refs on all of them.  Otherwise the tail
     * pages between the layout size and (1 << order) would never be
     * referenced or freed.
     */
    order = get_order_from_pages(nr_pages);
    nr_pages = 1u << order;
    if ( nr_pages > SYNC_REGION_MAX_PAGES )
        return -EINVAL;

    pg = alloc_domheap_pages(d, order, MEMF_no_refcount);
    if ( !pg )
        return -ENOMEM;

    for ( j = 0; j < nr_pages; j++ )
    {
        if ( !get_page_and_type(&pg[j], d, PGT_writable_page) )
        {
            rc = -ENODATA;
            goto fail;
        }
        refs_taken++;
    }

    region = page_to_virt(pg);
    memset(region, 0, (unsigned long)nr_pages << PAGE_SHIFT);

    /*
     * Publish the layout for the consumer.  These header fields are
     * descriptive only: Xen never reads them back (see sync_slot_ptr()).
     */
    hdr = region;
    hdr->magic              = VM_EVENT_SYNC_MAGIC;
    hdr->version            = VM_EVENT_SYNC_VERSION;
    hdr->header_size        = hs;
    hdr->port_array_size    = pas;
    hdr->slot_size          = slot_size;
    hdr->slot_array_offset  = sao;
    hdr->nr_vcpus           = nr_vcpus;
    hdr->flags              = 0;

    ports = (evtchn_port_t *)((char *)region + hs);

    for_each_vcpu ( d, v )
    {
        rc = alloc_unbound_xen_event_channel(d, v->vcpu_id,
                                             current->domain->domain_id,
                                             sync_slot_notification);
        if ( rc < 0 )
            goto fail;
        ports[v->vcpu_id] = rc;
    }

    ved->sync_region_nr_pages = nr_pages;
    ved->sync_ports           = ports;

    /* Cache the trusted layout privately; never trust the shared header. */
    ved->sync_slot_size         = slot_size;
    ved->sync_slot_array_offset = sao;
    ved->sync_nr_vcpus          = nr_vcpus;

    smp_wmb();
    /* Publish the transport last; vm_event_has_sync_slots() keys on this. */
    ved->sync_region = region;
    return 0;

 fail:
    if ( ports )
    {
        for_each_vcpu ( d, v )
        {
            evtchn_port_t p = ports[v->vcpu_id];
            if ( p > 0 )
                free_xen_event_channel(d, p);
        }
    }
    /*
     * Drop both refs taken by get_page_and_type() (the allocation ref and
     * the writable type ref), mirroring vmtrace_free_buffer().  Pages that
     * never got their type ref (a partial get_page_and_type() failure, only
     * reachable under pathological refcounting) are left alone, as there.
     */
    while ( refs_taken-- )
    {
        put_page_alloc_ref(&pg[refs_taken]);
        put_page_and_type(&pg[refs_taken]);
    }
    return rc;
}

int vm_event_sync_disable(struct domain *d)
{
    struct vm_event_domain *ved = d->vm_event_monitor;
    struct vcpu *v;
    unsigned int i;

    if ( !vm_event_has_sync_slots(ved) )
        return 0;

    for ( i = 0; i < ved->sync_nr_vcpus; i++ )
    {
        struct vm_event_sync_slot *slot = sync_slot_ptr(ved, i);
        slot->state = VM_EVENT_SYNC_STATE_ABANDONED;
    }
    smp_wmb();

    for_each_vcpu ( d, v )
    {
        if ( v->vm_event_sync_paused )
        {
            v->vm_event_sync_paused = false;
            vm_event_vcpu_unpause(v);
        }
    }

    for_each_vcpu ( d, v )
    {
        evtchn_port_t port = ved->sync_ports[v->vcpu_id];
        if ( port > 0 )
            free_xen_event_channel(d, port);
    }

    {
        struct page_info *pg = virt_to_page(ved->sync_region);
        unsigned int k;

        /*
         * Drop both refs taken at enable time (allocation ref + writable
         * type ref) for every page of the allocation, mirroring
         * vmtrace_free_buffer().  sync_region_nr_pages is the full
         * power-of-two allocation, so no tail pages are left behind.
         */
        for ( k = 0; k < ved->sync_region_nr_pages; k++ )
        {
            put_page_alloc_ref(&pg[k]);
            put_page_and_type(&pg[k]);
        }
    }

    /*
     * Detach the sync transport from the monitor.  The struct
     * vm_event_domain itself is freed by vm_event_monitor_destroy() once both
     * transports are gone; clearing sync_region makes vm_event_has_sync_slots()
     * false so a re-attach (or destroy) sees no live transport.
     */
    ved->sync_region          = NULL;
    ved->sync_region_nr_pages = 0;
    ved->sync_ports           = NULL;
    return 0;
}

int vm_event_sync_put(struct vcpu *v, const vm_event_request_t *req)
{
    struct domain *d = v->domain;
    struct vm_event_domain *ved = d->vm_event_monitor;
    struct vm_event_sync_slot *slot;

    ASSERT(v == current);
    ASSERT(vm_event_has_sync_slots(ved));

    if ( v->vcpu_id >= ved->sync_nr_vcpus )
    {
        ASSERT_UNREACHABLE();
        return 0;
    }

    slot = sync_slot_ptr(ved, v->vcpu_id);

    if ( slot->state != VM_EVENT_SYNC_STATE_IDLE )
    {
        gprintk(XENLOG_ERR,
                "vm_event_sync: slot non-IDLE on entry (state=%u "
                "req_seq=%u resp_seq=%u); crashing domain\n",
                slot->state, slot->request_seq, slot->response_seq);
        domain_crash(d);
        return 0;
    }

    slot->req = *req;
    /* Stamp the interface version, as vm_event_put_request() does for v1. */
    slot->req.version = VM_EVENT_INTERFACE_VERSION;
    slot->request_seq++;

    v->vm_event_sync_paused = true;
    vm_event_vcpu_pause(v);

    smp_wmb();
    slot->state = VM_EVENT_SYNC_STATE_REQUEST;

    notify_via_xen_event_channel(d, ved->sync_ports[v->vcpu_id]);

    return 1;
}

void vm_event_sync_pickup(struct vcpu *v)
{
    struct domain *d = v->domain;
    struct vm_event_domain *ved = d->vm_event_monitor;
    struct vm_event_sync_slot *slot;
    vm_event_response_t rsp;
    uint32_t state, request_seq, response_seq;

    if ( !vm_event_has_sync_slots(ved) )
        return;

    ASSERT(v == current);

    if ( v->vcpu_id >= ved->sync_nr_vcpus )
    {
        ASSERT_UNREACHABLE();
        return;
    }

    slot = sync_slot_ptr(ved, v->vcpu_id);

    state = slot->state;
    smp_rmb();
    request_seq = slot->request_seq;
    response_seq = slot->response_seq;

    switch ( state )
    {
    case VM_EVENT_SYNC_STATE_RESPONSE:
        /*
         * The monitor has responded; the sync-event window is over.  Clear
         * it before resuming so the arch interrupt-injection assist stops
         * holding off (this also covers the dropped-response paths below).
         */
        vm_event_sync_event(v, false);

        if ( response_seq != request_seq )
        {
            gprintk(XENLOG_WARNING,
                    "vm_event sync vcpu %u: stale response "
                    "(request_seq=%u response_seq=%u); dropping\n",
                    v->vcpu_id, request_seq, response_seq);
            slot->state = VM_EVENT_SYNC_STATE_IDLE;
            return;
        }

        rsp = slot->rsp;

        if ( rsp.version != VM_EVENT_INTERFACE_VERSION )
        {
            gprintk(XENLOG_WARNING,
                    "vm_event sync vcpu %u: response version mismatch "
                    "(got %u, expected %u); dropping\n",
                    v->vcpu_id, rsp.version, VM_EVENT_INTERFACE_VERSION);
            slot->state = VM_EVENT_SYNC_STATE_IDLE;
            return;
        }

        /*
         * Dispatch on the *request* reason -- which Xen stamped in
         * vm_event_sync_put() and the consumer cannot alter -- not the
         * consumer-supplied response reason.  Non-monitor event classes
         * (paging, sharing) carried on the shared sync slots take their own
         * resume action and skip the monitor response handling below.  This
         * mirrors the reason dispatch the legacy ring does in
         * vm_event_resume().  The vCPU was already unpaused by
         * sync_slot_notification(); here we only perform the resume side
         * effect before the guest re-runs the faulting instruction.
         */
#ifdef CONFIG_MEM_PAGING
        if ( slot->req.reason == VM_EVENT_REASON_MEM_PAGING )
        {
            p2m_mem_paging_resume(d, &rsp);
            slot->state = VM_EVENT_SYNC_STATE_IDLE;
            break;
        }
#endif

        atomic_inc(&v->vm_event_pause_count);

        vm_event_emulate_check(v, &rsp);
        vm_event_register_write_resume(v, &rsp);
        vm_event_toggle_singlestep(d, v, &rsp);
        if ( IS_ENABLED(CONFIG_ALTP2M) &&
             (rsp.flags & VM_EVENT_FLAG_ALTERNATE_P2M) )
            p2m_altp2m_check(v, rsp.altp2m_idx);
        if ( rsp.flags & VM_EVENT_FLAG_SET_REGISTERS )
            vm_event_set_registers(v, &rsp);
        if ( rsp.flags & VM_EVENT_FLAG_GET_NEXT_INTERRUPT )
            vm_event_monitor_next_interrupt(v);
        if ( IS_ENABLED(CONFIG_VMTRACE) &&
             (rsp.flags & VM_EVENT_FLAG_RESET_VMTRACE) )
            vm_event_reset_vmtrace(v);

        atomic_dec(&v->vm_event_pause_count);

        slot->state = VM_EVENT_SYNC_STATE_IDLE;
        break;

    case VM_EVENT_SYNC_STATE_ABANDONED:
        vm_event_sync_event(v, false);
        v->vm_event_sync_paused = false;
        break;

    case VM_EVENT_SYNC_STATE_REQUEST:
    case VM_EVENT_SYNC_STATE_IDLE:
    default:
        break;
    }
}

unsigned int vm_event_sync_resource_max_frames(const struct domain *d)
{
    const struct vm_event_domain *ved = d->vm_event_monitor;

    return vm_event_has_sync_slots(ved) ? ved->sync_region_nr_pages : 0;
}

int vm_event_acquire_sync_resource(struct domain *d, unsigned int id,
                                   unsigned int frame, unsigned int nr_frames,
                                   xen_pfn_t mfn_list[])
{
    const struct vm_event_domain *ved = d->vm_event_monitor;
    mfn_t base_mfn;
    unsigned int i;

    if ( id != 0 )
        return -EINVAL;

    if ( !vm_event_has_sync_slots(ved) )
        return -ENOENT;

    if ( nr_frames == 0 ||
         frame + nr_frames > ved->sync_region_nr_pages )
        return -EINVAL;

    base_mfn = page_to_mfn(virt_to_page(ved->sync_region));
    for ( i = 0; i < nr_frames; i++ )
        mfn_list[i] = mfn_x(base_mfn) + frame + i;

    return nr_frames;
}
