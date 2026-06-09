/******************************************************************************
 * vm_event.h
 *
 * Common interface for memory event support.
 *
 * Copyright (c) 2009 Citrix Systems, Inc. (Patrick Colp)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */


#ifndef __VM_EVENT_H__
#define __VM_EVENT_H__

#include <xen/sched.h>
#include <public/vm_event.h>
#include <asm/vm_event.h>

struct vm_event_domain
{
    spinlock_t lock;
    /* The ring has 64 entries */
    unsigned char foreign_producers;
    unsigned char target_producers;
    /* shared ring page */
    void *ring_page;
    struct page_info *ring_pg_struct;
    /* front-end ring */
    vm_event_front_ring_t front_ring;
    /* event channel port (vcpu0 only) */
    int xen_port;
    /* vm_event bit for vcpu->pause_flags */
    int pause_flag;
    /* list of vcpus waiting for room in the ring */
    struct waitqueue_head wq;
    /* the number of vCPUs blocked */
    unsigned int blocked;
    /* The last vcpu woken up */
    unsigned int last_vcpu_wake_up;

    /*
     * True once this domain's monitor is the v2 shared-memory interface
     * (sync slots and/or async ring), as opposed to the legacy v1 ring.
     * Set when the monitor is created, before any transport is attached, so
     * an async-only monitor (sync_region == NULL) is still recognised as v2.
     */
    bool new_api;

    void *sync_region;
    unsigned int sync_region_nr_pages;
    evtchn_port_t *sync_ports;

    /*
     * Private, immutable copy of the slot-array layout published in the
     * shared sync header.  That header lives in a page mapped writable by
     * the (potentially untrusted) consumer, so Xen must never re-read it
     * for its own pointer arithmetic.  These cached fields are the trusted
     * source of truth; the shared header is descriptive only.
     */
    uint32_t sync_slot_size;
    uint32_t sync_slot_array_offset;
    uint32_t sync_nr_vcpus;

    void *async_region;
    unsigned int async_region_nr_pages;
    evtchn_port_t async_port;

    /*
     * Private, immutable copy of the async ring layout (same rationale as
     * the sync cache above: the shared header is consumer-writable and must
     * never be trusted for Xen's pointer arithmetic).  The live ring
     * indices prod_idx/cons_idx remain in the shared header -- they are
     * protocol state, not layout -- and the cached nr_slots keeps the slot
     * index bounded regardless of what the consumer writes there.
     */
    uint32_t async_slot_size;
    uint32_t async_slot_array_offset;
    uint32_t async_nr_slots;
    uint32_t async_max_outstanding;
};

static inline bool vm_event_has_new_api(const struct vm_event_domain *ved)
{
    return ved && ved->new_api;
}

static inline bool vm_event_has_sync_slots(const struct vm_event_domain *ved)
{
    return ved && ved->sync_region;
}

static inline bool vm_event_has_async_ring(const struct vm_event_domain *ved)
{
    return ved && ved->async_region;
}

/* Returns whether a ring has been set up */
#ifdef CONFIG_VM_EVENT
bool vm_event_check_ring(struct vm_event_domain *ved);
#else
static inline bool vm_event_check_ring(struct vm_event_domain *ved)
{
    return false;
}
#endif /* CONFIG_VM_EVENT */

/*
 * Returns whether a monitor listener is attached, via either the legacy
 * v1 ring or the v2 sync/async interface.  Use this for listener-presence
 * checks (e.g. in the mem_access path); use vm_event_check_ring() only
 * when the v1 ring data structures themselves are required.
 */
static inline bool vm_event_check(struct vm_event_domain *ved)
{
    return vm_event_check_ring(ved) || vm_event_has_new_api(ved);
}

/*
 * Whether the monitor can deliver an asynchronous (non-paused) event without
 * losing it.  The legacy v1 ring carries async events inline; the v2
 * interface needs a dedicated async ring.  Used to reject configuring async
 * event delivery that would otherwise be silently dropped.  A NULL monitor
 * counts as capable: the transport is configured separately, and the
 * no-listener case is handled where events are produced.
 */
static inline bool vm_event_monitor_async_capable(const struct domain *d)
{
    const struct vm_event_domain *ved = d->vm_event_monitor;

    if ( !vm_event_has_new_api(ved) )
        return true;

    return vm_event_has_async_ring(ved);
}

/*
 * Whether the monitor can deliver a synchronous (vCPU-paused) event.  The
 * mirror of vm_event_monitor_async_capable(): a v2 monitor needs the per-vCPU
 * sync slots, which an async-only monitor does not bring up.  Used to reject
 * configuring sync event delivery that would otherwise be silently dropped.
 * A NULL or legacy v1 monitor counts as capable (the v1 ring carries sync
 * events inline; the no-listener case is handled where events are produced).
 */
static inline bool vm_event_monitor_sync_capable(const struct domain *d)
{
    const struct vm_event_domain *ved = d->vm_event_monitor;

    if ( !vm_event_has_new_api(ved) )
        return true;

    return vm_event_has_sync_slots(ved);
}

/* Returns 0 on success, -ENOSYS if there is no ring, -EBUSY if there is no
 * available space and the caller is a foreign domain. If the guest itself
 * is the caller, -EBUSY is avoided by sleeping on a wait queue to ensure
 * that the ring does not lose future events.
 *
 * However, the allow_sleep flag can be set to false in cases in which it is ok
 * to lose future events, and thus -EBUSY can be returned to guest vcpus
 * (handle with care!).
 *
 * In general, you must follow a claim_slot() call with either put_request() or
 * cancel_slot(), both of which are guaranteed to
 * succeed.
 */
int __vm_event_claim_slot(struct domain *d, struct vm_event_domain *ved,
                          bool allow_sleep);
static inline int vm_event_claim_slot(struct domain *d,
                                      struct vm_event_domain *ved)
{
    return __vm_event_claim_slot(d, ved, true);
}

static inline int vm_event_claim_slot_nosleep(struct domain *d,
                                              struct vm_event_domain *ved)
{
    return __vm_event_claim_slot(d, ved, false);
}

void vm_event_cancel_slot(struct domain *d, struct vm_event_domain *ved);

void vm_event_put_request(struct domain *d, struct vm_event_domain *ved,
                          vm_event_request_t *req);

#ifdef CONFIG_VM_EVENT
/* Clean up on domain destruction */
void vm_event_cleanup(struct domain *d);
int vm_event_domctl(struct domain *d, struct xen_domctl_vm_event_op *vec);

int vm_event_sync_enable(struct domain *d,
                         struct xen_domctl_vm_event_op *vec);
int vm_event_sync_disable(struct domain *d);

unsigned int vm_event_sync_resource_max_frames(const struct domain *d);
int vm_event_acquire_sync_resource(struct domain *d, unsigned int id,
                                   unsigned int frame, unsigned int nr_frames,
                                   xen_pfn_t mfn_list[]);

int vm_event_sync_put(struct vcpu *v, const vm_event_request_t *req);
void vm_event_sync_pickup(struct vcpu *v);

int vm_event_async_enable(struct domain *d, uint32_t async_ring_pages);
int vm_event_async_disable(struct domain *d);

unsigned int vm_event_async_resource_max_frames(const struct domain *d);
int vm_event_acquire_async_resource(struct domain *d, unsigned int id,
                                    unsigned int frame, unsigned int nr_frames,
                                    xen_pfn_t mfn_list[]);

int vm_event_async_put(struct vcpu *v, const vm_event_request_t *req);
#else /* !CONFIG_VM_EVENT */
static inline void vm_event_cleanup(struct domain *d) {}
static inline int vm_event_domctl(struct domain *d,
                                  struct xen_domctl_vm_event_op *vec)
{
    return -EOPNOTSUPP;
}
static inline int vm_event_sync_enable(struct domain *d,
                                       struct xen_domctl_vm_event_op *vec)
{
    return -EOPNOTSUPP;
}
static inline int vm_event_sync_disable(struct domain *d)
{
    return 0;
}
static inline unsigned int
vm_event_sync_resource_max_frames(const struct domain *d)
{
    return 0;
}
static inline int
vm_event_acquire_sync_resource(struct domain *d, unsigned int id,
                               unsigned int frame, unsigned int nr_frames,
                               xen_pfn_t mfn_list[])
{
    return -EOPNOTSUPP;
}
static inline int vm_event_sync_put(struct vcpu *v,
                                    const vm_event_request_t *req)
{
    return 0;
}
static inline void vm_event_sync_pickup(struct vcpu *v) {}
static inline int vm_event_async_enable(struct domain *d,
                                        uint32_t async_ring_pages)
{
    return -EOPNOTSUPP;
}
static inline int vm_event_async_disable(struct domain *d)
{
    return 0;
}
static inline unsigned int
vm_event_async_resource_max_frames(const struct domain *d)
{
    return 0;
}
static inline int
vm_event_acquire_async_resource(struct domain *d, unsigned int id,
                                unsigned int frame, unsigned int nr_frames,
                                xen_pfn_t mfn_list[])
{
    return -EOPNOTSUPP;
}
static inline int vm_event_async_put(struct vcpu *v,
                                     const vm_event_request_t *req)
{
    return 0;
}
#endif /* !CONFIG_VM_EVENT */

void vm_event_vcpu_pause(struct vcpu *v);
void vm_event_vcpu_unpause(struct vcpu *v);

void vm_event_fill_regs(vm_event_request_t *req);
void vm_event_set_registers(struct vcpu *v, vm_event_response_t *rsp);

void vm_event_monitor_next_interrupt(struct vcpu *v);

#endif /* __VM_EVENT_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
