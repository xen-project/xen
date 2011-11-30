/******************************************************************************
 * arch/x86/mm/mem_event.c
 *
 * Memory event support.
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#include <asm/domain.h>
#include <xen/event.h>
#include <asm/p2m.h>
#include <asm/mem_event.h>
#include <asm/mem_paging.h>
#include <asm/mem_access.h>

/* for public/io/ring.h macros */
#define xen_mb()   mb()
#define xen_rmb()  rmb()
#define xen_wmb()  wmb()

#define mem_event_ring_lock_init(_med)  spin_lock_init(&(_med)->ring_lock)
#define mem_event_ring_lock(_med)       spin_lock(&(_med)->ring_lock)
#define mem_event_ring_unlock(_med)     spin_unlock(&(_med)->ring_lock)

static int mem_event_enable(struct domain *d,
                            xen_domctl_mem_event_op_t *mec,
                            struct mem_event_domain *med)
{
    int rc;
    struct domain *dom_mem_event = current->domain;
    struct vcpu *v = current;
    unsigned long ring_addr = mec->ring_addr;
    unsigned long shared_addr = mec->shared_addr;
    l1_pgentry_t l1e;
    unsigned long shared_gfn = 0, ring_gfn = 0; /* gcc ... */
    p2m_type_t p2mt;
    mfn_t ring_mfn;
    mfn_t shared_mfn;

    /* Only one helper at a time. If the helper crashed,
     * the ring is in an undefined state and so is the guest.
     */
    if ( med->ring_page )
        return -EBUSY;

    /* Get MFN of ring page */
    guest_get_eff_l1e(v, ring_addr, &l1e);
    ring_gfn = l1e_get_pfn(l1e);
    /* We're grabbing these two in an order that could deadlock
     * dom0 if 1. it were an hvm 2. there were two concurrent
     * enables 3. the two gfn's in each enable criss-crossed
     * 2MB regions. Duly noted.... */
    ring_mfn = get_gfn(dom_mem_event, ring_gfn, &p2mt);

    if ( unlikely(!mfn_valid(mfn_x(ring_mfn))) )
    {
        put_gfn(dom_mem_event, ring_gfn);
        return -EINVAL;
    }

    /* Get MFN of shared page */
    guest_get_eff_l1e(v, shared_addr, &l1e);
    shared_gfn = l1e_get_pfn(l1e);
    shared_mfn = get_gfn(dom_mem_event, shared_gfn, &p2mt);

    if ( unlikely(!mfn_valid(mfn_x(shared_mfn))) )
    {
        put_gfn(dom_mem_event, ring_gfn);
        put_gfn(dom_mem_event, shared_gfn);
        return -EINVAL;
    }

    /* Map ring and shared pages */
    med->ring_page = map_domain_page(mfn_x(ring_mfn));
    med->shared_page = map_domain_page(mfn_x(shared_mfn));
    put_gfn(dom_mem_event, ring_gfn);
    put_gfn(dom_mem_event, shared_gfn); 

    /* Allocate event channel */
    rc = alloc_unbound_xen_event_channel(d->vcpu[0],
                                         current->domain->domain_id);
    if ( rc < 0 )
        goto err;

    ((mem_event_shared_page_t *)med->shared_page)->port = rc;
    med->xen_port = rc;

    /* Prepare ring buffer */
    FRONT_RING_INIT(&med->front_ring,
                    (mem_event_sring_t *)med->ring_page,
                    PAGE_SIZE);

    mem_event_ring_lock_init(med);

    /* Wake any VCPUs paused for memory events */
    mem_event_unpause_vcpus(d);

    return 0;

 err:
    unmap_domain_page(med->shared_page);
    med->shared_page = NULL;

    unmap_domain_page(med->ring_page);
    med->ring_page = NULL;

    return rc;
}

static int mem_event_disable(struct mem_event_domain *med)
{
    unmap_domain_page(med->ring_page);
    med->ring_page = NULL;

    unmap_domain_page(med->shared_page);
    med->shared_page = NULL;

    return 0;
}

void mem_event_put_request(struct domain *d, struct mem_event_domain *med, mem_event_request_t *req)
{
    mem_event_front_ring_t *front_ring;
    RING_IDX req_prod;

    mem_event_ring_lock(med);

    front_ring = &med->front_ring;
    req_prod = front_ring->req_prod_pvt;

    /* Copy request */
    memcpy(RING_GET_REQUEST(front_ring, req_prod), req, sizeof(*req));
    req_prod++;

    /* Update ring */
    med->req_producers--;
    front_ring->req_prod_pvt = req_prod;
    RING_PUSH_REQUESTS(front_ring);

    mem_event_ring_unlock(med);

    notify_via_xen_event_channel(d, med->xen_port);
}

void mem_event_get_response(struct mem_event_domain *med, mem_event_response_t *rsp)
{
    mem_event_front_ring_t *front_ring;
    RING_IDX rsp_cons;

    mem_event_ring_lock(med);

    front_ring = &med->front_ring;
    rsp_cons = front_ring->rsp_cons;

    /* Copy response */
    memcpy(rsp, RING_GET_RESPONSE(front_ring, rsp_cons), sizeof(*rsp));
    rsp_cons++;

    /* Update ring */
    front_ring->rsp_cons = rsp_cons;
    front_ring->sring->rsp_event = rsp_cons + 1;

    mem_event_ring_unlock(med);
}

void mem_event_unpause_vcpus(struct domain *d)
{
    struct vcpu *v;

    for_each_vcpu ( d, v )
        if ( test_and_clear_bit(_VPF_mem_event, &v->pause_flags) )
            vcpu_wake(v);
}

void mem_event_mark_and_pause(struct vcpu *v)
{
    set_bit(_VPF_mem_event, &v->pause_flags);
    vcpu_sleep_nosync(v);
}

void mem_event_put_req_producers(struct mem_event_domain *med)
{
    mem_event_ring_lock(med);
    med->req_producers--;
    mem_event_ring_unlock(med);
}

int mem_event_check_ring(struct domain *d, struct mem_event_domain *med)
{
    struct vcpu *curr = current;
    int free_requests;
    int ring_full = 1;

    if ( !med->ring_page )
        return -1;

    mem_event_ring_lock(med);

    free_requests = RING_FREE_REQUESTS(&med->front_ring);
    if ( med->req_producers < free_requests )
    {
        med->req_producers++;
        ring_full = 0;
    }

    if ( ring_full && (curr->domain == d) )
        mem_event_mark_and_pause(curr);

    mem_event_ring_unlock(med);

    return ring_full;
}

int mem_event_domctl(struct domain *d, xen_domctl_mem_event_op_t *mec,
                     XEN_GUEST_HANDLE(void) u_domctl)
{
    int rc;

    if ( unlikely(d == current->domain) )
    {
        gdprintk(XENLOG_INFO, "Tried to do a memory paging op on itself.\n");
        return -EINVAL;
    }

    if ( unlikely(d->is_dying) )
    {
        gdprintk(XENLOG_INFO, "Ignoring memory paging op on dying domain %u\n",
                 d->domain_id);
        return 0;
    }

    if ( unlikely(d->vcpu == NULL) || unlikely(d->vcpu[0] == NULL) )
    {
        gdprintk(XENLOG_INFO,
                 "Memory paging op on a domain (%u) with no vcpus\n",
                 d->domain_id);
        return -EINVAL;
    }

    /* TODO: XSM hook */
#if 0
    rc = xsm_mem_event_control(d, mec->op);
    if ( rc )
        return rc;
#endif

    rc = -ENOSYS;

    switch ( mec->mode )
    {
    case XEN_DOMCTL_MEM_EVENT_OP_PAGING:
    {
        struct mem_event_domain *med = &d->mem_event->paging;
        rc = -EINVAL;

        switch( mec->op )
        {
        case XEN_DOMCTL_MEM_EVENT_OP_PAGING_ENABLE:
        {
            struct p2m_domain *p2m = p2m_get_hostp2m(d);
            rc = -ENODEV;
            /* Only HAP is supported */
            if ( !hap_enabled(d) )
                break;

            /* Currently only EPT is supported */
            if ( boot_cpu_data.x86_vendor != X86_VENDOR_INTEL )
                break;

            rc = -EXDEV;
            /* Disallow paging in a PoD guest */
            if ( p2m->pod.entry_count )
                break;

            rc = mem_event_enable(d, mec, med);
        }
        break;

        case XEN_DOMCTL_MEM_EVENT_OP_PAGING_DISABLE:
        {
            if ( med->ring_page )
                rc = mem_event_disable(med);
        }
        break;

        default:
        {
            if ( med->ring_page )
                rc = mem_paging_domctl(d, mec, u_domctl);
        }
        break;
        }
    }
    break;

    case XEN_DOMCTL_MEM_EVENT_OP_ACCESS: 
    {
        struct mem_event_domain *med = &d->mem_event->access;
        rc = -EINVAL;

        switch( mec->op )
        {
        case XEN_DOMCTL_MEM_EVENT_OP_ACCESS_ENABLE:
        {
            rc = -ENODEV;
            /* Only HAP is supported */
            if ( !hap_enabled(d) )
                break;

            /* Currently only EPT is supported */
            if ( boot_cpu_data.x86_vendor != X86_VENDOR_INTEL )
                break;

            rc = mem_event_enable(d, mec, med);
        }
        break;

        case XEN_DOMCTL_MEM_EVENT_OP_ACCESS_DISABLE:
        {
            if ( med->ring_page )
                rc = mem_event_disable(med);
        }
        break;

        default:
        {
            if ( med->ring_page )
                rc = mem_access_domctl(d, mec, u_domctl);
        }
        break;
        }
    }
    break;
    }

    return rc;
}


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
