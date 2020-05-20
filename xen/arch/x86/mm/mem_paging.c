/******************************************************************************
 * arch/x86/mm/mem_paging.c
 *
 * Memory paging support.
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


#include <asm/p2m.h>
#include <xen/guest_access.h>
#include <xen/vm_event.h>
#include <xsm/xsm.h>

#include "mm-locks.h"

/*
 * p2m_mem_paging_drop_page - Tell pager to drop its reference to a paged page
 * @d: guest domain
 * @gfn: guest page to drop
 *
 * p2m_mem_paging_drop_page() will notify the pager that a paged-out gfn was
 * released by the guest. The pager is supposed to drop its reference of the
 * gfn.
 */
void p2m_mem_paging_drop_page(struct domain *d, gfn_t gfn, p2m_type_t p2mt)
{
    vm_event_request_t req = {
        .reason = VM_EVENT_REASON_MEM_PAGING,
        .u.mem_paging.gfn = gfn_x(gfn)
    };

    /*
     * We allow no ring in this unique case, because it won't affect
     * correctness of the guest execution at this point.  If this is the only
     * page that happens to be paged-out, we'll be okay..  but it's likely the
     * guest will crash shortly anyways.
     */
    int rc = vm_event_claim_slot(d, d->vm_event_paging);

    if ( rc < 0 )
        return;

    /* Send release notification to pager */
    req.u.mem_paging.flags = MEM_PAGING_DROP_PAGE;

    /* Update stats unless the page hasn't yet been evicted */
    if ( p2mt != p2m_ram_paging_out )
        atomic_dec(&d->paged_pages);
    else
        /* Evict will fail now, tag this request for pager */
        req.u.mem_paging.flags |= MEM_PAGING_EVICT_FAIL;

    vm_event_put_request(d, d->vm_event_paging, &req);
}

/*
 * p2m_mem_paging_populate - Tell pager to populate a paged page
 * @d: guest domain
 * @gfn: guest page in paging state
 *
 * p2m_mem_paging_populate() will notify the pager that a page in any of the
 * paging states needs to be written back into the guest.
 * This function needs to be called whenever gfn_to_mfn() returns any of the p2m
 * paging types because the gfn may not be backed by a mfn.
 *
 * The gfn can be in any of the paging states, but the pager needs only be
 * notified when the gfn is in the paging-out path (paging_out or paged).  This
 * function may be called more than once from several vcpus. If the vcpu belongs
 * to the guest, the vcpu must be stopped and the pager notified that the vcpu
 * was stopped. The pager needs to handle several requests for the same gfn.
 *
 * If the gfn is not in the paging-out path and the vcpu does not belong to the
 * guest, nothing needs to be done and the function assumes that a request was
 * already sent to the pager. In this case the caller has to try again until the
 * gfn is fully paged in again.
 */
void p2m_mem_paging_populate(struct domain *d, gfn_t gfn)
{
    struct vcpu *v = current;
    vm_event_request_t req = {
        .reason = VM_EVENT_REASON_MEM_PAGING,
        .u.mem_paging.gfn = gfn_x(gfn)
    };
    p2m_type_t p2mt;
    p2m_access_t a;
    mfn_t mfn;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    int rc = vm_event_claim_slot(d, d->vm_event_paging);

    /* We're paging. There should be a ring. */
    if ( rc == -EOPNOTSUPP )
    {
        gdprintk(XENLOG_ERR, "%pd paging gfn %"PRI_gfn" yet no ring in place\n",
                 d, gfn_x(gfn));
        /* Prevent the vcpu from faulting repeatedly on the same gfn */
        if ( v->domain == d )
            vcpu_pause_nosync(v);
        domain_crash(d);
        return;
    }
    else if ( rc < 0 )
        return;

    /* Fix p2m mapping */
    gfn_lock(p2m, gfn, 0);
    mfn = p2m->get_entry(p2m, gfn, &p2mt, &a, 0, NULL, NULL);
    /* Allow only nominated or evicted pages to enter page-in path */
    if ( p2mt == p2m_ram_paging_out || p2mt == p2m_ram_paged )
    {
        /* Evict will fail now, tag this request for pager */
        if ( p2mt == p2m_ram_paging_out )
            req.u.mem_paging.flags |= MEM_PAGING_EVICT_FAIL;

        rc = p2m_set_entry(p2m, gfn, mfn, PAGE_ORDER_4K, p2m_ram_paging_in, a);
    }
    gfn_unlock(p2m, gfn, 0);
    if ( rc < 0 )
        goto out_cancel;

    /* Pause domain if request came from guest and gfn has paging type */
    if ( p2m_is_paging(p2mt) && v->domain == d )
    {
        vm_event_vcpu_pause(v);
        req.flags |= VM_EVENT_FLAG_VCPU_PAUSED;
    }
    /* No need to inform pager if the gfn is not in the page-out path */
    else if ( p2mt != p2m_ram_paging_out && p2mt != p2m_ram_paged )
    {
        /* gfn is already on its way back and vcpu is not paused */
    out_cancel:
        vm_event_cancel_slot(d, d->vm_event_paging);
        return;
    }

    /* Send request to pager */
    req.u.mem_paging.p2mt = p2mt;
    req.vcpu_id = v->vcpu_id;

    vm_event_put_request(d, d->vm_event_paging, &req);
}

/*
 * p2m_mem_paging_resume - Resume guest gfn
 * @d: guest domain
 * @rsp: vm_event response received
 *
 * p2m_mem_paging_resume() will forward the p2mt of a gfn to ram_rw. It is
 * called by the pager.
 *
 * The gfn was previously either evicted and populated, or nominated and
 * populated. If the page was evicted the p2mt will be p2m_ram_paging_in. If
 * the page was just nominated the p2mt will be p2m_ram_paging_in_start because
 * the pager did not call prepare().
 *
 * If the gfn was dropped the vcpu needs to be unpaused.
 */
void p2m_mem_paging_resume(struct domain *d, vm_event_response_t *rsp)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    p2m_type_t p2mt;
    p2m_access_t a;
    mfn_t mfn;

    /* Fix p2m entry if the page was not dropped */
    if ( !(rsp->u.mem_paging.flags & MEM_PAGING_DROP_PAGE) )
    {
        gfn_t gfn = _gfn(rsp->u.mem_access.gfn);

        gfn_lock(p2m, gfn, 0);
        mfn = p2m->get_entry(p2m, gfn, &p2mt, &a, 0, NULL, NULL);
        /*
         * Allow only pages which were prepared properly, or pages which
         * were nominated but not evicted.
         */
        if ( mfn_valid(mfn) && (p2mt == p2m_ram_paging_in) )
        {
            int rc = p2m_set_entry(p2m, gfn, mfn, PAGE_ORDER_4K,
                                   paging_mode_log_dirty(d) ? p2m_ram_logdirty
                                                            : p2m_ram_rw, a);

            if ( !rc )
                set_gpfn_from_mfn(mfn_x(mfn), gfn_x(gfn));
        }
        gfn_unlock(p2m, gfn, 0);
    }
}

/*
 * nominate - Mark a guest page as to-be-paged-out
 * @d: guest domain
 * @gfn: guest page to nominate
 *
 * Returns 0 for success or negative errno values if gfn is not pageable.
 *
 * nominate() is called by the pager and checks if a guest page can be paged
 * out. If the following conditions are met the p2mt will be changed:
 * - the gfn is backed by a mfn
 * - the p2mt of the gfn is pageable
 * - the mfn is not used for IO
 * - the mfn has exactly one user and has no special meaning
 *
 * Once the p2mt is changed the page is readonly for the guest.  On success the
 * pager can write the page contents to disk and later evict the page.
 */
static int nominate(struct domain *d, gfn_t gfn)
{
    struct page_info *page;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    p2m_type_t p2mt;
    p2m_access_t a;
    mfn_t mfn;
    int ret = -EBUSY;

    gfn_lock(p2m, gfn, 0);

    mfn = p2m->get_entry(p2m, gfn, &p2mt, &a, 0, NULL, NULL);

    /* Check if mfn is valid */
    if ( !mfn_valid(mfn) )
        goto out;

    /* Check p2m type */
    if ( !p2m_is_pageable(p2mt) )
        goto out;

    /* Check for io memory page */
    if ( is_iomem_page(mfn) )
        goto out;

    /* Check page count and type */
    page = mfn_to_page(mfn);
    if ( (page->count_info & (PGC_count_mask | PGC_allocated)) !=
         (1 | PGC_allocated) )
        goto out;

    if ( (page->u.inuse.type_info & PGT_count_mask) != 0 )
        goto out;

    /* Fix p2m entry */
    ret = p2m_set_entry(p2m, gfn, mfn, PAGE_ORDER_4K, p2m_ram_paging_out, a);

 out:
    gfn_unlock(p2m, gfn, 0);
    return ret;
}

/*
 * evict - Mark a guest page as paged-out
 * @d: guest domain
 * @gfn: guest page to evict
 *
 * Returns 0 for success or negative errno values if eviction is not possible.
 *
 * evict() is called by the pager and will free a guest page and release it
 * back to Xen. If the following conditions are met the page can be freed:
 * - the gfn is backed by a mfn
 * - the gfn was nominated
 * - the mfn has still exactly one user and has no special meaning
 *
 * After successful nomination some other process could have mapped the page. In
 * this case eviction can not be done. If the gfn was populated before the pager
 * could evict it, eviction can not be done either. In this case the gfn is
 * still backed by a mfn.
 */
static int evict(struct domain *d, gfn_t gfn)
{
    struct page_info *page;
    p2m_type_t p2mt;
    p2m_access_t a;
    mfn_t mfn;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    int ret = -EBUSY;

    gfn_lock(p2m, gfn, 0);

    /* Get mfn */
    mfn = p2m->get_entry(p2m, gfn, &p2mt, &a, 0, NULL, NULL);
    if ( unlikely(!mfn_valid(mfn)) )
        goto out;

    /* Allow only nominated pages */
    if ( p2mt != p2m_ram_paging_out )
        goto out;

    /* Get the page so it doesn't get modified under Xen's feet */
    page = mfn_to_page(mfn);
    if ( unlikely(!get_page(page, d)) )
        goto out;

    /* Check page count and type once more */
    if ( (page->count_info & (PGC_count_mask | PGC_allocated)) !=
         (2 | PGC_allocated) )
        goto out_put;

    if ( (page->u.inuse.type_info & PGT_count_mask) != 0 )
        goto out_put;

    /* Decrement guest domain's ref count of the page */
    put_page_alloc_ref(page);

    /* Remove mapping from p2m table */
    ret = p2m_set_entry(p2m, gfn, INVALID_MFN, PAGE_ORDER_4K,
                        p2m_ram_paged, a);

    /* Clear content before returning the page to Xen */
    scrub_one_page(page);

    /* Track number of paged gfns */
    atomic_inc(&d->paged_pages);

 out_put:
    /* Put the page back so it gets freed */
    put_page(page);

 out:
    gfn_unlock(p2m, gfn, 0);
    return ret;
}

/*
 * prepare - Allocate a new page for the guest
 * @d: guest domain
 * @gfn: guest page in paging state
 *
 * prepare() will allocate a new page for the guest if the gfn is not backed
 * by a mfn. It is called by the pager.
 * It is required that the gfn was already populated. The gfn may already have a
 * mfn if populate was called for  gfn which was nominated but not evicted. In
 * this case only the p2mt needs to be forwarded.
 */
static int prepare(struct domain *d, gfn_t gfn,
                   XEN_GUEST_HANDLE_64(const_uint8) buffer)
{
    struct page_info *page = NULL;
    p2m_type_t p2mt;
    p2m_access_t a;
    mfn_t mfn;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    int ret, page_extant = 1;

    if ( !guest_handle_okay(buffer, PAGE_SIZE) )
        return -EINVAL;

    gfn_lock(p2m, gfn, 0);

    mfn = p2m->get_entry(p2m, gfn, &p2mt, &a, 0, NULL, NULL);

    ret = -ENOENT;
    /* Allow missing pages */
    if ( (p2mt != p2m_ram_paging_in) && (p2mt != p2m_ram_paged) )
        goto out;

    /* Allocate a page if the gfn does not have one yet */
    if ( !mfn_valid(mfn) )
    {
        void *guest_map;

        /* If the user did not provide a buffer, we disallow */
        ret = -EINVAL;
        if ( unlikely(guest_handle_is_null(buffer)) )
            goto out;
        /* Get a free page */
        ret = -ENOMEM;
        page_alloc_mm_pre_lock(d);
        page = alloc_domheap_page(d, 0);
        if ( unlikely(page == NULL) )
            goto out;
        if ( unlikely(!get_page(page, d)) )
        {
            /*
             * The domain can't possibly know about this page yet, so failure
             * here is a clear indication of something fishy going on.
             */
            gprintk(XENLOG_ERR,
                    "%pd: fresh page for GFN %"PRI_gfn" in unexpected state\n",
                    d, gfn_x(gfn));
            domain_crash(d);
            page = NULL;
            goto out;
        }
        mfn = page_to_mfn(page);
        page_extant = 0;

        guest_map = map_domain_page(mfn);
        ret = copy_from_guest(guest_map, buffer, PAGE_SIZE);
        unmap_domain_page(guest_map);
        if ( ret )
        {
            ret = -EFAULT;
            goto out;
        }
    }

    /*
     * Make the page already guest-accessible. If the pager still has a
     * pending resume operation, it will be idempotent p2m entry-wise, but
     * will unpause the vcpu.
     */
    ret = p2m_set_entry(p2m, gfn, mfn, PAGE_ORDER_4K,
                        paging_mode_log_dirty(d) ? p2m_ram_logdirty
                                                 : p2m_ram_rw, a);
    if ( !ret )
    {
        set_gpfn_from_mfn(mfn_x(mfn), gfn_x(gfn));

        if ( !page_extant )
            atomic_dec(&d->paged_pages);
    }

 out:
    gfn_unlock(p2m, gfn, 0);

    if ( page )
    {
        /*
         * Free the page on error.  Drop our temporary reference in all
         * cases.
         */
        if ( ret )
            put_page_alloc_ref(page);
        put_page(page);
    }

    return ret;
}

int mem_paging_memop(XEN_GUEST_HANDLE_PARAM(xen_mem_paging_op_t) arg)
{
    int rc;
    xen_mem_paging_op_t mpo;
    struct domain *d;
    bool_t copyback = 0;

    if ( copy_from_guest(&mpo, arg, 1) )
        return -EFAULT;

    rc = rcu_lock_live_remote_domain_by_id(mpo.domain, &d);
    if ( rc )
        return rc;

    rc = xsm_mem_paging(XSM_DM_PRIV, d);
    if ( rc )
        goto out;

    rc = -ENODEV;
    if ( unlikely(!vm_event_check_ring(d->vm_event_paging)) )
        goto out;

    switch( mpo.op )
    {
    case XENMEM_paging_op_nominate:
        rc = nominate(d, _gfn(mpo.gfn));
        break;

    case XENMEM_paging_op_evict:
        rc = evict(d, _gfn(mpo.gfn));
        break;

    case XENMEM_paging_op_prep:
        rc = prepare(d, _gfn(mpo.gfn), mpo.buffer);
        if ( !rc )
            copyback = 1;
        break;

    default:
        rc = -ENOSYS;
        break;
    }

    if ( copyback && __copy_to_guest(arg, &mpo, 1) )
        rc = -EFAULT;

out:
    rcu_unlock_domain(d);
    return rc;
}


/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
