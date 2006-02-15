/******************************************************************************
 * common/grant_table.c
 * 
 * Mechanism for granting foreign access to page frames, and receiving
 * page-ownership transfers.
 * 
 * Copyright (c) 2005 Christopher Clark
 * Copyright (c) 2004 K A Fraser
 * Copyright (c) 2005 Andrew Warfield
 * Modifications by Geoffrey Lefebvre are (c) Intel Research Cambridge
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

#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/shadow.h>
#include <xen/mm.h>
#include <acm/acm_hooks.h>
#include <xen/trace.h>

#define PIN_FAIL(_lbl, _rc, _f, _a...)          \
    do {                                        \
        DPRINTK( _f, ## _a );                   \
        rc = (_rc);                             \
        goto _lbl;                              \
    } while ( 0 )

static inline int
get_maptrack_handle(
    grant_table_t *t)
{
    unsigned int h;
    if ( unlikely((h = t->maptrack_head) == (t->maptrack_limit - 1)) )
        return -1;
    t->maptrack_head = t->maptrack[h].ref_and_flags >> MAPTRACK_REF_SHIFT;
    t->map_count++;
    return h;
}

static inline void
put_maptrack_handle(
    grant_table_t *t, int handle)
{
    t->maptrack[handle].ref_and_flags = t->maptrack_head << MAPTRACK_REF_SHIFT;
    t->maptrack_head = handle;
    t->map_count--;
}

/*
 * Returns 0 if TLB flush / invalidate required by caller.
 * va will indicate the address to be invalidated.
 * 
 * addr is _either_ a host virtual address, or the address of the pte to
 * update, as indicated by the GNTMAP_contains_pte flag.
 */
static void
__gnttab_map_grant_ref(
    struct gnttab_map_grant_ref *op)
{
    struct domain *ld, *rd;
    struct vcpu   *led;
    int            handle;
    unsigned long  frame = 0;
    int            rc = GNTST_okay;
    active_grant_entry_t *act;

    /* Entry details from @rd's shared grant table. */
    grant_entry_t *sha;
    domid_t        sdom;
    u16            sflags;

    /*
     * We bound the number of times we retry CMPXCHG on memory locations that
     * we share with a guest OS. The reason is that the guest can modify that
     * location at a higher rate than we can read-modify-CMPXCHG, so the guest
     * could cause us to livelock. There are a few cases where it is valid for
     * the guest to race our updates (e.g., to change the GTF_readonly flag),
     * so we allow a few retries before failing.
     */
    int retries = 0;

    led = current;
    ld = led->domain;

    if ( unlikely(op->ref >= NR_GRANT_ENTRIES) ||
         unlikely((op->flags & (GNTMAP_device_map|GNTMAP_host_map)) == 0) )
    {
        DPRINTK("Bad ref (%d) or flags (%x).\n", op->ref, op->flags);
        op->status = GNTST_bad_gntref;
        return;
    }

    if ( acm_pre_grant_map_ref(op->dom) )
    {
        op->status = GNTST_permission_denied;
        return;
    }

    if ( unlikely((rd = find_domain_by_id(op->dom)) == NULL) ||
         unlikely(ld == rd) )
    {
        if ( rd != NULL )
            put_domain(rd);
        DPRINTK("Could not find domain %d\n", op->dom);
        op->status = GNTST_bad_domain;
        return;
    }

    /* Get a maptrack handle. */
    if ( unlikely((handle = get_maptrack_handle(ld->grant_table)) == -1) )
    {
        int              i;
        grant_mapping_t *new_mt;
        grant_table_t   *lgt = ld->grant_table;

        if ( (lgt->maptrack_limit << 1) > MAPTRACK_MAX_ENTRIES )
        {
            put_domain(rd);
            DPRINTK("Maptrack table is at maximum size.\n");
            op->status = GNTST_no_device_space;
            return;
        }

        /* Grow the maptrack table. */
        new_mt = alloc_xenheap_pages(lgt->maptrack_order + 1);
        if ( new_mt == NULL )
        {
            put_domain(rd);
            DPRINTK("No more map handles available.\n");
            op->status = GNTST_no_device_space;
            return;
        }

        memcpy(new_mt, lgt->maptrack, PAGE_SIZE << lgt->maptrack_order);
        for ( i = lgt->maptrack_limit; i < (lgt->maptrack_limit << 1); i++ )
            new_mt[i].ref_and_flags = (i+1) << MAPTRACK_REF_SHIFT;

        free_xenheap_pages(lgt->maptrack, lgt->maptrack_order);
        lgt->maptrack          = new_mt;
        lgt->maptrack_order   += 1;
        lgt->maptrack_limit  <<= 1;

        DPRINTK("Doubled maptrack size\n");
        handle = get_maptrack_handle(ld->grant_table);
    }

    act = &rd->grant_table->active[op->ref];
    sha = &rd->grant_table->shared[op->ref];

    spin_lock(&rd->grant_table->lock);

    if ( !act->pin ||
         (!(op->flags & GNTMAP_readonly) &&
          !(act->pin & (GNTPIN_hstw_mask|GNTPIN_devw_mask))) )
    {
        sflags = sha->flags;
        sdom   = sha->domid;

        /*
         * This loop attempts to set the access (reading/writing) flags
         * in the grant table entry.  It tries a cmpxchg on the field
         * up to five times, and then fails under the assumption that 
         * the guest is misbehaving.
         */
        for ( ; ; )
        {
            u32 scombo, prev_scombo, new_scombo;

            if ( unlikely((sflags & GTF_type_mask) != GTF_permit_access) ||
                 unlikely(sdom != led->domain->domain_id) )
                PIN_FAIL(unlock_out, GNTST_general_error,
                         "Bad flags (%x) or dom (%d). (NB. expected dom %d)\n",
                         sflags, sdom, led->domain->domain_id);

            /* Merge two 16-bit values into a 32-bit combined update. */
            /* NB. Endianness! */
            prev_scombo = scombo = ((u32)sdom << 16) | (u32)sflags;

            new_scombo = scombo | GTF_reading;
            if ( !(op->flags & GNTMAP_readonly) )
            {
                new_scombo |= GTF_writing;
                if ( unlikely(sflags & GTF_readonly) )
                    PIN_FAIL(unlock_out, GNTST_general_error,
                             "Attempt to write-pin a r/o grant entry.\n");
            }

            /* NB. prev_scombo is updated in place to seen value. */
            if ( unlikely(cmpxchg_user((u32 *)&sha->flags,
                                       prev_scombo,
                                       new_scombo)) )
                PIN_FAIL(unlock_out, GNTST_general_error,
                         "Fault while modifying shared flags and domid.\n");

            /* Did the combined update work (did we see what we expected?). */
            if ( likely(prev_scombo == scombo) )
                break;

            if ( retries++ == 4 )
                PIN_FAIL(unlock_out, GNTST_general_error,
                         "Shared grant entry is unstable.\n");

            /* Didn't see what we expected. Split out the seen flags & dom. */
            /* NB. Endianness! */
            sflags = (u16)prev_scombo;
            sdom   = (u16)(prev_scombo >> 16);
        }

        if ( !act->pin )
        {
            act->domid = sdom;
            act->frame = gmfn_to_mfn(rd, sha->frame);
        }
    }
    else if ( (act->pin & 0x80808080U) != 0 )
        PIN_FAIL(unlock_out, ENOSPC,
                 "Risk of counter overflow %08x\n", act->pin);

    if ( op->flags & GNTMAP_device_map )
        act->pin += (op->flags & GNTMAP_readonly) ?
            GNTPIN_devr_inc : GNTPIN_devw_inc;
    if ( op->flags & GNTMAP_host_map )
        act->pin += (op->flags & GNTMAP_readonly) ?
            GNTPIN_hstr_inc : GNTPIN_hstw_inc;

    spin_unlock(&rd->grant_table->lock);

    frame = act->frame;
    if ( unlikely(!mfn_valid(frame)) ||
         unlikely(!((op->flags & GNTMAP_readonly) ?
                    get_page(mfn_to_page(frame), rd) :
                    get_page_and_type(mfn_to_page(frame), rd,
                                      PGT_writable_page))) )
        PIN_FAIL(undo_out, GNTST_general_error,
                 "Could not pin the granted frame (%lx)!\n", frame);

    if ( op->flags & GNTMAP_host_map )
    {
        rc = create_grant_host_mapping(op->host_addr, frame, op->flags);
        if ( rc != GNTST_okay )
        {
            if ( !(op->flags & GNTMAP_readonly) )
                put_page_type(mfn_to_page(frame));
            put_page(mfn_to_page(frame));
            goto undo_out;
        }

        if ( op->flags & GNTMAP_device_map )
        {
            (void)get_page(mfn_to_page(frame), rd);
            if ( !(op->flags & GNTMAP_readonly) )
                get_page_type(mfn_to_page(frame), PGT_writable_page);
        }
    }

    TRACE_1D(TRC_MEM_PAGE_GRANT_MAP, op->dom);

    ld->grant_table->maptrack[handle].domid         = op->dom;
    ld->grant_table->maptrack[handle].ref_and_flags =
        (op->ref << MAPTRACK_REF_SHIFT) |
        (op->flags & MAPTRACK_GNTMAP_MASK);

    op->dev_bus_addr = (u64)frame << PAGE_SHIFT;
    op->handle       = handle;
    op->status       = GNTST_okay;

    put_domain(rd);
    return;

 undo_out:
    spin_lock(&rd->grant_table->lock);

    if ( op->flags & GNTMAP_device_map )
        act->pin -= (op->flags & GNTMAP_readonly) ?
            GNTPIN_devr_inc : GNTPIN_devw_inc;
    if ( op->flags & GNTMAP_host_map )
        act->pin -= (op->flags & GNTMAP_readonly) ?
            GNTPIN_hstr_inc : GNTPIN_hstw_inc;

    if ( !(op->flags & GNTMAP_readonly) &&
         !(act->pin & (GNTPIN_hstw_mask|GNTPIN_devw_mask)) )
        clear_bit(_GTF_writing, &sha->flags);

    if ( !act->pin )
        clear_bit(_GTF_reading, &sha->flags);

 unlock_out:
    spin_unlock(&rd->grant_table->lock);
    op->status = rc;
    put_maptrack_handle(ld->grant_table, handle);
    put_domain(rd);
}

static long
gnttab_map_grant_ref(
    struct gnttab_map_grant_ref *uop, unsigned int count)
{
    int i;
    struct gnttab_map_grant_ref op;

    for ( i = 0; i < count; i++ )
    {
        if ( unlikely(__copy_from_user(&op, &uop[i], sizeof(op))) )
            return -EFAULT;
        __gnttab_map_grant_ref(&op);
        if ( unlikely(__copy_to_user(&uop[i], &op, sizeof(op))) )
            return -EFAULT;
    }

    return 0;
}

static void
__gnttab_unmap_grant_ref(
    struct gnttab_unmap_grant_ref *op)
{
    domid_t          dom;
    grant_ref_t      ref;
    struct domain   *ld, *rd;
    active_grant_entry_t *act;
    grant_entry_t   *sha;
    grant_mapping_t *map;
    u16              flags;
    s16              rc = 0;
    unsigned long    frame;

    ld = current->domain;

    frame = (unsigned long)(op->dev_bus_addr >> PAGE_SHIFT);

    map = &ld->grant_table->maptrack[op->handle];

    if ( unlikely(op->handle >= ld->grant_table->maptrack_limit) ||
         unlikely(!(map->ref_and_flags & MAPTRACK_GNTMAP_MASK)) )
    {
        DPRINTK("Bad handle (%d).\n", op->handle);
        op->status = GNTST_bad_handle;
        return;
    }

    dom   = map->domid;
    ref   = map->ref_and_flags >> MAPTRACK_REF_SHIFT;
    flags = map->ref_and_flags & MAPTRACK_GNTMAP_MASK;

    if ( unlikely((rd = find_domain_by_id(dom)) == NULL) ||
         unlikely(ld == rd) )
    {
        if ( rd != NULL )
            put_domain(rd);
        DPRINTK("Could not find domain %d\n", dom);
        op->status = GNTST_bad_domain;
        return;
    }

    TRACE_1D(TRC_MEM_PAGE_GRANT_UNMAP, dom);

    act = &rd->grant_table->active[ref];
    sha = &rd->grant_table->shared[ref];

    spin_lock(&rd->grant_table->lock);

    if ( frame == 0 )
    {
        frame = act->frame;
    }
    else
    {
        if ( unlikely(frame != act->frame) )
            PIN_FAIL(unmap_out, GNTST_general_error,
                     "Bad frame number doesn't match gntref.\n");
        if ( flags & GNTMAP_device_map )
        {
            ASSERT(act->pin & (GNTPIN_devw_mask | GNTPIN_devr_mask));
            map->ref_and_flags &= ~GNTMAP_device_map;
            if ( flags & GNTMAP_readonly )
            {
                act->pin -= GNTPIN_devr_inc;
                put_page(mfn_to_page(frame));
            }
            else
            {
                act->pin -= GNTPIN_devw_inc;
                put_page_and_type(mfn_to_page(frame));
            }
        }
    }

    if ( (op->host_addr != 0) && (flags & GNTMAP_host_map) )
    {
        if ( (rc = destroy_grant_host_mapping(op->host_addr,
                                              frame, flags)) < 0 )
            goto unmap_out;

        ASSERT(act->pin & (GNTPIN_hstw_mask | GNTPIN_hstr_mask));
        map->ref_and_flags &= ~GNTMAP_host_map;
        if ( flags & GNTMAP_readonly )
        {
            act->pin -= GNTPIN_hstr_inc;
            put_page(mfn_to_page(frame));
        }
        else
        {
            act->pin -= GNTPIN_hstw_inc;
            put_page_and_type(mfn_to_page(frame));
        }
    }

    if ( (map->ref_and_flags & (GNTMAP_device_map|GNTMAP_host_map)) == 0 )
    {
        map->ref_and_flags = 0;
        put_maptrack_handle(ld->grant_table, op->handle);
    }

    /* If just unmapped a writable mapping, mark as dirtied */
    if ( !(flags & GNTMAP_readonly) )
         gnttab_log_dirty(rd, frame);

    if ( ((act->pin & (GNTPIN_devw_mask|GNTPIN_hstw_mask)) == 0) &&
         !(flags & GNTMAP_readonly) )
        clear_bit(_GTF_writing, &sha->flags);

    if ( act->pin == 0 )
        clear_bit(_GTF_reading, &sha->flags);

 unmap_out:
    op->status = rc;
    spin_unlock(&rd->grant_table->lock);
    put_domain(rd);
}

static long
gnttab_unmap_grant_ref(
    struct gnttab_unmap_grant_ref *uop, unsigned int count)
{
    int i;
    struct gnttab_unmap_grant_ref op;

    for ( i = 0; i < count; i++ )
    {
        if ( unlikely(__copy_from_user(&op, &uop[i], sizeof(op))) )
            goto fault;
        __gnttab_unmap_grant_ref(&op);
        if ( unlikely(__copy_to_user(&uop[i], &op, sizeof(op))) )
            goto fault;
    }

    flush_tlb_mask(current->domain->domain_dirty_cpumask);
    return 0;

fault:
    flush_tlb_mask(current->domain->domain_dirty_cpumask);
    return -EFAULT;    
}

static long 
gnttab_setup_table(
    struct gnttab_setup_table *uop, unsigned int count)
{
    struct gnttab_setup_table op;
    struct domain *d;
    int            i;
    unsigned long  gmfn;
    domid_t        dom;

    if ( count != 1 )
        return -EINVAL;

    if ( unlikely(copy_from_user(&op, uop, sizeof(op)) != 0) )
    {
        DPRINTK("Fault while reading gnttab_setup_table_t.\n");
        return -EFAULT;
    }

    if ( unlikely(op.nr_frames > NR_GRANT_FRAMES) )
    {
        DPRINTK("Xen only supports up to %d grant-table frames per domain.\n",
                NR_GRANT_FRAMES);
        op.status = GNTST_general_error;
        goto out;
    }

    dom = op.dom;
    if ( dom == DOMID_SELF )
    {
        dom = current->domain->domain_id;
    }
    else if ( unlikely(!IS_PRIV(current->domain)) )
    {
        op.status = GNTST_permission_denied;
        goto out;
    }

    if ( unlikely((d = find_domain_by_id(dom)) == NULL) )
    {
        DPRINTK("Bad domid %d.\n", dom);
        op.status = GNTST_bad_domain;
        goto out;
    }

    if ( op.nr_frames <= NR_GRANT_FRAMES )
    {
        ASSERT(d->grant_table != NULL);
        op.status = GNTST_okay;
        for ( i = 0; i < op.nr_frames; i++ )
        {
            gmfn = gnttab_shared_gmfn(d, d->grant_table, i);
            (void)copy_to_user(&op.frame_list[i], &gmfn, sizeof(gmfn));
        }
    }

    put_domain(d);

 out:
    if ( unlikely(copy_to_user(uop, &op, sizeof(op))) )
        return -EFAULT;

    return 0;
}

/*
 * Check that the given grant reference (rd,ref) allows 'ld' to transfer
 * ownership of a page frame. If so, lock down the grant entry.
 */
static int 
gnttab_prepare_for_transfer(
    struct domain *rd, struct domain *ld, grant_ref_t ref)
{
    grant_table_t *rgt;
    grant_entry_t *sha;
    domid_t        sdom;
    u16            sflags;
    u32            scombo, prev_scombo;
    int            retries = 0;

    if ( unlikely((rgt = rd->grant_table) == NULL) ||
         unlikely(ref >= NR_GRANT_ENTRIES) )
    {
        DPRINTK("Dom %d has no g.t., or ref is bad (%d).\n",
                rd->domain_id, ref);
        return 0;
    }

    spin_lock(&rgt->lock);

    sha = &rgt->shared[ref];
    
    sflags = sha->flags;
    sdom   = sha->domid;

    for ( ; ; )
    {
        if ( unlikely(sflags != GTF_accept_transfer) ||
             unlikely(sdom != ld->domain_id) )
        {
            DPRINTK("Bad flags (%x) or dom (%d). (NB. expected dom %d)\n",
                    sflags, sdom, ld->domain_id);
            goto fail;
        }

        /* Merge two 16-bit values into a 32-bit combined update. */
        /* NB. Endianness! */
        prev_scombo = scombo = ((u32)sdom << 16) | (u32)sflags;

        /* NB. prev_scombo is updated in place to seen value. */
        if ( unlikely(cmpxchg_user((u32 *)&sha->flags, prev_scombo, 
                                   prev_scombo | GTF_transfer_committed)) )
        {
            DPRINTK("Fault while modifying shared flags and domid.\n");
            goto fail;
        }

        /* Did the combined update work (did we see what we expected?). */
        if ( likely(prev_scombo == scombo) )
            break;

        if ( retries++ == 4 )
        {
            DPRINTK("Shared grant entry is unstable.\n");
            goto fail;
        }

        /* Didn't see what we expected. Split out the seen flags & dom. */
        /* NB. Endianness! */
        sflags = (u16)prev_scombo;
        sdom   = (u16)(prev_scombo >> 16);
    }

    spin_unlock(&rgt->lock);
    return 1;

 fail:
    spin_unlock(&rgt->lock);
    return 0;
}

static long
gnttab_transfer(
    struct gnttab_transfer *uop, unsigned int count)
{
    struct domain *d = current->domain;
    struct domain *e;
    struct page_info *page;
    int i;
    grant_entry_t *sha;
    struct gnttab_transfer gop;
    unsigned long mfn;

    for ( i = 0; i < count; i++ )
    {
        /* Read from caller address space. */
        if ( unlikely(__copy_from_user(&gop, &uop[i], sizeof(gop))) )
        {
            DPRINTK("gnttab_transfer: error reading req %d/%d\n", i, count);
            return -EFAULT;
        }

        /* Check the passed page frame for basic validity. */
        if ( unlikely(!mfn_valid(gop.mfn)) )
        { 
            DPRINTK("gnttab_transfer: out-of-range %lx\n",
                    (unsigned long)gop.mfn);
            gop.status = GNTST_bad_page;
            goto copyback;
        }

        mfn = gmfn_to_mfn(d, gop.mfn);
        page = mfn_to_page(mfn);
        if ( unlikely(IS_XEN_HEAP_FRAME(page)) )
        { 
            DPRINTK("gnttab_transfer: xen frame %lx\n",
                    (unsigned long)gop.mfn);
            gop.status = GNTST_bad_page;
            goto copyback;
        }

        if ( steal_page_for_grant_transfer(d, page) < 0 )
        {
            gop.status = GNTST_bad_page;
            goto copyback;
        }

        /* Find the target domain. */
        if ( unlikely((e = find_domain_by_id(gop.domid)) == NULL) )
        {
            DPRINTK("gnttab_transfer: can't find domain %d\n", gop.domid);
            page->count_info &= ~(PGC_count_mask|PGC_allocated);
            free_domheap_page(page);
            gop.status = GNTST_bad_domain;
            goto copyback;
        }

        spin_lock(&e->page_alloc_lock);

        /*
         * Check that 'e' will accept the page and has reservation
         * headroom.  Also, a domain mustn't have PGC_allocated
         * pages when it is dying.
         */
        if ( unlikely(test_bit(_DOMF_dying, &e->domain_flags)) ||
             unlikely(e->tot_pages >= e->max_pages) ||
             unlikely(!gnttab_prepare_for_transfer(e, d, gop.ref)) )
        {
            if ( !test_bit(_DOMF_dying, &e->domain_flags) )
                DPRINTK("gnttab_transfer: Transferee has no reservation "
                        "headroom (%d,%d) or provided a bad grant ref (%08x) "
                        "or is dying (%lx)\n",
                        e->tot_pages, e->max_pages, gop.ref, e->domain_flags);
            spin_unlock(&e->page_alloc_lock);
            put_domain(e);
            page->count_info &= ~(PGC_count_mask|PGC_allocated);
            free_domheap_page(page);
            gop.status = GNTST_general_error;
            goto copyback;
        }

        /* Okay, add the page to 'e'. */
        if ( unlikely(e->tot_pages++ == 0) )
            get_knownalive_domain(e);
        list_add_tail(&page->list, &e->page_list);
        page_set_owner(page, e);

        spin_unlock(&e->page_alloc_lock);

        TRACE_1D(TRC_MEM_PAGE_GRANT_TRANSFER, e->domain_id);

        /* Tell the guest about its new page frame. */
        sha = &e->grant_table->shared[gop.ref];
        guest_physmap_add_page(e, sha->frame, mfn);
        sha->frame = mfn;
        wmb();
        sha->flags |= GTF_transfer_completed;

        put_domain(e);

        gop.status = GNTST_okay;

    copyback:
        if ( unlikely(__copy_from_user(&uop[i], &gop, sizeof(gop))) )
        {
            DPRINTK("gnttab_transfer: error writing resp %d/%d\n", i, count);
            return -EFAULT;
        }
    }

    return 0;
}

long 
do_grant_table_op(
    unsigned int cmd, void *uop, unsigned int count)
{
    long rc;
    struct domain *d = current->domain;
    
    if ( count > 512 )
        return -EINVAL;
    
    LOCK_BIGLOCK(d);
    
    sync_pagetable_state(d);
    
    rc = -EFAULT;
    switch ( cmd )
    {
    case GNTTABOP_map_grant_ref:
        if ( unlikely(!array_access_ok(
            uop, count, sizeof(gnttab_map_grant_ref_t))) )
            goto out;
        rc = gnttab_map_grant_ref((gnttab_map_grant_ref_t *)uop, count);
        break;
    case GNTTABOP_unmap_grant_ref:
        if ( unlikely(!array_access_ok(
            uop, count, sizeof(gnttab_unmap_grant_ref_t))) )
            goto out;
        rc = gnttab_unmap_grant_ref(
            (gnttab_unmap_grant_ref_t *)uop, count);
        break;
    case GNTTABOP_setup_table:
        rc = gnttab_setup_table((gnttab_setup_table_t *)uop, count);
        break;
    case GNTTABOP_transfer:
        if (unlikely(!array_access_ok(
            uop, count, sizeof(gnttab_transfer_t))))
            goto out;
        rc = gnttab_transfer(uop, count);
        break;
    default:
        rc = -ENOSYS;
        break;
    }
    
  out:
    UNLOCK_BIGLOCK(d);
    
    return rc;
}

int 
grant_table_create(
    struct domain *d)
{
    grant_table_t *t;
    int            i;

    if ( (t = xmalloc(grant_table_t)) == NULL )
        goto no_mem;

    /* Simple stuff. */
    memset(t, 0, sizeof(*t));
    spin_lock_init(&t->lock);

    /* Active grant table. */
    if ( (t->active = xmalloc_array(active_grant_entry_t, NR_GRANT_ENTRIES))
         == NULL )
        goto no_mem;
    memset(t->active, 0, sizeof(active_grant_entry_t) * NR_GRANT_ENTRIES);

    /* Tracking of mapped foreign frames table */
    if ( (t->maptrack = alloc_xenheap_page()) == NULL )
        goto no_mem;
    t->maptrack_order = 0;
    t->maptrack_limit = PAGE_SIZE / sizeof(grant_mapping_t);
    memset(t->maptrack, 0, PAGE_SIZE);
    for ( i = 0; i < t->maptrack_limit; i++ )
        t->maptrack[i].ref_and_flags = (i+1) << MAPTRACK_REF_SHIFT;

    /* Shared grant table. */
    t->shared = alloc_xenheap_pages(ORDER_GRANT_FRAMES);
    if ( t->shared == NULL )
        goto no_mem;
    memset(t->shared, 0, NR_GRANT_FRAMES * PAGE_SIZE);

    for ( i = 0; i < NR_GRANT_FRAMES; i++ )
        gnttab_create_shared_page(d, t, i);

    /* Okay, install the structure. */
    wmb(); /* avoid races with lock-free access to d->grant_table */
    d->grant_table = t;
    return 0;

 no_mem:
    if ( t != NULL )
    {
        xfree(t->active);
        free_xenheap_page(t->maptrack);
        xfree(t);
    }
    return -ENOMEM;
}

void
gnttab_release_mappings(
    struct domain *d)
{
    grant_table_t        *gt = d->grant_table;
    grant_mapping_t      *map;
    grant_ref_t           ref;
    grant_handle_t        handle;
    struct domain        *rd;
    active_grant_entry_t *act;
    grant_entry_t        *sha;

    BUG_ON(!test_bit(_DOMF_dying, &d->domain_flags));

    for ( handle = 0; handle < gt->maptrack_limit; handle++ )
    {
        map = &gt->maptrack[handle];
        if ( !(map->ref_and_flags & (GNTMAP_device_map|GNTMAP_host_map)) )
            continue;

        ref = map->ref_and_flags >> MAPTRACK_REF_SHIFT;

        DPRINTK("Grant release (%hu) ref:(%hu) flags:(%x) dom:(%hu)\n",
                handle, ref, map->ref_and_flags & MAPTRACK_GNTMAP_MASK,
                map->domid);

        rd = find_domain_by_id(map->domid);
        BUG_ON(rd == NULL);

        spin_lock(&rd->grant_table->lock);

        act = &rd->grant_table->active[ref];
        sha = &rd->grant_table->shared[ref];

        if ( map->ref_and_flags & GNTMAP_readonly )
        {
            if ( map->ref_and_flags & GNTMAP_device_map )
            {
                BUG_ON(!(act->pin & GNTPIN_devr_mask));
                act->pin -= GNTPIN_devr_inc;
                put_page(mfn_to_page(act->frame));
            }

            if ( map->ref_and_flags & GNTMAP_host_map )
            {
                BUG_ON(!(act->pin & GNTPIN_hstr_mask));
                act->pin -= GNTPIN_hstr_inc;
                /* Done implicitly when page tables are destroyed. */
                /* put_page(mfn_to_page(act->frame)); */
            }
        }
        else
        {
            if ( map->ref_and_flags & GNTMAP_device_map )
            {
                BUG_ON(!(act->pin & GNTPIN_devw_mask));
                act->pin -= GNTPIN_devw_inc;
                put_page_and_type(mfn_to_page(act->frame));
            }

            if ( map->ref_and_flags & GNTMAP_host_map )
            {
                BUG_ON(!(act->pin & GNTPIN_hstw_mask));
                act->pin -= GNTPIN_hstw_inc;
                /* Done implicitly when page tables are destroyed. */
                /* put_page_and_type(mfn_to_page(act->frame)); */
            }

            if ( (act->pin & (GNTPIN_devw_mask|GNTPIN_hstw_mask)) == 0 )
                clear_bit(_GTF_writing, &sha->flags);
        }

        if ( act->pin == 0 )
            clear_bit(_GTF_reading, &sha->flags);

        spin_unlock(&rd->grant_table->lock);

        put_domain(rd);

        map->ref_and_flags = 0;
    }
}


void
grant_table_destroy(
    struct domain *d)
{
    grant_table_t *t = d->grant_table;

    if ( t == NULL )
        return;
    
    free_xenheap_pages(t->shared, ORDER_GRANT_FRAMES);
    free_xenheap_page(t->maptrack);
    xfree(t->active);
    xfree(t);

    d->grant_table = NULL;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
