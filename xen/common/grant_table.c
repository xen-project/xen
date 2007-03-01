/******************************************************************************
 * common/grant_table.c
 * 
 * Mechanism for granting foreign access to page frames, and receiving
 * page-ownership transfers.
 * 
 * Copyright (c) 2005-2006 Christopher Clark
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

#include <xen/config.h>
#include <xen/iocap.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/shadow.h>
#include <xen/mm.h>
#include <xen/trace.h>
#include <xen/guest_access.h>
#include <xen/domain_page.h>
#include <acm/acm_hooks.h>

unsigned int max_nr_grant_frames = DEFAULT_MAX_NR_GRANT_FRAMES;
integer_param("gnttab_max_nr_frames", max_nr_grant_frames);

/* The maximum number of grant mappings is defined as a multiplier of the
 * maximum number of grant table entries. This defines the multiplier used.
 * Pretty arbitrary. [POLICY]
 */
#define MAX_MAPTRACK_TO_GRANTS_RATIO 8

/*
 * The first two members of a grant entry are updated as a combined pair.
 * The following union allows that to happen in an endian-neutral fashion.
 */
union grant_combo {
    uint32_t word;
    struct {
        uint16_t flags;
        domid_t  domid;
    } shorts;
};

#define PIN_FAIL(_lbl, _rc, _f, _a...)          \
    do {                                        \
        gdprintk(XENLOG_WARNING, _f, ## _a );   \
        rc = (_rc);                             \
        goto _lbl;                              \
    } while ( 0 )

#define MAPTRACK_PER_PAGE (PAGE_SIZE / sizeof(struct grant_mapping))
#define maptrack_entry(t, e) \
    ((t)->maptrack[(e)/MAPTRACK_PER_PAGE][(e)%MAPTRACK_PER_PAGE])

static inline unsigned int
nr_maptrack_frames(struct grant_table *t)
{
    return t->maptrack_limit / MAPTRACK_PER_PAGE;
}

static unsigned inline int max_nr_maptrack_frames(void)
{
    return (max_nr_grant_frames * MAX_MAPTRACK_TO_GRANTS_RATIO);
}

static inline unsigned int
num_act_frames_from_sha_frames(const unsigned int num)
{
    /* How many frames are needed for the active grant table,
     * given the size of the shared grant table?
     *
     * act_per_page = PAGE_SIZE / sizeof(active_grant_entry_t);
     * sha_per_page = PAGE_SIZE / sizeof(grant_entry_t);
     * num_sha_entries = num * sha_per_page;
     * num_act_frames = (num_sha_entries + (act_per_page-1)) / act_per_page;
     */
    return ((num * (PAGE_SIZE / sizeof(grant_entry_t))) +
            ((PAGE_SIZE / sizeof(struct active_grant_entry))-1))
           / (PAGE_SIZE / sizeof(struct active_grant_entry));
}

static inline unsigned int
nr_active_grant_frames(struct grant_table *gt)
{
    return num_act_frames_from_sha_frames(nr_grant_frames(gt));
}

#define SHGNT_PER_PAGE (PAGE_SIZE / sizeof(grant_entry_t))
#define shared_entry(t, e) \
    ((t)->shared[(e)/SHGNT_PER_PAGE][(e)%SHGNT_PER_PAGE])
#define ACGNT_PER_PAGE (PAGE_SIZE / sizeof(struct active_grant_entry))
#define active_entry(t, e) \
    ((t)->active[(e)/ACGNT_PER_PAGE][(e)%ACGNT_PER_PAGE])

static inline int
__get_maptrack_handle(
    struct grant_table *t)
{
    unsigned int h;
    if ( unlikely((h = t->maptrack_head) == (t->maptrack_limit - 1)) )
        return -1;
    t->maptrack_head = maptrack_entry(t, h).ref;
    t->map_count++;
    return h;
}

static inline void
put_maptrack_handle(
    struct grant_table *t, int handle)
{
    maptrack_entry(t, handle).ref = t->maptrack_head;
    t->maptrack_head = handle;
    t->map_count--;
}

static inline int
get_maptrack_handle(
    struct grant_table *lgt)
{
    int                   i;
    grant_handle_t        handle;
    struct grant_mapping *new_mt;
    unsigned int          new_mt_limit, nr_frames;

    if ( unlikely((handle = __get_maptrack_handle(lgt)) == -1) )
    {
        spin_lock(&lgt->lock);

        if ( unlikely((handle = __get_maptrack_handle(lgt)) == -1) )
        {
            nr_frames = nr_maptrack_frames(lgt);
            if ( nr_frames >= max_nr_maptrack_frames() )
            {
                spin_unlock(&lgt->lock);
                return -1;
            }

            new_mt = alloc_xenheap_page();
            if ( new_mt == NULL )
            {
                spin_unlock(&lgt->lock);
                return -1;
            }

            memset(new_mt, 0, PAGE_SIZE);

            new_mt_limit = lgt->maptrack_limit + MAPTRACK_PER_PAGE;

            for ( i = lgt->maptrack_limit; i < new_mt_limit; i++ )
            {
                new_mt[i % MAPTRACK_PER_PAGE].ref = i+1;
                new_mt[i % MAPTRACK_PER_PAGE].flags = 0;
            }

            lgt->maptrack[nr_frames] = new_mt;
            lgt->maptrack_limit      = new_mt_limit;

            gdprintk(XENLOG_INFO,
                    "Increased maptrack size to %u frames.\n", nr_frames + 1);
            handle = __get_maptrack_handle(lgt);
        }

        spin_unlock(&lgt->lock);
    }
    return handle;
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
    struct active_grant_entry *act;
    struct grant_mapping *mt;
    grant_entry_t *sha;
    union grant_combo scombo, prev_scombo, new_scombo;

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

    if ( unlikely((op->flags & (GNTMAP_device_map|GNTMAP_host_map)) == 0) )
    {
        gdprintk(XENLOG_INFO, "Bad flags in grant map op (%x).\n", op->flags);
        op->status = GNTST_bad_gntref;
        return;
    }

    if ( acm_pre_grant_map_ref(op->dom) )
    {
        op->status = GNTST_permission_denied;
        return;
    }

    if ( unlikely((rd = rcu_lock_domain_by_id(op->dom)) == NULL) )
    {
        gdprintk(XENLOG_INFO, "Could not find domain %d\n", op->dom);
        op->status = GNTST_bad_domain;
        return;
    }

    if ( unlikely((handle = get_maptrack_handle(ld->grant_table)) == -1) )
    {
        rcu_unlock_domain(rd);
        gdprintk(XENLOG_INFO, "Failed to obtain maptrack handle.\n");
        op->status = GNTST_no_device_space;
        return;
    }

    spin_lock(&rd->grant_table->lock);

    /* Bounds check on the grant ref */
    if ( unlikely(op->ref >= nr_grant_entries(rd->grant_table)))
        PIN_FAIL(unlock_out, GNTST_bad_gntref, "Bad ref (%d).\n", op->ref);

    act = &active_entry(rd->grant_table, op->ref);
    sha = &shared_entry(rd->grant_table, op->ref);

    /* If already pinned, check the active domid and avoid refcnt overflow. */
    if ( act->pin &&
         ((act->domid != ld->domain_id) ||
          (act->pin & 0x80808080U) != 0) )
        PIN_FAIL(unlock_out, GNTST_general_error,
                 "Bad domain (%d != %d), or risk of counter overflow %08x\n",
                 act->domid, ld->domain_id, act->pin);

    if ( !act->pin ||
         (!(op->flags & GNTMAP_readonly) &&
          !(act->pin & (GNTPIN_hstw_mask|GNTPIN_devw_mask))) )
    {
        scombo.word = *(u32 *)&sha->flags;

        /*
         * This loop attempts to set the access (reading/writing) flags
         * in the grant table entry.  It tries a cmpxchg on the field
         * up to five times, and then fails under the assumption that 
         * the guest is misbehaving.
         */
        for ( ; ; )
        {
            /* If not already pinned, check the grant domid and type. */
            if ( !act->pin &&
                 (((scombo.shorts.flags & GTF_type_mask) !=
                   GTF_permit_access) ||
                  (scombo.shorts.domid != ld->domain_id)) )
                 PIN_FAIL(unlock_out, GNTST_general_error,
                          "Bad flags (%x) or dom (%d). (expected dom %d)\n",
                          scombo.shorts.flags, scombo.shorts.domid,
                          ld->domain_id);

            new_scombo = scombo;
            new_scombo.shorts.flags |= GTF_reading;

            if ( !(op->flags & GNTMAP_readonly) )
            {
                new_scombo.shorts.flags |= GTF_writing;
                if ( unlikely(scombo.shorts.flags & GTF_readonly) )
                    PIN_FAIL(unlock_out, GNTST_general_error,
                             "Attempt to write-pin a r/o grant entry.\n");
            }

            prev_scombo.word = cmpxchg((u32 *)&sha->flags,
                                       scombo.word, new_scombo.word);
            if ( likely(prev_scombo.word == scombo.word) )
                break;

            if ( retries++ == 4 )
                PIN_FAIL(unlock_out, GNTST_general_error,
                         "Shared grant entry is unstable.\n");

            scombo = prev_scombo;
        }

        if ( !act->pin )
        {
            act->domid = scombo.shorts.domid;
            act->frame = gmfn_to_mfn(rd, sha->frame);
        }
    }

    if ( op->flags & GNTMAP_device_map )
        act->pin += (op->flags & GNTMAP_readonly) ?
            GNTPIN_devr_inc : GNTPIN_devw_inc;
    if ( op->flags & GNTMAP_host_map )
        act->pin += (op->flags & GNTMAP_readonly) ?
            GNTPIN_hstr_inc : GNTPIN_hstw_inc;

    frame = act->frame;

    spin_unlock(&rd->grant_table->lock);

    if ( unlikely(!mfn_valid(frame)) ||
         unlikely(!((op->flags & GNTMAP_readonly) ?
                    get_page(mfn_to_page(frame), rd) :
                    get_page_and_type(mfn_to_page(frame), rd,
                                      PGT_writable_page))) )
    {
        if ( !test_bit(_DOMF_dying, &rd->domain_flags) )
            gdprintk(XENLOG_WARNING, "Could not pin grant frame %lx\n", frame);
        rc = GNTST_general_error;
        goto undo_out;
    }

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

    mt = &maptrack_entry(ld->grant_table, handle);
    mt->domid = op->dom;
    mt->ref   = op->ref;
    mt->flags = op->flags;

    op->dev_bus_addr = (u64)frame << PAGE_SHIFT;
    op->handle       = handle;
    op->status       = GNTST_okay;

    rcu_unlock_domain(rd);
    return;

 undo_out:
    spin_lock(&rd->grant_table->lock);

    act = &active_entry(rd->grant_table, op->ref);
    sha = &shared_entry(rd->grant_table, op->ref);

    if ( op->flags & GNTMAP_device_map )
        act->pin -= (op->flags & GNTMAP_readonly) ?
            GNTPIN_devr_inc : GNTPIN_devw_inc;
    if ( op->flags & GNTMAP_host_map )
        act->pin -= (op->flags & GNTMAP_readonly) ?
            GNTPIN_hstr_inc : GNTPIN_hstw_inc;

    if ( !(op->flags & GNTMAP_readonly) &&
         !(act->pin & (GNTPIN_hstw_mask|GNTPIN_devw_mask)) )
        gnttab_clear_flag(_GTF_writing, &sha->flags);

    if ( !act->pin )
        gnttab_clear_flag(_GTF_reading, &sha->flags);

 unlock_out:
    spin_unlock(&rd->grant_table->lock);
    op->status = rc;
    put_maptrack_handle(ld->grant_table, handle);
    rcu_unlock_domain(rd);
}

static long
gnttab_map_grant_ref(
    XEN_GUEST_HANDLE(gnttab_map_grant_ref_t) uop, unsigned int count)
{
    int i;
    struct gnttab_map_grant_ref op;

    for ( i = 0; i < count; i++ )
    {
        if ( unlikely(__copy_from_guest_offset(&op, uop, i, 1)) )
            return -EFAULT;
        __gnttab_map_grant_ref(&op);
        if ( unlikely(__copy_to_guest_offset(uop, i, &op, 1)) )
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
    struct active_grant_entry *act;
    grant_entry_t   *sha;
    struct grant_mapping *map;
    u16              flags;
    s16              rc = 0;
    unsigned long    frame;

    ld = current->domain;

    frame = (unsigned long)(op->dev_bus_addr >> PAGE_SHIFT);

    if ( unlikely(op->handle >= ld->grant_table->maptrack_limit) )
    {
        gdprintk(XENLOG_INFO, "Bad handle (%d).\n", op->handle);
        op->status = GNTST_bad_handle;
        return;
    }

    map = &maptrack_entry(ld->grant_table, op->handle);

    if ( unlikely(!map->flags) )
    {
        gdprintk(XENLOG_INFO, "Zero flags for handle (%d).\n", op->handle);
        op->status = GNTST_bad_handle;
        return;
    }

    dom   = map->domid;
    ref   = map->ref;
    flags = map->flags;

    if ( unlikely((rd = rcu_lock_domain_by_id(dom)) == NULL) )
    {
        /* This can happen when a grant is implicitly unmapped. */
        gdprintk(XENLOG_INFO, "Could not find domain %d\n", dom);
        domain_crash(ld); /* naughty... */
        return;
    }

    TRACE_1D(TRC_MEM_PAGE_GRANT_UNMAP, dom);

    spin_lock(&rd->grant_table->lock);

    act = &active_entry(rd->grant_table, ref);
    sha = &shared_entry(rd->grant_table, ref);

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
            map->flags &= ~GNTMAP_device_map;
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
        map->flags &= ~GNTMAP_host_map;
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

    if ( (map->flags & (GNTMAP_device_map|GNTMAP_host_map)) == 0 )
    {
        map->flags = 0;
        put_maptrack_handle(ld->grant_table, op->handle);
    }

    /* If just unmapped a writable mapping, mark as dirtied */
    if ( !(flags & GNTMAP_readonly) )
         gnttab_mark_dirty(rd, frame);

    if ( ((act->pin & (GNTPIN_devw_mask|GNTPIN_hstw_mask)) == 0) &&
         !(flags & GNTMAP_readonly) )
        gnttab_clear_flag(_GTF_writing, &sha->flags);

    if ( act->pin == 0 )
        gnttab_clear_flag(_GTF_reading, &sha->flags);

 unmap_out:
    op->status = rc;
    spin_unlock(&rd->grant_table->lock);
    rcu_unlock_domain(rd);
}

static long
gnttab_unmap_grant_ref(
    XEN_GUEST_HANDLE(gnttab_unmap_grant_ref_t) uop, unsigned int count)
{
    int i;
    struct gnttab_unmap_grant_ref op;

    for ( i = 0; i < count; i++ )
    {
        if ( unlikely(__copy_from_guest_offset(&op, uop, i, 1)) )
            goto fault;
        __gnttab_unmap_grant_ref(&op);
        if ( unlikely(__copy_to_guest_offset(uop, i, &op, 1)) )
            goto fault;
    }

    flush_tlb_mask(current->domain->domain_dirty_cpumask);
    return 0;

fault:
    flush_tlb_mask(current->domain->domain_dirty_cpumask);
    return -EFAULT;    
}

int
gnttab_grow_table(struct domain *d, unsigned int req_nr_frames)
{
    /* d's grant table lock must be held by the caller */

    struct grant_table *gt = d->grant_table;
    unsigned int i;

    ASSERT(req_nr_frames <= max_nr_grant_frames);

    gdprintk(XENLOG_INFO,
            "Expanding dom (%d) grant table from (%d) to (%d) frames.\n",
            d->domain_id, nr_grant_frames(gt), req_nr_frames);

    /* Active */
    for ( i = nr_active_grant_frames(gt);
          i < num_act_frames_from_sha_frames(req_nr_frames); i++ )
    {
        if ( (gt->active[i] = alloc_xenheap_page()) == NULL )
            goto active_alloc_failed;
        memset(gt->active[i], 0, PAGE_SIZE);
    }

    /* Shared */
    for ( i = nr_grant_frames(gt); i < req_nr_frames; i++ )
    {
        if ( (gt->shared[i] = alloc_xenheap_page()) == NULL )
            goto shared_alloc_failed;
        memset(gt->shared[i], 0, PAGE_SIZE);
    }

    /* Share the new shared frames with the recipient domain */
    for ( i = nr_grant_frames(gt); i < req_nr_frames; i++ )
        gnttab_create_shared_page(d, gt, i);

    gt->nr_grant_frames = req_nr_frames;

    return 1;

shared_alloc_failed:
    for ( i = nr_grant_frames(gt); i < req_nr_frames; i++ )
    {
        free_xenheap_page(gt->shared[i]);
        gt->shared[i] = NULL;
    }
active_alloc_failed:
    for ( i = nr_active_grant_frames(gt);
          i < num_act_frames_from_sha_frames(req_nr_frames); i++ )
    {
        free_xenheap_page(gt->active[i]);
        gt->active[i] = NULL;
    }
    gdprintk(XENLOG_INFO, "Allocation failure when expanding grant table.\n");
    return 0;
}

static long 
gnttab_setup_table(
    XEN_GUEST_HANDLE(gnttab_setup_table_t) uop, unsigned int count)
{
    struct gnttab_setup_table op;
    struct domain *d;
    int            i;
    unsigned long  gmfn;
    domid_t        dom;

    if ( count != 1 )
        return -EINVAL;

    if ( unlikely(copy_from_guest(&op, uop, 1) != 0) )
    {
        gdprintk(XENLOG_INFO, "Fault while reading gnttab_setup_table_t.\n");
        return -EFAULT;
    }

    if ( unlikely(op.nr_frames > max_nr_grant_frames) )
    {
        gdprintk(XENLOG_INFO, "Xen only supports up to %d grant-table frames"
                " per domain.\n",
                max_nr_grant_frames);
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

    if ( unlikely((d = rcu_lock_domain_by_id(dom)) == NULL) )
    {
        gdprintk(XENLOG_INFO, "Bad domid %d.\n", dom);
        op.status = GNTST_bad_domain;
        goto out;
    }

    spin_lock(&d->grant_table->lock);

    if ( (op.nr_frames > nr_grant_frames(d->grant_table)) &&
         !gnttab_grow_table(d, op.nr_frames) )
    {
        gdprintk(XENLOG_INFO,
                "Expand grant table to %d failed. Current: %d Max: %d.\n",
                op.nr_frames,
                nr_grant_frames(d->grant_table),
                max_nr_grant_frames);
        op.status = GNTST_general_error;
        goto setup_unlock_out;
    }
 
    op.status = GNTST_okay;
    for ( i = 0; i < op.nr_frames; i++ )
    {
        gmfn = gnttab_shared_gmfn(d, d->grant_table, i);
        (void)copy_to_guest_offset(op.frame_list, i, &gmfn, 1);
    }

 setup_unlock_out:
    spin_unlock(&d->grant_table->lock);

    rcu_unlock_domain(d);

 out:
    if ( unlikely(copy_to_guest(uop, &op, 1)) )
        return -EFAULT;

    return 0;
}

static long 
gnttab_query_size(
    XEN_GUEST_HANDLE(gnttab_query_size_t) uop, unsigned int count)
{
    struct gnttab_query_size op;
    struct domain *d;
    domid_t        dom;

    if ( count != 1 )
        return -EINVAL;

    if ( unlikely(copy_from_guest(&op, uop, 1) != 0) )
    {
        gdprintk(XENLOG_INFO, "Fault while reading gnttab_query_size_t.\n");
        return -EFAULT;
    }

    dom = op.dom;
    if ( dom == DOMID_SELF )
    {
        dom = current->domain->domain_id;
    }
    else if ( unlikely(!IS_PRIV(current->domain)) )
    {
        op.status = GNTST_permission_denied;
        goto query_out;
    }

    if ( unlikely((d = rcu_lock_domain_by_id(dom)) == NULL) )
    {
        gdprintk(XENLOG_INFO, "Bad domid %d.\n", dom);
        op.status = GNTST_bad_domain;
        goto query_out;
    }

    spin_lock(&d->grant_table->lock);

    op.nr_frames     = nr_grant_frames(d->grant_table);
    op.max_nr_frames = max_nr_grant_frames;
    op.status        = GNTST_okay;

    spin_unlock(&d->grant_table->lock);

    rcu_unlock_domain(d);

 query_out:
    if ( unlikely(copy_to_guest(uop, &op, 1)) )
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
    struct grant_table *rgt;
    struct grant_entry *sha;
    union grant_combo   scombo, prev_scombo, new_scombo;
    int                 retries = 0;

    if ( unlikely((rgt = rd->grant_table) == NULL) )
    {
        gdprintk(XENLOG_INFO, "Dom %d has no grant table.\n", rd->domain_id);
        return 0;
    }

    spin_lock(&rgt->lock);

    if ( unlikely(ref >= nr_grant_entries(rd->grant_table)) )
    {
        gdprintk(XENLOG_INFO,
                "Bad grant reference (%d) for transfer to domain(%d).\n",
                ref, rd->domain_id);
        goto fail;
    }

    sha = &shared_entry(rgt, ref);
    
    scombo.word = *(u32 *)&sha->flags;

    for ( ; ; )
    {
        if ( unlikely(scombo.shorts.flags != GTF_accept_transfer) ||
             unlikely(scombo.shorts.domid != ld->domain_id) )
        {
            gdprintk(XENLOG_INFO, "Bad flags (%x) or dom (%d). "
                    "(NB. expected dom %d)\n",
                    scombo.shorts.flags, scombo.shorts.domid,
                    ld->domain_id);
            goto fail;
        }

        new_scombo = scombo;
        new_scombo.shorts.flags |= GTF_transfer_committed;

        prev_scombo.word = cmpxchg((u32 *)&sha->flags,
                                   scombo.word, new_scombo.word);
        if ( likely(prev_scombo.word == scombo.word) )
            break;

        if ( retries++ == 4 )
        {
            gdprintk(XENLOG_WARNING, "Shared grant entry is unstable.\n");
            goto fail;
        }

        scombo = prev_scombo;
    }

    spin_unlock(&rgt->lock);
    return 1;

 fail:
    spin_unlock(&rgt->lock);
    return 0;
}

static long
gnttab_transfer(
    XEN_GUEST_HANDLE(gnttab_transfer_t) uop, unsigned int count)
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
        if ( unlikely(__copy_from_guest_offset(&gop, uop, i, 1)) )
        {
            gdprintk(XENLOG_INFO, "gnttab_transfer: error reading req %d/%d\n",
                    i, count);
            return -EFAULT;
        }

        mfn = gmfn_to_mfn(d, gop.mfn);

        /* Check the passed page frame for basic validity. */
        if ( unlikely(!mfn_valid(mfn)) )
        { 
            gdprintk(XENLOG_INFO, "gnttab_transfer: out-of-range %lx\n",
                    (unsigned long)gop.mfn);
            gop.status = GNTST_bad_page;
            goto copyback;
        }

        page = mfn_to_page(mfn);
        if ( unlikely(IS_XEN_HEAP_FRAME(page)) )
        { 
            gdprintk(XENLOG_INFO, "gnttab_transfer: xen frame %lx\n",
                    (unsigned long)gop.mfn);
            gop.status = GNTST_bad_page;
            goto copyback;
        }

        if ( steal_page(d, page, 0) < 0 )
        {
            gop.status = GNTST_bad_page;
            goto copyback;
        }

        /* Find the target domain. */
        if ( unlikely((e = rcu_lock_domain_by_id(gop.domid)) == NULL) )
        {
            gdprintk(XENLOG_INFO, "gnttab_transfer: can't find domain %d\n",
                    gop.domid);
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
                gdprintk(XENLOG_INFO, "gnttab_transfer: "
                        "Transferee has no reservation "
                        "headroom (%d,%d) or provided a bad grant ref (%08x) "
                        "or is dying (%lx)\n",
                        e->tot_pages, e->max_pages, gop.ref, e->domain_flags);
            spin_unlock(&e->page_alloc_lock);
            rcu_unlock_domain(e);
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
        spin_lock(&e->grant_table->lock);

        sha = &shared_entry(e->grant_table, gop.ref);
        guest_physmap_add_page(e, sha->frame, mfn);
        sha->frame = mfn;
        wmb();
        sha->flags |= GTF_transfer_completed;

        spin_unlock(&e->grant_table->lock);

        rcu_unlock_domain(e);

        gop.status = GNTST_okay;

    copyback:
        if ( unlikely(__copy_to_guest_offset(uop, i, &gop, 1)) )
        {
            gdprintk(XENLOG_INFO, "gnttab_transfer: error writing resp "
                     "%d/%d\n", i, count);
            return -EFAULT;
        }
    }

    return 0;
}

/* Undo __acquire_grant_for_copy.  Again, this has no effect on page
   type and reference counts. */
static void
__release_grant_for_copy(
    struct domain *rd, unsigned long gref, int readonly)
{
    grant_entry_t *sha;
    struct active_grant_entry *act;
    unsigned long r_frame;

    spin_lock(&rd->grant_table->lock);

    act = &active_entry(rd->grant_table, gref);
    sha = &shared_entry(rd->grant_table, gref);
    r_frame = act->frame;

    if ( readonly )
    {
        act->pin -= GNTPIN_hstr_inc;
    }
    else
    {
        gnttab_mark_dirty(rd, r_frame);

        act->pin -= GNTPIN_hstw_inc;
        if ( !(act->pin & (GNTPIN_devw_mask|GNTPIN_hstw_mask)) )
            gnttab_clear_flag(_GTF_writing, &sha->flags);
    }

    if ( !act->pin )
        gnttab_clear_flag(_GTF_reading, &sha->flags);

    spin_unlock(&rd->grant_table->lock);
}

/* Grab a frame number from a grant entry and update the flags and pin
   count as appropriate.  Note that this does *not* update the page
   type or reference counts, and does not check that the mfn is
   actually valid. */
static int
__acquire_grant_for_copy(
    struct domain *rd, unsigned long gref, int readonly,
    unsigned long *frame)
{
    grant_entry_t *sha;
    struct active_grant_entry *act;
    s16 rc = GNTST_okay;
    int retries = 0;
    union grant_combo scombo, prev_scombo, new_scombo;

    spin_lock(&rd->grant_table->lock);

    if ( unlikely(gref >= nr_grant_entries(rd->grant_table)) )
        PIN_FAIL(unlock_out, GNTST_bad_gntref,
                 "Bad grant reference %ld\n", gref);

    act = &active_entry(rd->grant_table, gref);
    sha = &shared_entry(rd->grant_table, gref);
    
    /* If already pinned, check the active domid and avoid refcnt overflow. */
    if ( act->pin &&
         ((act->domid != current->domain->domain_id) ||
          (act->pin & 0x80808080U) != 0) )
        PIN_FAIL(unlock_out, GNTST_general_error,
                 "Bad domain (%d != %d), or risk of counter overflow %08x\n",
                 act->domid, current->domain->domain_id, act->pin);

    if ( !act->pin ||
         (!readonly && !(act->pin & (GNTPIN_devw_mask|GNTPIN_hstw_mask))) )
    {
        scombo.word = *(u32 *)&sha->flags;

        for ( ; ; )
        {
            /* If not already pinned, check the grant domid and type. */
            if ( !act->pin &&
                 (((scombo.shorts.flags & GTF_type_mask) !=
                   GTF_permit_access) ||
                  (scombo.shorts.domid != current->domain->domain_id)) )
                 PIN_FAIL(unlock_out, GNTST_general_error,
                          "Bad flags (%x) or dom (%d). (expected dom %d)\n",
                          scombo.shorts.flags, scombo.shorts.domid,
                          current->domain->domain_id);

            new_scombo = scombo;
            new_scombo.shorts.flags |= GTF_reading;

            if ( !readonly )
            {
                new_scombo.shorts.flags |= GTF_writing;
                if ( unlikely(scombo.shorts.flags & GTF_readonly) )
                    PIN_FAIL(unlock_out, GNTST_general_error,
                             "Attempt to write-pin a r/o grant entry.\n");
            }

            prev_scombo.word = cmpxchg((u32 *)&sha->flags,
                                       scombo.word, new_scombo.word);
            if ( likely(prev_scombo.word == scombo.word) )
                break;

            if ( retries++ == 4 )
                PIN_FAIL(unlock_out, GNTST_general_error,
                         "Shared grant entry is unstable.\n");

            scombo = prev_scombo;
        }

        if ( !act->pin )
        {
            act->domid = scombo.shorts.domid;
            act->frame = gmfn_to_mfn(rd, sha->frame);
        }
    }

    act->pin += readonly ? GNTPIN_hstr_inc : GNTPIN_hstw_inc;

    *frame = act->frame;

 unlock_out:
    spin_unlock(&rd->grant_table->lock);
    return rc;
}

static void
__gnttab_copy(
    struct gnttab_copy *op)
{
    struct domain *sd = NULL, *dd = NULL;
    unsigned long s_frame, d_frame;
    char *sp, *dp;
    s16 rc = GNTST_okay;
    int have_d_grant = 0, have_s_grant = 0, have_s_ref = 0;
    int src_is_gref, dest_is_gref;

    if ( ((op->source.offset + op->len) > PAGE_SIZE) ||
         ((op->dest.offset + op->len) > PAGE_SIZE) )
        PIN_FAIL(error_out, GNTST_bad_copy_arg, "copy beyond page area.\n");

    src_is_gref = op->flags & GNTCOPY_source_gref;
    dest_is_gref = op->flags & GNTCOPY_dest_gref;

    if ( (op->source.domid != DOMID_SELF && !src_is_gref ) ||
         (op->dest.domid   != DOMID_SELF && !dest_is_gref)   )
        PIN_FAIL(error_out, GNTST_permission_denied,
                 "only allow copy-by-mfn for DOMID_SELF.\n");

    if ( op->source.domid == DOMID_SELF )
    {
        sd = current->domain;
        get_knownalive_domain(sd);
    }
    else if ( (sd = rcu_lock_domain_by_id(op->source.domid)) == NULL )
    {
        PIN_FAIL(error_out, GNTST_bad_domain,
                 "couldn't find %d\n", op->source.domid);
    }

    if ( op->dest.domid == DOMID_SELF )
    {
        dd = current->domain;
        get_knownalive_domain(dd);
    }
    else if ( (dd = rcu_lock_domain_by_id(op->dest.domid)) == NULL )
    {
        PIN_FAIL(error_out, GNTST_bad_domain,
                 "couldn't find %d\n", op->dest.domid);
    }

    if ( src_is_gref )
    {
        rc = __acquire_grant_for_copy(sd, op->source.u.ref, 1, &s_frame);
        if ( rc != GNTST_okay )
            goto error_out;
        have_s_grant = 1;
    }
    else
    {
        s_frame = gmfn_to_mfn(sd, op->source.u.gmfn);
    }
    if ( unlikely(!mfn_valid(s_frame)) )
        PIN_FAIL(error_out, GNTST_general_error,
                 "source frame %lx invalid.\n", s_frame);
    if ( !get_page(mfn_to_page(s_frame), sd) )
    {
        if ( !test_bit(_DOMF_dying, &sd->domain_flags) )
            gdprintk(XENLOG_WARNING, "Could not get src frame %lx\n", s_frame);
        rc = GNTST_general_error;
        goto error_out;
    }
    have_s_ref = 1;

    if ( dest_is_gref )
    {
        rc = __acquire_grant_for_copy(dd, op->dest.u.ref, 0, &d_frame);
        if ( rc != GNTST_okay )
            goto error_out;
        have_d_grant = 1;
    }
    else
    {
        d_frame = gmfn_to_mfn(dd, op->dest.u.gmfn);
    }
    if ( unlikely(!mfn_valid(d_frame)) )
        PIN_FAIL(error_out, GNTST_general_error,
                 "destination frame %lx invalid.\n", d_frame);
    if ( !get_page_and_type(mfn_to_page(d_frame), dd, PGT_writable_page) )
    {
        if ( !test_bit(_DOMF_dying, &dd->domain_flags) )
            gdprintk(XENLOG_WARNING, "Could not get dst frame %lx\n", d_frame);
        rc = GNTST_general_error;
        goto error_out;
    }

    sp = map_domain_page(s_frame);
    dp = map_domain_page(d_frame);

    memcpy(dp + op->dest.offset, sp + op->source.offset, op->len);

    unmap_domain_page(dp);
    unmap_domain_page(sp);

    gnttab_mark_dirty(dd, d_frame);

    put_page_and_type(mfn_to_page(d_frame));
 error_out:
    if ( have_s_ref )
        put_page(mfn_to_page(s_frame));
    if ( have_s_grant )
        __release_grant_for_copy(sd, op->source.u.ref, 1);
    if ( have_d_grant )
        __release_grant_for_copy(dd, op->dest.u.ref, 0);
    if ( sd )
        rcu_unlock_domain(sd);
    if ( dd )
        rcu_unlock_domain(dd);
    op->status = rc;
}

static long
gnttab_copy(
    XEN_GUEST_HANDLE(gnttab_copy_t) uop, unsigned int count)
{
    int i;
    struct gnttab_copy op;

    for ( i = 0; i < count; i++ )
    {
        if ( unlikely(__copy_from_guest_offset(&op, uop, i, 1)) )
            return -EFAULT;
        __gnttab_copy(&op);
        if ( unlikely(__copy_to_guest_offset(uop, i, &op, 1)) )
            return -EFAULT;
    }
    return 0;
}

long
do_grant_table_op(
    unsigned int cmd, XEN_GUEST_HANDLE(void) uop, unsigned int count)
{
    long rc;
    struct domain *d = current->domain;
    
    if ( count > 512 )
        return -EINVAL;
    
    LOCK_BIGLOCK(d);
    
    rc = -EFAULT;
    switch ( cmd )
    {
    case GNTTABOP_map_grant_ref:
    {
        XEN_GUEST_HANDLE(gnttab_map_grant_ref_t) map =
            guest_handle_cast(uop, gnttab_map_grant_ref_t);
        if ( unlikely(!guest_handle_okay(map, count)) )
            goto out;
        rc = -EPERM;
        if ( unlikely(!grant_operation_permitted(d)) )
            goto out;
        rc = gnttab_map_grant_ref(map, count);
        break;
    }
    case GNTTABOP_unmap_grant_ref:
    {
        XEN_GUEST_HANDLE(gnttab_unmap_grant_ref_t) unmap =
            guest_handle_cast(uop, gnttab_unmap_grant_ref_t);
        if ( unlikely(!guest_handle_okay(unmap, count)) )
            goto out;
        rc = -EPERM;
        if ( unlikely(!grant_operation_permitted(d)) )
            goto out;
        rc = gnttab_unmap_grant_ref(unmap, count);
        break;
    }
    case GNTTABOP_setup_table:
    {
        rc = gnttab_setup_table(
            guest_handle_cast(uop, gnttab_setup_table_t), count);
        break;
    }
    case GNTTABOP_transfer:
    {
        XEN_GUEST_HANDLE(gnttab_transfer_t) transfer =
            guest_handle_cast(uop, gnttab_transfer_t);
        if ( unlikely(!guest_handle_okay(transfer, count)) )
            goto out;
        rc = -EPERM;
        if ( unlikely(!grant_operation_permitted(d)) )
            goto out;
        rc = gnttab_transfer(transfer, count);
        break;
    }
    case GNTTABOP_copy:
    {
        XEN_GUEST_HANDLE(gnttab_copy_t) copy =
            guest_handle_cast(uop, gnttab_copy_t);
        if ( unlikely(!guest_handle_okay(copy, count)) )
            goto out;
        rc = gnttab_copy(copy, count);
        break;
    }
    case GNTTABOP_query_size:
    {
        rc = gnttab_query_size(
            guest_handle_cast(uop, gnttab_query_size_t), count);
        break;
    }
    default:
        rc = -ENOSYS;
        break;
    }
    
  out:
    UNLOCK_BIGLOCK(d);
    
    return rc;
}

#ifdef CONFIG_COMPAT
#include "compat/grant_table.c"
#endif

static unsigned int max_nr_active_grant_frames(void)
{
    return (((max_nr_grant_frames * (PAGE_SIZE / sizeof(grant_entry_t))) + 
                    ((PAGE_SIZE / sizeof(struct active_grant_entry))-1)) 
                   / (PAGE_SIZE / sizeof(struct active_grant_entry)));
}

int 
grant_table_create(
    struct domain *d)
{
    struct grant_table *t;
    int                 i;

    /* If this sizeof assertion fails, fix the function: shared_index */
    ASSERT(sizeof(grant_entry_t) == 8);

    if ( (t = xmalloc(struct grant_table)) == NULL )
        goto no_mem_0;

    /* Simple stuff. */
    memset(t, 0, sizeof(*t));
    spin_lock_init(&t->lock);
    t->nr_grant_frames = INITIAL_NR_GRANT_FRAMES;

    /* Active grant table. */
    if ( (t->active = xmalloc_array(struct active_grant_entry *,
                                    max_nr_active_grant_frames())) == NULL )
        goto no_mem_1;
    memset(t->active, 0, max_nr_active_grant_frames() * sizeof(t->active[0]));
    for ( i = 0;
          i < num_act_frames_from_sha_frames(INITIAL_NR_GRANT_FRAMES); i++ )
    {
        if ( (t->active[i] = alloc_xenheap_page()) == NULL )
            goto no_mem_2;
        memset(t->active[i], 0, PAGE_SIZE);
    }

    /* Tracking of mapped foreign frames table */
    if ( (t->maptrack = xmalloc_array(struct grant_mapping *,
                                      max_nr_maptrack_frames())) == NULL )
        goto no_mem_2;
    memset(t->maptrack, 0, max_nr_maptrack_frames() * sizeof(t->maptrack[0]));
    if ( (t->maptrack[0] = alloc_xenheap_page()) == NULL )
        goto no_mem_3;
    memset(t->maptrack[0], 0, PAGE_SIZE);
    t->maptrack_limit = PAGE_SIZE / sizeof(struct grant_mapping);
    for ( i = 0; i < t->maptrack_limit; i++ )
        t->maptrack[0][i].ref = i+1;

    /* Shared grant table. */
    if ( (t->shared = xmalloc_array(struct grant_entry *,
                                    max_nr_grant_frames)) == NULL )
        goto no_mem_3;
    memset(t->shared, 0, max_nr_grant_frames * sizeof(t->shared[0]));
    for ( i = 0; i < INITIAL_NR_GRANT_FRAMES; i++ )
    {
        if ( (t->shared[i] = alloc_xenheap_page()) == NULL )
            goto no_mem_4;
        memset(t->shared[i], 0, PAGE_SIZE);
    }

    for ( i = 0; i < INITIAL_NR_GRANT_FRAMES; i++ )
        gnttab_create_shared_page(d, t, i);

    /* Okay, install the structure. */
    d->grant_table = t;
    return 0;

 no_mem_4:
    for ( i = 0; i < INITIAL_NR_GRANT_FRAMES; i++ )
        free_xenheap_page(t->shared[i]);
    xfree(t->shared);
 no_mem_3:
    free_xenheap_page(t->maptrack[0]);
    xfree(t->maptrack);
 no_mem_2:
    for ( i = 0;
          i < num_act_frames_from_sha_frames(INITIAL_NR_GRANT_FRAMES); i++ )
        free_xenheap_page(t->active[i]);
    xfree(t->active);
 no_mem_1:
    xfree(t);
 no_mem_0:
    return -ENOMEM;
}

void
gnttab_release_mappings(
    struct domain *d)
{
    struct grant_table   *gt = d->grant_table;
    struct grant_mapping *map;
    grant_ref_t           ref;
    grant_handle_t        handle;
    struct domain        *rd;
    struct active_grant_entry *act;
    struct grant_entry   *sha;

    BUG_ON(!test_bit(_DOMF_dying, &d->domain_flags));

    for ( handle = 0; handle < gt->maptrack_limit; handle++ )
    {
        map = &maptrack_entry(gt, handle);
        if ( !(map->flags & (GNTMAP_device_map|GNTMAP_host_map)) )
            continue;

        ref = map->ref;

        gdprintk(XENLOG_INFO, "Grant release (%hu) ref:(%hu) "
                "flags:(%x) dom:(%hu)\n",
                handle, ref, map->flags, map->domid);

        rd = rcu_lock_domain_by_id(map->domid);
        if ( rd == NULL )
        {
            /* Nothing to clear up... */
            map->flags = 0;
            continue;
        }

        spin_lock(&rd->grant_table->lock);

        act = &active_entry(rd->grant_table, ref);
        sha = &shared_entry(rd->grant_table, ref);

        if ( map->flags & GNTMAP_readonly )
        {
            if ( map->flags & GNTMAP_device_map )
            {
                BUG_ON(!(act->pin & GNTPIN_devr_mask));
                act->pin -= GNTPIN_devr_inc;
                put_page(mfn_to_page(act->frame));
            }

            if ( map->flags & GNTMAP_host_map )
            {
                BUG_ON(!(act->pin & GNTPIN_hstr_mask));
                act->pin -= GNTPIN_hstr_inc;
                /* Done implicitly when page tables are destroyed. */
                /* put_page(mfn_to_page(act->frame)); */
            }
        }
        else
        {
            if ( map->flags & GNTMAP_device_map )
            {
                BUG_ON(!(act->pin & GNTPIN_devw_mask));
                act->pin -= GNTPIN_devw_inc;
                put_page_and_type(mfn_to_page(act->frame));
            }

            if ( map->flags & GNTMAP_host_map )
            {
                BUG_ON(!(act->pin & GNTPIN_hstw_mask));
                act->pin -= GNTPIN_hstw_inc;
                /* Done implicitly when page tables are destroyed. */
                /* put_page_and_type(mfn_to_page(act->frame)); */
            }

            if ( (act->pin & (GNTPIN_devw_mask|GNTPIN_hstw_mask)) == 0 )
                gnttab_clear_flag(_GTF_writing, &sha->flags);
        }

        if ( act->pin == 0 )
            gnttab_clear_flag(_GTF_reading, &sha->flags);

        spin_unlock(&rd->grant_table->lock);

        rcu_unlock_domain(rd);

        map->flags = 0;
    }
}


void
grant_table_destroy(
    struct domain *d)
{
    struct grant_table *t = d->grant_table;
    int i;

    if ( t == NULL )
        return;
    
    for ( i = 0; i < nr_grant_frames(t); i++ )
        free_xenheap_page(t->shared[i]);
    xfree(t->shared);

    for ( i = 0; i < nr_maptrack_frames(t); i++ )
        free_xenheap_page(t->maptrack[i]);
    xfree(t->maptrack);

    for ( i = 0; i < nr_active_grant_frames(t); i++ )
        free_xenheap_page(t->active[i]);
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
