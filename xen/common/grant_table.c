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
#include <xen/mm.h>
#include <xen/event.h>
#include <xen/trace.h>
#include <xen/guest_access.h>
#include <xen/domain_page.h>
#include <xen/iommu.h>
#include <xen/paging.h>
#include <xen/keyhandler.h>
#include <xsm/xsm.h>

#ifndef max_nr_grant_frames
unsigned int max_nr_grant_frames = DEFAULT_MAX_NR_GRANT_FRAMES;
integer_param("gnttab_max_nr_frames", max_nr_grant_frames);
#endif

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

/* Used to share code between unmap_grant_ref and unmap_and_replace. */
struct gnttab_unmap_common {
    /* Input */
    uint64_t host_addr;
    uint64_t dev_bus_addr;
    uint64_t new_addr;
    grant_handle_t handle;

    /* Return */
    int16_t status;

    /* Shared state beteen *_unmap and *_unmap_complete */
    u16 flags;
    unsigned long frame;
    struct grant_mapping *map;
    struct domain *rd;
};

/* Number of unmap operations that are done between each tlb flush */
#define GNTTAB_UNMAP_BATCH_SIZE 32


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

#ifdef CONFIG_X86
#define gfn_to_mfn_private(_d, _gfn) ({                     \
    p2m_type_t __p2mt;                                      \
    unsigned long __x;                                      \
    __x = mfn_x(gfn_to_mfn_unshare(p2m_get_hostp2m(_d), _gfn, &__p2mt, 1));  \
    if ( !p2m_is_valid(__p2mt) )                            \
        __x = INVALID_MFN;                                  \
    __x; })
#else
#define gfn_to_mfn_private(_d, _gfn) gmfn_to_mfn(_d, _gfn)
#endif

#define SHGNT_PER_PAGE_V1 (PAGE_SIZE / sizeof(grant_entry_v1_t))
#define shared_entry_v1(t, e) \
    ((t)->shared_v1[(e)/SHGNT_PER_PAGE_V1][(e)%SHGNT_PER_PAGE_V1])
#define SHGNT_PER_PAGE_V2 (PAGE_SIZE / sizeof(grant_entry_v2_t))
#define shared_entry_v2(t, e) \
    ((t)->shared_v2[(e)/SHGNT_PER_PAGE_V2][(e)%SHGNT_PER_PAGE_V2])
#define STGNT_PER_PAGE (PAGE_SIZE / sizeof(grant_status_t))
#define status_entry(t, e) \
    ((t)->status[(e)/STGNT_PER_PAGE][(e)%STGNT_PER_PAGE])
static grant_entry_header_t *
shared_entry_header(struct grant_table *t, grant_ref_t ref)
{
    ASSERT(t->gt_version != 0);
    if (t->gt_version == 1)
        return (grant_entry_header_t*)&shared_entry_v1(t, ref);
    else
        return &shared_entry_v2(t, ref).hdr;
}
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
    return h;
}

static inline void
put_maptrack_handle(
    struct grant_table *t, int handle)
{
    maptrack_entry(t, handle).ref = t->maptrack_head;
    t->maptrack_head = handle;
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

            clear_page(new_mt);

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

/* Number of grant table entries. Caller must hold d's grant table lock. */
static unsigned int nr_grant_entries(struct grant_table *gt)
{
    ASSERT(gt->gt_version != 0);
    if (gt->gt_version == 1)
        return (nr_grant_frames(gt) << PAGE_SHIFT) / sizeof(grant_entry_v1_t);
    else
        return (nr_grant_frames(gt) << PAGE_SHIFT) / sizeof(grant_entry_v2_t);
}

static int _set_status_v1(domid_t  domid,
                          int readonly,
                          int mapflag,
                          grant_entry_header_t *shah, 
                          struct active_grant_entry *act)
{
    int rc = GNTST_okay;
    union grant_combo scombo, prev_scombo, new_scombo;
    uint16_t mask = GTF_type_mask;

    /*
     * We bound the number of times we retry CMPXCHG on memory locations that
     * we share with a guest OS. The reason is that the guest can modify that
     * location at a higher rate than we can read-modify-CMPXCHG, so the guest
     * could cause us to livelock. There are a few cases where it is valid for
     * the guest to race our updates (e.g., to change the GTF_readonly flag),
     * so we allow a few retries before failing.
     */
    int retries = 0;

    /* if this is a grant mapping operation we should ensure GTF_sub_page
       is not set */
    if (mapflag)
        mask |= GTF_sub_page;

    scombo.word = *(u32 *)shah;

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
             (((scombo.shorts.flags & mask) !=
               GTF_permit_access) ||
              (scombo.shorts.domid != domid)) )
            PIN_FAIL(done, GNTST_general_error,
                     "Bad flags (%x) or dom (%d). (expected dom %d)\n",
                     scombo.shorts.flags, scombo.shorts.domid,
                     domid);

        new_scombo = scombo;
        new_scombo.shorts.flags |= GTF_reading;

        if ( !readonly )
        {
            new_scombo.shorts.flags |= GTF_writing;
            if ( unlikely(scombo.shorts.flags & GTF_readonly) )
                PIN_FAIL(done, GNTST_general_error,
                         "Attempt to write-pin a r/o grant entry.\n");
        }

        prev_scombo.word = cmpxchg((u32 *)shah,
                                   scombo.word, new_scombo.word);
        if ( likely(prev_scombo.word == scombo.word) )
            break;

        if ( retries++ == 4 )
            PIN_FAIL(done, GNTST_general_error,
                     "Shared grant entry is unstable.\n");

        scombo = prev_scombo;
    }

done:
    return rc;
}

static int _set_status_v2(domid_t  domid,
                          int readonly,
                          int mapflag,
                          grant_entry_header_t *shah, 
                          struct active_grant_entry *act,
                          grant_status_t *status)
{
    int      rc    = GNTST_okay;
    union grant_combo scombo;
    uint16_t flags = shah->flags;
    domid_t  id    = shah->domid;
    uint16_t mask  = GTF_type_mask;

    /* we read flags and domid in a single memory access.
       this avoids the need for another memory barrier to
       ensure access to these fields are not reordered */
    scombo.word = *(u32 *)shah;
    barrier(); /* but we still need to stop the compiler from turning
                  it back into two reads */
    flags = scombo.shorts.flags;
    id = scombo.shorts.domid;

    /* if this is a grant mapping operation we should ensure GTF_sub_page
       is not set */
    if (mapflag)
        mask |= GTF_sub_page;

    /* If not already pinned, check the grant domid and type. */
    if ( !act->pin &&
         ( (((flags & mask) != GTF_permit_access) &&
            ((flags & mask) != GTF_transitive)) ||
          (id != domid)) )
        PIN_FAIL(done, GNTST_general_error,
                 "Bad flags (%x) or dom (%d). (expected dom %d, flags %x)\n",
                 flags, id, domid, mask);

    if ( readonly )
    {
        *status |= GTF_reading;
    }
    else
    {
        if ( unlikely(flags & GTF_readonly) )
            PIN_FAIL(done, GNTST_general_error,
                     "Attempt to write-pin a r/o grant entry.\n");
        *status |= GTF_reading | GTF_writing;
    }

    /* Make sure guest sees status update before checking if flags are
       still valid */
    mb();

    scombo.word = *(u32 *)shah;
    barrier();
    flags = scombo.shorts.flags;
    id = scombo.shorts.domid;

    if ( !act->pin )
    {
        if ( (((flags & mask) != GTF_permit_access) &&
              ((flags & mask) != GTF_transitive)) ||
             (id != domid) ||
             (!readonly && (flags & GTF_readonly)) )
        {
            gnttab_clear_flag(_GTF_reading | _GTF_writing, status);
            PIN_FAIL(done, GNTST_general_error,
                     "Unstable flags (%x) or dom (%d). (expected dom %d) "
                     "(r/w: %d)\n",
                     flags, id, domid, !readonly);
        }
    }
    else
    {
        if ( unlikely(flags & GTF_readonly) )
        {
            gnttab_clear_flag(_GTF_writing, status);
            PIN_FAIL(done, GNTST_general_error,
                     "Unstable grant readonly flag\n");
        }
    }

done:
    return rc;
}


static int _set_status(unsigned gt_version,
                       domid_t  domid,
                       int readonly,
                       int mapflag,
                       grant_entry_header_t *shah,
                       struct active_grant_entry *act,
                       grant_status_t *status)
{

    if (gt_version == 1)
        return _set_status_v1(domid, readonly, mapflag, shah, act);
    else
        return _set_status_v2(domid, readonly, mapflag, shah, act, status);
}

static void mapcount(
    struct domain *ld, unsigned long mfn,
    unsigned int *wrc, unsigned int *rdc)
{
    struct grant_table *gt = ld->grant_table;
    struct grant_mapping *map;
    grant_handle_t handle;
    struct domain *rd;

    *wrc = *rdc = 0;

    for ( handle = 0; handle < gt->maptrack_limit; handle++ )
    {
        map = &maptrack_entry(gt, handle);
        if ( !(map->flags & (GNTMAP_device_map|GNTMAP_host_map)) )
            continue;
        rd = rcu_lock_domain_by_id(map->domid);
        if ( active_entry(rd->grant_table, map->ref).frame == mfn )
            (map->flags & GNTMAP_readonly) ? (*rdc)++ : (*wrc)++;
        rcu_unlock_domain(rd);
    }
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
    struct domain *ld, *rd, *owner;
    struct vcpu   *led;
    int            handle;
    unsigned long  frame = 0, nr_gets = 0;
    struct page_info *pg;
    int            rc = GNTST_okay;
    u32            old_pin;
    u32            act_pin;
    unsigned int   cache_flags;
    struct active_grant_entry *act;
    struct grant_mapping *mt;
    grant_entry_v1_t *sha1;
    grant_entry_v2_t *sha2;
    grant_entry_header_t *shah;
    uint16_t *status;

    led = current;
    ld = led->domain;

    if ( unlikely((op->flags & (GNTMAP_device_map|GNTMAP_host_map)) == 0) )
    {
        gdprintk(XENLOG_INFO, "Bad flags in grant map op (%x).\n", op->flags);
        op->status = GNTST_bad_gntref;
        return;
    }

    if ( unlikely(paging_mode_external(ld) &&
                  (op->flags & (GNTMAP_device_map|GNTMAP_application_map|
                            GNTMAP_contains_pte))) )
    {
        gdprintk(XENLOG_INFO, "No device mapping in HVM domain.\n");
        op->status = GNTST_general_error;
        return;
    }

    if ( unlikely((rd = rcu_lock_domain_by_id(op->dom)) == NULL) )
    {
        gdprintk(XENLOG_INFO, "Could not find domain %d\n", op->dom);
        op->status = GNTST_bad_domain;
        return;
    }

    rc = xsm_grant_mapref(ld, rd, op->flags);
    if ( rc )
    {
        rcu_unlock_domain(rd);
        op->status = GNTST_permission_denied;
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

    if ( rd->grant_table->gt_version == 0 )
        PIN_FAIL(unlock_out, GNTST_general_error,
                 "remote grant table not yet set up");

    /* Bounds check on the grant ref */
    if ( unlikely(op->ref >= nr_grant_entries(rd->grant_table)))
        PIN_FAIL(unlock_out, GNTST_bad_gntref, "Bad ref (%d).\n", op->ref);

    act = &active_entry(rd->grant_table, op->ref);
    shah = shared_entry_header(rd->grant_table, op->ref);
    if (rd->grant_table->gt_version == 1) {
        sha1 = &shared_entry_v1(rd->grant_table, op->ref);
        sha2 = NULL;
        status = &shah->flags;
    } else {
        sha2 = &shared_entry_v2(rd->grant_table, op->ref);
        sha1 = NULL;
        status = &status_entry(rd->grant_table, op->ref);
    }

    /* If already pinned, check the active domid and avoid refcnt overflow. */
    if ( act->pin &&
         ((act->domid != ld->domain_id) ||
          (act->pin & 0x80808080U) != 0 ||
          (act->is_sub_page)) )
        PIN_FAIL(unlock_out, GNTST_general_error,
                 "Bad domain (%d != %d), or risk of counter overflow %08x, or subpage %d\n",
                 act->domid, ld->domain_id, act->pin, act->is_sub_page);

    if ( !act->pin ||
         (!(op->flags & GNTMAP_readonly) &&
          !(act->pin & (GNTPIN_hstw_mask|GNTPIN_devw_mask))) )
    {
        if ( (rc = _set_status(rd->grant_table->gt_version,
                               ld->domain_id, op->flags & GNTMAP_readonly,
                               1, shah, act, status) ) != GNTST_okay )
             goto unlock_out;

        if ( !act->pin )
        {
            act->domid = ld->domain_id;
            if ( sha1 )
                act->gfn = sha1->frame;
            else
                act->gfn = sha2->full_page.frame;
            act->frame = (op->flags & GNTMAP_readonly) ?  
                            gmfn_to_mfn(rd, act->gfn) :
                            gfn_to_mfn_private(rd, act->gfn); 
            act->start = 0;
            act->length = PAGE_SIZE;
            act->is_sub_page = 0;
        }
    }

    old_pin = act->pin;
    if ( op->flags & GNTMAP_device_map )
        act->pin += (op->flags & GNTMAP_readonly) ?
            GNTPIN_devr_inc : GNTPIN_devw_inc;
    if ( op->flags & GNTMAP_host_map )
        act->pin += (op->flags & GNTMAP_readonly) ?
            GNTPIN_hstr_inc : GNTPIN_hstw_inc;

    frame = act->frame;
    act_pin = act->pin;

    cache_flags = (shah->flags & (GTF_PAT | GTF_PWT | GTF_PCD) );

    spin_unlock(&rd->grant_table->lock);

    pg = mfn_valid(frame) ? mfn_to_page(frame) : NULL;

    if ( !pg || (owner = page_get_owner_and_reference(pg)) == dom_io )
    {
        /* Only needed the reference to confirm dom_io ownership. */
        if ( pg )
            put_page(pg);

        if ( paging_mode_external(ld) )
        {
            gdprintk(XENLOG_WARNING, "HVM guests can't grant map iomem\n");
            rc = GNTST_general_error;
            goto undo_out;
        }

        if ( !iomem_access_permitted(rd, frame, frame) )
        {
            gdprintk(XENLOG_WARNING,
                     "Iomem mapping not permitted %lx (domain %d)\n", 
                     frame, rd->domain_id);
            rc = GNTST_general_error;
            goto undo_out;
        }

        rc = create_grant_host_mapping(
            op->host_addr, frame, op->flags, cache_flags);
        if ( rc != GNTST_okay )
            goto undo_out;
    }
    else if ( owner == rd || owner == dom_cow )
    {
        if ( gnttab_host_mapping_get_page_type(op, ld, rd) &&
             !get_page_type(pg, PGT_writable_page) )
            goto could_not_pin;

        nr_gets++;
        if ( op->flags & GNTMAP_host_map )
        {
            rc = create_grant_host_mapping(op->host_addr, frame, op->flags, 0);
            if ( rc != GNTST_okay )
                goto undo_out;

            if ( op->flags & GNTMAP_device_map )
            {
                nr_gets++;
                (void)get_page(pg, rd);
                if ( !(op->flags & GNTMAP_readonly) )
                    get_page_type(pg, PGT_writable_page);
            }
        }
    }
    else
    {
    could_not_pin:
        if ( !rd->is_dying )
            gdprintk(XENLOG_WARNING, "Could not pin grant frame %lx\n",
                     frame);
        if ( owner != NULL )
            put_page(pg);
        rc = GNTST_general_error;
        goto undo_out;
    }

    if ( !is_hvm_domain(ld) && need_iommu(ld) )
    {
        unsigned int wrc, rdc;
        int err = 0;
        /* Shouldn't happen, because you can't use iommu in a HVM domain. */
        BUG_ON(paging_mode_translate(ld));
        /* We're not translated, so we know that gmfns and mfns are
           the same things, so the IOMMU entry is always 1-to-1. */
        mapcount(ld, frame, &wrc, &rdc);
        if ( (act_pin & (GNTPIN_hstw_mask|GNTPIN_devw_mask)) &&
             !(old_pin & (GNTPIN_hstw_mask|GNTPIN_devw_mask)) )
        {
            if ( wrc == 0 )
                err = iommu_map_page(ld, frame, frame,
                                     IOMMUF_readable|IOMMUF_writable);
        }
        else if ( act_pin && !old_pin )
        {
            if ( (wrc + rdc) == 0 )
                err = iommu_map_page(ld, frame, frame, IOMMUF_readable);
        }
        if ( err )
        {
            rc = GNTST_general_error;
            goto undo_out;
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
    if ( nr_gets > 1 )
    {
        if ( !(op->flags & GNTMAP_readonly) )
            put_page_type(pg);
        put_page(pg);
    }
    if ( nr_gets > 0 )
    {
        if ( gnttab_host_mapping_get_page_type(op, ld, rd) )
            put_page_type(pg);
        put_page(pg);
    }

    spin_lock(&rd->grant_table->lock);

    act = &active_entry(rd->grant_table, op->ref);
    shah = shared_entry_header(rd->grant_table, op->ref);

    if ( op->flags & GNTMAP_device_map )
        act->pin -= (op->flags & GNTMAP_readonly) ?
            GNTPIN_devr_inc : GNTPIN_devw_inc;
    if ( op->flags & GNTMAP_host_map )
        act->pin -= (op->flags & GNTMAP_readonly) ?
            GNTPIN_hstr_inc : GNTPIN_hstw_inc;

    if ( !(op->flags & GNTMAP_readonly) &&
         !(act->pin & (GNTPIN_hstw_mask|GNTPIN_devw_mask)) )
        gnttab_clear_flag(_GTF_writing, status);

    if ( !act->pin )
        gnttab_clear_flag(_GTF_reading, status);

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
        if (i && hypercall_preempt_check())
            return i;
        if ( unlikely(__copy_from_guest_offset(&op, uop, i, 1)) )
            return -EFAULT;
        __gnttab_map_grant_ref(&op);
        if ( unlikely(__copy_to_guest_offset(uop, i, &op, 1)) )
            return -EFAULT;
    }

    return 0;
}

static void
__gnttab_unmap_common(
    struct gnttab_unmap_common *op)
{
    domid_t          dom;
    struct domain   *ld, *rd;
    struct active_grant_entry *act;
    s16              rc = 0;
    u32              old_pin;

    ld = current->domain;

    op->frame = (unsigned long)(op->dev_bus_addr >> PAGE_SHIFT);

    if ( unlikely(op->handle >= ld->grant_table->maptrack_limit) )
    {
        gdprintk(XENLOG_INFO, "Bad handle (%d).\n", op->handle);
        op->status = GNTST_bad_handle;
        return;
    }

    op->map = &maptrack_entry(ld->grant_table, op->handle);

    if ( unlikely(!op->map->flags) )
    {
        gdprintk(XENLOG_INFO, "Zero flags for handle (%d).\n", op->handle);
        op->status = GNTST_bad_handle;
        return;
    }

    dom   = op->map->domid;
    op->flags = op->map->flags;

    if ( unlikely((op->rd = rd = rcu_lock_domain_by_id(dom)) == NULL) )
    {
        /* This can happen when a grant is implicitly unmapped. */
        gdprintk(XENLOG_INFO, "Could not find domain %d\n", dom);
        domain_crash(ld); /* naughty... */
        return;
    }

    rc = xsm_grant_unmapref(ld, rd);
    if ( rc )
    {
        rcu_unlock_domain(rd);
        op->status = GNTST_permission_denied;
        return;
    }

    TRACE_1D(TRC_MEM_PAGE_GRANT_UNMAP, dom);

    spin_lock(&rd->grant_table->lock);

    act = &active_entry(rd->grant_table, op->map->ref);
    old_pin = act->pin;

    if ( op->frame == 0 )
    {
        op->frame = act->frame;
    }
    else
    {
        if ( unlikely(op->frame != act->frame) )
            PIN_FAIL(unmap_out, GNTST_general_error,
                     "Bad frame number doesn't match gntref. (%lx != %lx)\n",
                     op->frame, act->frame);
        if ( op->flags & GNTMAP_device_map )
        {
            ASSERT(act->pin & (GNTPIN_devw_mask | GNTPIN_devr_mask));
            op->map->flags &= ~GNTMAP_device_map;
            if ( op->flags & GNTMAP_readonly )
                act->pin -= GNTPIN_devr_inc;
            else
                act->pin -= GNTPIN_devw_inc;
        }
    }

    if ( (op->host_addr != 0) && (op->flags & GNTMAP_host_map) )
    {
        if ( (rc = replace_grant_host_mapping(op->host_addr,
                                              op->frame, op->new_addr, 
                                              op->flags)) < 0 )
            goto unmap_out;

        ASSERT(act->pin & (GNTPIN_hstw_mask | GNTPIN_hstr_mask));
        op->map->flags &= ~GNTMAP_host_map;
        if ( op->flags & GNTMAP_readonly )
            act->pin -= GNTPIN_hstr_inc;
        else
            act->pin -= GNTPIN_hstw_inc;
    }

    if ( !is_hvm_domain(ld) && need_iommu(ld) )
    {
        unsigned int wrc, rdc;
        int err = 0;
        BUG_ON(paging_mode_translate(ld));
        mapcount(ld, op->frame, &wrc, &rdc);
        if ( (wrc + rdc) == 0 )
            err = iommu_unmap_page(ld, op->frame);
        else if ( wrc == 0 )
            err = iommu_map_page(ld, op->frame, op->frame, IOMMUF_readable);
        if ( err )
        {
            rc = GNTST_general_error;
            goto unmap_out;
        }
    }

    /* If just unmapped a writable mapping, mark as dirtied */
    if ( !(op->flags & GNTMAP_readonly) )
         gnttab_mark_dirty(rd, op->frame);

 unmap_out:
    op->status = rc;
    spin_unlock(&rd->grant_table->lock);
    rcu_unlock_domain(rd);
}

static void
__gnttab_unmap_common_complete(struct gnttab_unmap_common *op)
{
    struct domain   *ld, *rd;
    struct active_grant_entry *act;
    grant_entry_header_t *sha;
    struct page_info *pg;
    uint16_t *status;

    rd = op->rd;

    if ( rd == NULL )
    { 
        /*
         * Suggests that __gntab_unmap_common failed in
         * rcu_lock_domain_by_id() or earlier, and so we have nothing
         * to complete
         */
        return;
    }

    ld = current->domain;

    rcu_lock_domain(rd);
    spin_lock(&rd->grant_table->lock);

    if ( rd->grant_table->gt_version == 0 )
        goto unmap_out;

    act = &active_entry(rd->grant_table, op->map->ref);
    sha = shared_entry_header(rd->grant_table, op->map->ref);

    if ( rd->grant_table->gt_version == 1 )
        status = &sha->flags;
    else
        status = &status_entry(rd->grant_table, op->map->ref);

    if ( unlikely(op->frame != act->frame) ) 
    {
        /*
         * Suggests that __gntab_unmap_common failed early and so
         * nothing further to do
         */
        goto unmap_out;
    }

    pg = mfn_to_page(op->frame);

    if ( op->flags & GNTMAP_device_map ) 
    {
        if ( !is_iomem_page(act->frame) )
        {
            if ( op->flags & GNTMAP_readonly )
                put_page(pg);
            else
                put_page_and_type(pg);
        }
    }

    if ( (op->host_addr != 0) && (op->flags & GNTMAP_host_map) )
    {
        if ( op->status != 0 ) 
        {
            /*
             * Suggests that __gntab_unmap_common failed in
             * replace_grant_host_mapping() so nothing further to do
             */
            goto unmap_out;
        }

        if ( !is_iomem_page(op->frame) ) 
        {
            if ( gnttab_host_mapping_get_page_type(op, ld, rd) )
                put_page_type(pg);
            put_page(pg);
        }
    }

    if ( (op->map->flags & (GNTMAP_device_map|GNTMAP_host_map)) == 0 )
    {
        op->map->flags = 0;
        put_maptrack_handle(ld->grant_table, op->handle);
    }

    if ( ((act->pin & (GNTPIN_devw_mask|GNTPIN_hstw_mask)) == 0) &&
         !(op->flags & GNTMAP_readonly) )
        gnttab_clear_flag(_GTF_writing, status);

    if ( act->pin == 0 )
        gnttab_clear_flag(_GTF_reading, status);

 unmap_out:
    spin_unlock(&rd->grant_table->lock);
    rcu_unlock_domain(rd);
}

static void
__gnttab_unmap_grant_ref(
    struct gnttab_unmap_grant_ref *op,
    struct gnttab_unmap_common *common)
{
	common->host_addr = op->host_addr;
    common->dev_bus_addr = op->dev_bus_addr;
    common->handle = op->handle;

    /* Intialise these in case common contains old state */
    common->new_addr = 0;
    common->rd = NULL;

    __gnttab_unmap_common(common);
    op->status = common->status;
}


static long
gnttab_unmap_grant_ref(
    XEN_GUEST_HANDLE(gnttab_unmap_grant_ref_t) uop, unsigned int count)
{
    int i, c, partial_done, done = 0;
    struct gnttab_unmap_grant_ref op;
    struct gnttab_unmap_common common[GNTTAB_UNMAP_BATCH_SIZE];

    while ( count != 0 )
    {
        c = min(count, (unsigned int)GNTTAB_UNMAP_BATCH_SIZE);
        partial_done = 0;

        for ( i = 0; i < c; i++ )
        {
            if ( unlikely(__copy_from_guest_offset(&op, uop, done+i, 1)) )
                goto fault;
            __gnttab_unmap_grant_ref(&op, &(common[i]));
            ++partial_done;
            if ( unlikely(__copy_to_guest_offset(uop, done+i, &op, 1)) )
                goto fault;
        }

        flush_tlb_mask(&current->domain->domain_dirty_cpumask);

        for ( i = 0; i < partial_done; i++ )
            __gnttab_unmap_common_complete(&(common[i]));

        count -= c;
        done += c;

        if (count && hypercall_preempt_check())
            return done;
    }
     
    return 0;

fault:
    flush_tlb_mask(&current->domain->domain_dirty_cpumask);

    for ( i = 0; i < partial_done; i++ )
        __gnttab_unmap_common_complete(&(common[i]));
    return -EFAULT;
}

static void
__gnttab_unmap_and_replace(
    struct gnttab_unmap_and_replace *op,
    struct gnttab_unmap_common *common)
{
	common->host_addr = op->host_addr;
	common->new_addr = op->new_addr;
	common->handle = op->handle;
    
    /* Intialise these in case common contains old state */
    common->dev_bus_addr = 0;
    common->rd = NULL;

    __gnttab_unmap_common(common);
    op->status = common->status;
}

static long
gnttab_unmap_and_replace(
    XEN_GUEST_HANDLE(gnttab_unmap_and_replace_t) uop, unsigned int count)
{
    int i, c, partial_done, done = 0;
    struct gnttab_unmap_and_replace op;
    struct gnttab_unmap_common common[GNTTAB_UNMAP_BATCH_SIZE];

    while ( count != 0 )
    {
        c = min(count, (unsigned int)GNTTAB_UNMAP_BATCH_SIZE);
        partial_done = 0;
        
        for ( i = 0; i < c; i++ )
        {
            if ( unlikely(__copy_from_guest_offset(&op, uop, done+i, 1)) )
                goto fault;
            __gnttab_unmap_and_replace(&op, &(common[i]));
            ++partial_done;
            if ( unlikely(__copy_to_guest_offset(uop, done+i, &op, 1)) )
                goto fault;
        }
        
        flush_tlb_mask(&current->domain->domain_dirty_cpumask);
        
        for ( i = 0; i < partial_done; i++ )
            __gnttab_unmap_common_complete(&(common[i]));

        count -= c;
        done += c;

        if (count && hypercall_preempt_check())
            return done;
    }

    return 0;

fault:
    flush_tlb_mask(&current->domain->domain_dirty_cpumask);

    for ( i = 0; i < partial_done; i++ )
        __gnttab_unmap_common_complete(&(common[i]));
    return -EFAULT;    
}

static int
gnttab_populate_status_frames(struct domain *d, struct grant_table *gt)
{
    unsigned i;
    unsigned req_status_frames;

    req_status_frames = grant_to_status_frames(gt->nr_grant_frames);
    for ( i = nr_status_frames(gt); i < req_status_frames; i++ )
    {
        if ( (gt->status[i] = alloc_xenheap_page()) == NULL )
            goto status_alloc_failed;
        clear_page(gt->status[i]);
    }
    /* Share the new status frames with the recipient domain */
    for ( i = nr_status_frames(gt); i < req_status_frames; i++ )
        gnttab_create_status_page(d, gt, i);

    gt->nr_status_frames = req_status_frames;

    return 0;

status_alloc_failed:
    for ( i = nr_status_frames(gt); i < req_status_frames; i++ )
    {
        free_xenheap_page(gt->status[i]);
        gt->status[i] = NULL;
    }
    return -ENOMEM;
}

static void
gnttab_unpopulate_status_frames(struct domain *d, struct grant_table *gt)
{
    int i;

    for ( i = 0; i < nr_status_frames(gt); i++ )
    {
        page_set_owner(virt_to_page(gt->status[i]), dom_xen);
        free_xenheap_page(gt->status[i]);
        gt->status[i] = NULL;
    }
    gt->nr_status_frames = 0;
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
        clear_page(gt->active[i]);
    }

    /* Shared */
    for ( i = nr_grant_frames(gt); i < req_nr_frames; i++ )
    {
        if ( (gt->shared_raw[i] = alloc_xenheap_page()) == NULL )
            goto shared_alloc_failed;
        clear_page(gt->shared_raw[i]);
    }

    /* Share the new shared frames with the recipient domain */
    for ( i = nr_grant_frames(gt); i < req_nr_frames; i++ )
        gnttab_create_shared_page(d, gt, i);

    gt->nr_grant_frames = req_nr_frames;

    /* Status pages - version 2 */
    if (gt->gt_version > 1)
    {
        if ( gnttab_populate_status_frames(d, gt) )
            goto shared_alloc_failed;
    }

    return 1;

shared_alloc_failed:
    for ( i = nr_grant_frames(gt); i < req_nr_frames; i++ )
    {
        free_xenheap_page(gt->shared_raw[i]);
        gt->shared_raw[i] = NULL;
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
        goto out1;
    }

    dom = op.dom;
    if ( dom == DOMID_SELF )
    {
        d = rcu_lock_current_domain();
    }
    else
    {
        if ( unlikely((d = rcu_lock_domain_by_id(dom)) == NULL) )
        {
            gdprintk(XENLOG_INFO, "Bad domid %d.\n", dom);
            op.status = GNTST_bad_domain;
            goto out1;
        }

        if ( unlikely(!IS_PRIV_FOR(current->domain, d)) )
        {
            op.status = GNTST_permission_denied;
            goto out2;
        }
    }

    if ( xsm_grant_setup(current->domain, d) )
    {
        op.status = GNTST_permission_denied;
        goto out2;
    }

    spin_lock(&d->grant_table->lock);

    if ( d->grant_table->gt_version == 0 )
        d->grant_table->gt_version = 1;

    if ( (op.nr_frames > nr_grant_frames(d->grant_table) ||
          ( (d->grant_table->gt_version > 1 ) &&
            (grant_to_status_frames(op.nr_frames) >
             nr_status_frames(d->grant_table))  )  ) &&
         !gnttab_grow_table(d, op.nr_frames) )
    {
        gdprintk(XENLOG_INFO,
                "Expand grant table to %d failed. Current: %d Max: %d.\n",
                op.nr_frames,
                nr_grant_frames(d->grant_table),
                max_nr_grant_frames);
        op.status = GNTST_general_error;
        goto out3;
    }
 
    op.status = GNTST_okay;
    for ( i = 0; i < op.nr_frames; i++ )
    {
        gmfn = gnttab_shared_gmfn(d, d->grant_table, i);
        /* Grant tables cannot be shared */
        BUG_ON(SHARED_M2P(gmfn));
        (void)copy_to_guest_offset(op.frame_list, i, &gmfn, 1);
    }

 out3:
    spin_unlock(&d->grant_table->lock);
 out2:
    rcu_unlock_domain(d);
 out1:
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
    int rc;

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
        d = rcu_lock_current_domain();
    }
    else
    {
        if ( unlikely((d = rcu_lock_domain_by_id(dom)) == NULL) )
        {
            gdprintk(XENLOG_INFO, "Bad domid %d.\n", dom);
            op.status = GNTST_bad_domain;
            goto query_out;
        }

        if ( unlikely(!IS_PRIV_FOR(current->domain, d)) )
        {
            op.status = GNTST_permission_denied;
            goto query_out_unlock;
        }
    }

    rc = xsm_grant_query_size(current->domain, d);
    if ( rc )
    {
        op.status = GNTST_permission_denied;
        goto query_out_unlock;
    }

    spin_lock(&d->grant_table->lock);

    op.nr_frames     = nr_grant_frames(d->grant_table);
    op.max_nr_frames = max_nr_grant_frames;
    op.status        = GNTST_okay;

    spin_unlock(&d->grant_table->lock);

 
 query_out_unlock:
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
    grant_entry_header_t *sha;
    union grant_combo   scombo, prev_scombo, new_scombo;
    int                 retries = 0;

    if ( unlikely((rgt = rd->grant_table) == NULL) )
    {
        gdprintk(XENLOG_INFO, "Dom %d has no grant table.\n", rd->domain_id);
        return 0;
    }

    spin_lock(&rgt->lock);

    if ( rgt->gt_version == 0 )
    {
        gdprintk(XENLOG_INFO,
                 "Grant table not ready for transfer to domain(%d).\n",
                 rd->domain_id);
        goto fail;
    }

    if ( unlikely(ref >= nr_grant_entries(rd->grant_table)) )
    {
        gdprintk(XENLOG_INFO,
                "Bad grant reference (%d) for transfer to domain(%d).\n",
                ref, rd->domain_id);
        goto fail;
    }

    sha = shared_entry_header(rgt, ref);
    
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
    struct gnttab_transfer gop;
    unsigned long mfn;
    unsigned int max_bitsize;

    for ( i = 0; i < count; i++ )
    {
        if (i && hypercall_preempt_check())
            return i;

        /* Read from caller address space. */
        if ( unlikely(__copy_from_guest_offset(&gop, uop, i, 1)) )
        {
            gdprintk(XENLOG_INFO, "gnttab_transfer: error reading req %d/%d\n",
                    i, count);
            return -EFAULT;
        }

        mfn = gfn_to_mfn_private(d, gop.mfn);

        /* Check the passed page frame for basic validity. */
        if ( unlikely(!mfn_valid(mfn)) )
        { 
            gdprintk(XENLOG_INFO, "gnttab_transfer: out-of-range %lx\n",
                    (unsigned long)gop.mfn);
            gop.status = GNTST_bad_page;
            goto copyback;
        }

        page = mfn_to_page(mfn);
        if ( unlikely(is_xen_heap_page(page)) )
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

#ifndef __ia64__ /* IA64 implicitly replaces the old page in steal_page(). */
        guest_physmap_remove_page(d, gop.mfn, mfn, 0);
#endif
        flush_tlb_mask(&d->domain_dirty_cpumask);

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

        if ( xsm_grant_transfer(d, e) )
        {
            gop.status = GNTST_permission_denied;
        unlock_and_copyback:
            rcu_unlock_domain(e);
            page->count_info &= ~(PGC_count_mask|PGC_allocated);
            free_domheap_page(page);
            goto copyback;
        }

        max_bitsize = domain_clamp_alloc_bitsize(
            e, BITS_PER_LONG+PAGE_SHIFT-1);
        if ( (1UL << (max_bitsize - PAGE_SHIFT)) <= mfn )
        {
            struct page_info *new_page;
            void *sp, *dp;

            new_page = alloc_domheap_page(NULL, MEMF_bits(max_bitsize));
            if ( new_page == NULL )
            {
                gop.status = GNTST_address_too_big;
                goto unlock_and_copyback;
            }

            sp = map_domain_page(mfn);
            dp = __map_domain_page(new_page);
            memcpy(dp, sp, PAGE_SIZE);
            unmap_domain_page(dp);
            unmap_domain_page(sp);

            page->count_info &= ~(PGC_count_mask|PGC_allocated);
            free_domheap_page(page);
            page = new_page;
        }

        spin_lock(&e->page_alloc_lock);

        /*
         * Check that 'e' will accept the page and has reservation
         * headroom.  Also, a domain mustn't have PGC_allocated
         * pages when it is dying.
         */
        if ( unlikely(e->is_dying) ||
             unlikely(e->tot_pages >= e->max_pages) ||
             unlikely(!gnttab_prepare_for_transfer(e, d, gop.ref)) )
        {
            if ( !e->is_dying )
                gdprintk(XENLOG_INFO, "gnttab_transfer: "
                        "Transferee has no reservation "
                        "headroom (%d,%d) or provided a bad grant ref (%08x) "
                        "or is dying (%d)\n",
                        e->tot_pages, e->max_pages, gop.ref, e->is_dying);
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
        page_list_add_tail(page, &e->page_list);
        page_set_owner(page, e);

        spin_unlock(&e->page_alloc_lock);

        TRACE_1D(TRC_MEM_PAGE_GRANT_TRANSFER, e->domain_id);

        /* Tell the guest about its new page frame. */
        spin_lock(&e->grant_table->lock);

        if ( e->grant_table->gt_version == 1 )
        {
            grant_entry_v1_t *sha = &shared_entry_v1(e->grant_table, gop.ref);
            guest_physmap_add_page(e, sha->frame, mfn, 0);
            sha->frame = mfn;
        }
        else
        {
            grant_entry_v2_t *sha = &shared_entry_v2(e->grant_table, gop.ref);
            guest_physmap_add_page(e, sha->full_page.frame, mfn, 0);
            sha->full_page.frame = mfn;
        }
        wmb();
        shared_entry_header(e->grant_table, gop.ref)->flags |=
            GTF_transfer_completed;

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
    grant_entry_header_t *sha;
    struct active_grant_entry *act;
    unsigned long r_frame;
    uint16_t *status;
    domid_t trans_domid;
    grant_ref_t trans_gref;
    int released_read;
    int released_write;
    struct domain *trans_dom;

    released_read = 0;
    released_write = 0;

    spin_lock(&rd->grant_table->lock);

    act = &active_entry(rd->grant_table, gref);
    sha = shared_entry_header(rd->grant_table, gref);
    r_frame = act->frame;

    if (rd->grant_table->gt_version == 1)
    {
        status = &sha->flags;
        trans_domid = rd->domain_id;
        /* Shut the compiler up.  This'll never be used, because
           trans_domid == rd->domain_id, but gcc doesn't know that. */
        trans_gref = 0x1234567;
    }
    else
    {
        status = &status_entry(rd->grant_table, gref);
        trans_domid = act->trans_dom;
        trans_gref = act->trans_gref;
    }

    if ( readonly )
    {
        act->pin -= GNTPIN_hstr_inc;
    }
    else
    {
        gnttab_mark_dirty(rd, r_frame);

        act->pin -= GNTPIN_hstw_inc;
        if ( !(act->pin & (GNTPIN_devw_mask|GNTPIN_hstw_mask)) )
        {
            released_write = 1;
            gnttab_clear_flag(_GTF_writing, status);
        }
    }

    if ( !act->pin )
    {
        gnttab_clear_flag(_GTF_reading, status);
        released_read = 1;
    }

    spin_unlock(&rd->grant_table->lock);

    if ( trans_domid != rd->domain_id )
    {
        if ( released_write || released_read )
        {
            trans_dom = rcu_lock_domain_by_id(trans_domid);
            if ( trans_dom != NULL )
            {
                /* Recursive calls, but they're tail calls, so it's
                   okay. */
                if ( released_write )
                    __release_grant_for_copy(trans_dom, trans_gref, 0);
                else if ( released_read )
                    __release_grant_for_copy(trans_dom, trans_gref, 1);
            }
        }
    }
}

/* The status for a grant indicates that we're taking more access than
   the pin requires.  Fix up the status to match the pin.  Called
   under the domain's grant table lock. */
/* Only safe on transitive grants.  Even then, note that we don't
   attempt to drop any pin on the referent grant. */
static void __fixup_status_for_pin(struct active_grant_entry *act,
                                   uint16_t *status)
{
    if ( !(act->pin & GNTPIN_hstw_mask) )
        *status &= ~_GTF_writing;

    if ( !(act->pin & GNTPIN_hstr_mask) )
        *status &= ~_GTF_reading;
}

/* Grab a frame number from a grant entry and update the flags and pin
   count as appropriate.  Note that this does *not* update the page
   type or reference counts, and does not check that the mfn is
   actually valid. */
static int
__acquire_grant_for_copy(
    struct domain *rd, unsigned long gref, struct domain *ld, int readonly,
    unsigned long *frame, unsigned *page_off, unsigned *length,
    unsigned allow_transitive, struct domain **owning_domain)
{
    grant_entry_v1_t *sha1;
    grant_entry_v2_t *sha2;
    grant_entry_header_t *shah;
    struct active_grant_entry *act;
    grant_status_t *status;
    uint32_t old_pin;
    domid_t trans_domid;
    grant_ref_t trans_gref;
    struct domain *rrd;
    unsigned long grant_frame;
    unsigned trans_page_off;
    unsigned trans_length;
    int is_sub_page;
    struct domain *ignore;
    s16 rc = GNTST_okay;

    *owning_domain = NULL;

    spin_lock(&rd->grant_table->lock);

    if ( rd->grant_table->gt_version == 0 )
        PIN_FAIL(unlock_out, GNTST_general_error,
                 "remote grant table not ready\n");

    if ( unlikely(gref >= nr_grant_entries(rd->grant_table)) )
        PIN_FAIL(unlock_out, GNTST_bad_gntref,
                 "Bad grant reference %ld\n", gref);

    act = &active_entry(rd->grant_table, gref);
    shah = shared_entry_header(rd->grant_table, gref);
    if ( rd->grant_table->gt_version == 1 )
    {
        sha1 = &shared_entry_v1(rd->grant_table, gref);
        sha2 = NULL;
        status = &shah->flags;
    }
    else
    {
        sha1 = NULL;
        sha2 = &shared_entry_v2(rd->grant_table, gref);
        status = &status_entry(rd->grant_table, gref);
    }

    /* If already pinned, check the active domid and avoid refcnt overflow. */
    if ( act->pin &&
         ((act->domid != ld->domain_id) ||
          (act->pin & 0x80808080U) != 0) )
        PIN_FAIL(unlock_out, GNTST_general_error,
                 "Bad domain (%d != %d), or risk of counter overflow %08x\n",
                 act->domid, ld->domain_id, act->pin);

    old_pin = act->pin;
    if ( !act->pin ||
         (!readonly && !(act->pin & (GNTPIN_devw_mask|GNTPIN_hstw_mask))) )
    {
        if ( (rc = _set_status(rd->grant_table->gt_version,
                               ld->domain_id,
                               readonly, 0, shah, act,
                               status) ) != GNTST_okay )
             goto unlock_out;

        trans_domid = ld->domain_id;
        trans_gref = 0;
        if ( sha2 && (shah->flags & GTF_type_mask) == GTF_transitive )
        {
            if ( !allow_transitive )
                PIN_FAIL(unlock_out, GNTST_general_error,
                         "transitive grant when transitivity not allowed\n");

            trans_domid = sha2->transitive.trans_domid;
            trans_gref = sha2->transitive.gref;
            barrier(); /* Stop the compiler from re-loading
                          trans_domid from shared memory */
            if ( trans_domid == rd->domain_id )
                PIN_FAIL(unlock_out, GNTST_general_error,
                         "transitive grants cannot be self-referential\n");

            /* We allow the trans_domid == ld->domain_id case, which
               corresponds to a grant being issued by one domain, sent
               to another one, and then transitively granted back to
               the original domain.  Allowing it is easy, and means
               that you don't need to go out of your way to avoid it
               in the guest. */

            rrd = rcu_lock_domain_by_id(trans_domid);
            if ( rrd == NULL )
                PIN_FAIL(unlock_out, GNTST_general_error,
                         "transitive grant referenced bad domain %d\n",
                         trans_domid);
            spin_unlock(&rd->grant_table->lock);

            rc = __acquire_grant_for_copy(rrd, trans_gref, rd,
                                          readonly, &grant_frame,
                                          &trans_page_off, &trans_length,
                                          0, &ignore);

            spin_lock(&rd->grant_table->lock);
            if ( rc != GNTST_okay ) {
                __fixup_status_for_pin(act, status);
                spin_unlock(&rd->grant_table->lock);
                return rc;
            }

            /* We dropped the lock, so we have to check that nobody
               else tried to pin (or, for that matter, unpin) the
               reference in *this* domain.  If they did, just give up
               and try again. */
            if ( act->pin != old_pin )
            {
                __fixup_status_for_pin(act, status);
                spin_unlock(&rd->grant_table->lock);
                return __acquire_grant_for_copy(rd, gref, ld, readonly,
                                                frame, page_off, length,
                                                allow_transitive,
                                                owning_domain);
            }

            /* The actual remote remote grant may or may not be a
               sub-page, but we always treat it as one because that
               blocks mappings of transitive grants. */
            is_sub_page = 1;
            *owning_domain = rrd;
            act->gfn = -1ul;
        }
        else if ( sha1 )
        {
            act->gfn = sha1->frame;
            grant_frame = readonly ? gmfn_to_mfn(rd, act->gfn) :
                                     gfn_to_mfn_private(rd, act->gfn);
            is_sub_page = 0;
            trans_page_off = 0;
            trans_length = PAGE_SIZE;
            *owning_domain = rd;
        }
        else if ( !(sha2->hdr.flags & GTF_sub_page) )
        {
            act->gfn = sha2->full_page.frame;
            grant_frame = readonly ? gmfn_to_mfn(rd, act->gfn) :
                                     gfn_to_mfn_private(rd, act->gfn);
            is_sub_page = 0;
            trans_page_off = 0;
            trans_length = PAGE_SIZE;
            *owning_domain = rd;
        }
        else
        {
            act->gfn = sha2->sub_page.frame;
            grant_frame = readonly ? gmfn_to_mfn(rd, act->gfn) :
                                     gfn_to_mfn_private(rd, act->gfn);
            is_sub_page = 1;
            trans_page_off = sha2->sub_page.page_off;
            trans_length = sha2->sub_page.length;
            *owning_domain = rd;
        }

        if ( !act->pin )
        {
            act->domid = ld->domain_id;
            act->is_sub_page = is_sub_page;
            act->start = trans_page_off;
            act->length = trans_length;
            act->trans_dom = trans_domid;
            act->trans_gref = trans_gref;
            act->frame = grant_frame;
        }
    }
    else
    {
        *owning_domain = rd;
    }

    act->pin += readonly ? GNTPIN_hstr_inc : GNTPIN_hstw_inc;

    *page_off = act->start;
    *length = act->length;
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
    struct domain *source_domain = NULL, *dest_domain = NULL;
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
        sd = rcu_lock_current_domain();
    else if ( (sd = rcu_lock_domain_by_id(op->source.domid)) == NULL )
        PIN_FAIL(error_out, GNTST_bad_domain,
                 "couldn't find %d\n", op->source.domid);

    if ( op->dest.domid == DOMID_SELF )
        dd = rcu_lock_current_domain();
    else if ( (dd = rcu_lock_domain_by_id(op->dest.domid)) == NULL )
        PIN_FAIL(error_out, GNTST_bad_domain,
                 "couldn't find %d\n", op->dest.domid);

    rc = xsm_grant_copy(sd, dd);
    if ( rc )
    {
        rc = GNTST_permission_denied;
        goto error_out;
    }

    if ( src_is_gref )
    {
        unsigned source_off, source_len;
        rc = __acquire_grant_for_copy(sd, op->source.u.ref, current->domain, 1,
                                      &s_frame, &source_off, &source_len, 1,
                                      &source_domain);
        if ( rc != GNTST_okay )
            goto error_out;
        have_s_grant = 1;
        if ( op->source.offset < source_off ||
             op->len > source_len )
            PIN_FAIL(error_out, GNTST_general_error,
                     "copy source out of bounds: %d < %d || %d > %d\n",
                     op->source.offset, source_off,
                     op->len, source_len);
    }
    else
    {
#ifdef CONFIG_X86
        p2m_type_t p2mt;
        struct p2m_domain *p2m = p2m_get_hostp2m(sd);
        s_frame = mfn_x(gfn_to_mfn(p2m, op->source.u.gmfn, &p2mt));
        if ( !p2m_is_valid(p2mt) )
          s_frame = INVALID_MFN;
        if ( p2m_is_paging(p2mt) )
        {
            p2m_mem_paging_populate(p2m, op->source.u.gmfn);
            rc = -ENOENT;
            goto error_out;
        }
#else
        s_frame = gmfn_to_mfn(sd, op->source.u.gmfn);        
#endif
        source_domain = sd;
    }
    if ( unlikely(!mfn_valid(s_frame)) )
        PIN_FAIL(error_out, GNTST_general_error,
                 "source frame %lx invalid.\n", s_frame);
    if ( !get_page(mfn_to_page(s_frame), source_domain) )
    {
        if ( !sd->is_dying )
            gdprintk(XENLOG_WARNING, "Could not get src frame %lx\n", s_frame);
        rc = GNTST_general_error;
        goto error_out;
    }
    have_s_ref = 1;

    if ( dest_is_gref )
    {
        unsigned dest_off, dest_len;
        rc = __acquire_grant_for_copy(dd, op->dest.u.ref, current->domain, 0,
                                      &d_frame, &dest_off, &dest_len, 1,
                                      &dest_domain);
        if ( rc != GNTST_okay )
            goto error_out;
        have_d_grant = 1;
        if ( op->dest.offset < dest_off ||
             op->len > dest_len )
            PIN_FAIL(error_out, GNTST_general_error,
                     "copy dest out of bounds: %d < %d || %d > %d\n",
                     op->dest.offset, dest_off,
                     op->len, dest_len);
    }
    else
    {
#ifdef CONFIG_X86
        p2m_type_t p2mt;
        struct p2m_domain *p2m = p2m_get_hostp2m(dd);
        d_frame = mfn_x(gfn_to_mfn_unshare(p2m, op->dest.u.gmfn, &p2mt, 1));
        if ( !p2m_is_valid(p2mt) )
          d_frame = INVALID_MFN;
        if ( p2m_is_paging(p2mt) )
        {
            p2m_mem_paging_populate(p2m, op->dest.u.gmfn);
            rc = -ENOENT;
            goto error_out;
        }
#else
        d_frame = gmfn_to_mfn(dd, op->dest.u.gmfn);
#endif
        dest_domain = dd;
    }
    if ( unlikely(!mfn_valid(d_frame)) )
        PIN_FAIL(error_out, GNTST_general_error,
                 "destination frame %lx invalid.\n", d_frame);
    if ( !get_page_and_type(mfn_to_page(d_frame), dest_domain,
                            PGT_writable_page) )
    {
        if ( !dd->is_dying )
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
        if (i && hypercall_preempt_check())
            return i;
        if ( unlikely(__copy_from_guest_offset(&op, uop, i, 1)) )
            return -EFAULT;
        __gnttab_copy(&op);
        if ( unlikely(__copy_to_guest_offset(uop, i, &op, 1)) )
            return -EFAULT;
    }
    return 0;
}

static long
gnttab_set_version(XEN_GUEST_HANDLE(gnttab_set_version_t uop))
{
    gnttab_set_version_t op;
    struct domain *d = current->domain;
    struct grant_table *gt = d->grant_table;
    struct active_grant_entry *act;
    long res;
    int i;

    if (copy_from_guest(&op, uop, 1))
        return -EFAULT;

    res = -EINVAL;
    if (op.version != 1 && op.version != 2)
        goto out;

    res = 0;
    if ( gt->gt_version == op.version )
        goto out;

    spin_lock(&gt->lock);
    /* Make sure that the grant table isn't currently in use when we
       change the version number. */
    /* (You need to change the version number for e.g. kexec.) */
    if ( gt->gt_version != 0 )
    {
        for ( i = 0; i < nr_grant_entries(gt); i++ )
        {
            act = &active_entry(gt, i);
            if ( act->pin != 0 )
            {
                gdprintk(XENLOG_WARNING,
                         "tried to change grant table version from %d to %d, but some grant entries still in use\n",
                         gt->gt_version,
                         op.version);
                res = -EBUSY;
                goto out_unlock;
            }
        }
    }

    /* XXX: If we're going to version 2, we could maybe shrink the
       active grant table here. */

    if ( op.version == 2 && gt->gt_version < 2 )
    {
        res = gnttab_populate_status_frames(d, gt);
        if ( res < 0)
            goto out_unlock;
    }

    if ( op.version < 2 && gt->gt_version == 2 )
        gnttab_unpopulate_status_frames(d, gt);

    if ( op.version != gt->gt_version )
    {
        /* Make sure there's no crud left over in the table from the
           old version. */
        for ( i = 0; i < nr_grant_frames(gt); i++ )
            memset(gt->shared_raw[i], 0, PAGE_SIZE);
    }

    gt->gt_version = op.version;

out_unlock:
    spin_unlock(&gt->lock);

out:
    op.version = gt->gt_version;

    if (copy_to_guest(uop, &op, 1))
        res = -EFAULT;

    return res;
}

static long
gnttab_get_status_frames(XEN_GUEST_HANDLE(gnttab_get_status_frames_t) uop,
                         int count)
{
    gnttab_get_status_frames_t op;
    struct domain *d;
    struct grant_table *gt;
    uint64_t       gmfn;
    int i;
    int rc;

    if ( count != 1 )
        return -EINVAL;

    if ( unlikely(copy_from_guest(&op, uop, 1) != 0) )
    {
        gdprintk(XENLOG_INFO,
                 "Fault while reading gnttab_get_status_frames_t.\n");
        return -EFAULT;
    }

    rc = rcu_lock_target_domain_by_id(op.dom, &d);
    if ( rc < 0 )
    {
        if ( rc == -ESRCH )
            op.status = GNTST_bad_domain;
        else if ( rc == -EPERM )
            op.status = GNTST_permission_denied;
        else
            op.status = GNTST_general_error;
        goto out1;
    }

    gt = d->grant_table;

    if ( unlikely(op.nr_frames > nr_status_frames(gt)) ) {
        gdprintk(XENLOG_INFO, "Guest requested addresses for %d grant status "
                 "frames, but only %d are available.\n",
                 op.nr_frames, nr_status_frames(gt));
        op.status = GNTST_general_error;
        goto out2;
    }

    op.status = GNTST_okay;

    spin_lock(&gt->lock);

    for ( i = 0; i < op.nr_frames; i++ )
    {
        gmfn = gnttab_status_gmfn(d, d->grant_table, i);
        if (copy_to_guest_offset(op.frame_list,
                                 i,
                                 &gmfn,
                                 1))
            op.status = GNTST_bad_virt_addr;
    }

    spin_unlock(&gt->lock);
out2:
    rcu_unlock_domain(d);
out1:
    if ( unlikely(copy_to_guest(uop, &op, 1)) )
        return -EFAULT;

    return 0;
}

static long
gnttab_get_version(XEN_GUEST_HANDLE(gnttab_get_version_t uop))
{
    gnttab_get_version_t op;
    struct domain *d;

    if ( copy_from_guest(&op, uop, 1) )
        return -EFAULT;
    d = rcu_lock_domain_by_id(op.dom);
    if ( d == NULL )
        return -ESRCH;
    if ( !IS_PRIV_FOR(current->domain, d) )
    {
        rcu_unlock_domain(d);
        return -EPERM;
    }
    spin_lock(&d->grant_table->lock);
    op.version = d->grant_table->gt_version;
    spin_unlock(&d->grant_table->lock);

    if ( copy_to_guest(uop, &op, 1) )
        return -EFAULT;
    else
        return 0;
}

long
do_grant_table_op(
    unsigned int cmd, XEN_GUEST_HANDLE(void) uop, unsigned int count)
{
    long rc;
    struct domain *d = current->domain;
    
    if ( (int)count < 0 )
        return -EINVAL;
    
    domain_lock(d);
    
    rc = -EFAULT;
    switch ( cmd )
    {
    case GNTTABOP_map_grant_ref:
    {
        XEN_GUEST_HANDLE(gnttab_map_grant_ref_t) map =
            guest_handle_cast(uop, gnttab_map_grant_ref_t);
        if ( unlikely(!guest_handle_okay(map, count)) )
            goto out;
        rc = gnttab_map_grant_ref(map, count);
        if ( rc > 0 )
        {
            guest_handle_add_offset(map, rc);
            uop = guest_handle_cast(map, void);
        }
        break;
    }
    case GNTTABOP_unmap_grant_ref:
    {
        XEN_GUEST_HANDLE(gnttab_unmap_grant_ref_t) unmap =
            guest_handle_cast(uop, gnttab_unmap_grant_ref_t);
        if ( unlikely(!guest_handle_okay(unmap, count)) )
            goto out;
        rc = gnttab_unmap_grant_ref(unmap, count);
        if ( rc > 0 )
        {
            guest_handle_add_offset(unmap, rc);
            uop = guest_handle_cast(unmap, void);
        }
        break;
    }
    case GNTTABOP_unmap_and_replace:
    {
        XEN_GUEST_HANDLE(gnttab_unmap_and_replace_t) unmap =
            guest_handle_cast(uop, gnttab_unmap_and_replace_t);
        if ( unlikely(!guest_handle_okay(unmap, count)) )
            goto out;
        rc = -ENOSYS;
        if ( unlikely(!replace_grant_supported()) )
            goto out;
        rc = gnttab_unmap_and_replace(unmap, count);
        if ( rc > 0 )
        {
            guest_handle_add_offset(unmap, rc);
            uop = guest_handle_cast(unmap, void);
        }
        break;
    }
    case GNTTABOP_setup_table:
    {
        rc = gnttab_setup_table(
            guest_handle_cast(uop, gnttab_setup_table_t), count);
        ASSERT(rc <= 0);
        break;
    }
    case GNTTABOP_transfer:
    {
        XEN_GUEST_HANDLE(gnttab_transfer_t) transfer =
            guest_handle_cast(uop, gnttab_transfer_t);
        if ( unlikely(!guest_handle_okay(transfer, count)) )
            goto out;
        rc = gnttab_transfer(transfer, count);
        if ( rc > 0 )
        {
            guest_handle_add_offset(transfer, rc);
            uop = guest_handle_cast(transfer, void);
        }
        break;
    }
    case GNTTABOP_copy:
    {
        XEN_GUEST_HANDLE(gnttab_copy_t) copy =
            guest_handle_cast(uop, gnttab_copy_t);
        if ( unlikely(!guest_handle_okay(copy, count)) )
            goto out;
        rc = gnttab_copy(copy, count);
        if ( rc > 0 )
        {
            guest_handle_add_offset(copy, rc);
            uop = guest_handle_cast(copy, void);
        }
        break;
    }
    case GNTTABOP_query_size:
    {
        rc = gnttab_query_size(
            guest_handle_cast(uop, gnttab_query_size_t), count);
        ASSERT(rc <= 0);
        break;
    }
    case GNTTABOP_set_version:
    {
        rc = gnttab_set_version(guest_handle_cast(uop, gnttab_set_version_t));
        break;
    }
    case GNTTABOP_get_status_frames:
    {
        rc = gnttab_get_status_frames(
            guest_handle_cast(uop, gnttab_get_status_frames_t), count);
        break;
    }
    case GNTTABOP_get_version:
    {
        rc = gnttab_get_version(guest_handle_cast(uop, gnttab_get_version_t));
        break;
    }
    default:
        rc = -ENOSYS;
        break;
    }
    
  out:
    domain_unlock(d);

    if ( rc > 0 )
    {
        ASSERT(rc < count);
        rc = hypercall_create_continuation(__HYPERVISOR_grant_table_op,
                                           "ihi", cmd, uop, count - rc);
    }
    
    return rc;
}

#ifdef CONFIG_COMPAT
#include "compat/grant_table.c"
#endif

static unsigned int max_nr_active_grant_frames(void)
{
    return (((max_nr_grant_frames * (PAGE_SIZE / sizeof(grant_entry_v1_t))) + 
                    ((PAGE_SIZE / sizeof(struct active_grant_entry))-1)) 
                   / (PAGE_SIZE / sizeof(struct active_grant_entry)));
}

int 
grant_table_create(
    struct domain *d)
{
    struct grant_table *t;
    int                 i;

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
        clear_page(t->active[i]);
    }

    /* Tracking of mapped foreign frames table */
    if ( (t->maptrack = xmalloc_array(struct grant_mapping *,
                                      max_nr_maptrack_frames())) == NULL )
        goto no_mem_2;
    memset(t->maptrack, 0, max_nr_maptrack_frames() * sizeof(t->maptrack[0]));
    if ( (t->maptrack[0] = alloc_xenheap_page()) == NULL )
        goto no_mem_3;
    clear_page(t->maptrack[0]);
    t->maptrack_limit = PAGE_SIZE / sizeof(struct grant_mapping);
    for ( i = 0; i < t->maptrack_limit; i++ )
        t->maptrack[0][i].ref = i+1;

    /* Shared grant table. */
    if ( (t->shared_raw = xmalloc_array(void *, max_nr_grant_frames)) == NULL )
        goto no_mem_3;
    memset(t->shared_raw, 0, max_nr_grant_frames * sizeof(t->shared_raw[0]));
    for ( i = 0; i < INITIAL_NR_GRANT_FRAMES; i++ )
    {
        if ( (t->shared_raw[i] = alloc_xenheap_page()) == NULL )
            goto no_mem_4;
        clear_page(t->shared_raw[i]);
    }
    
    for ( i = 0; i < INITIAL_NR_GRANT_FRAMES; i++ )
        gnttab_create_shared_page(d, t, i);

    /* Status pages for grant table - for version 2 */
    t->status = xmalloc_array(grant_status_t *,
                              grant_to_status_frames(max_nr_grant_frames));
    if ( t->status == NULL )
        goto no_mem_4;
    memset(t->status, 0,
           grant_to_status_frames(max_nr_grant_frames) * sizeof(t->status[0]));
    t->nr_status_frames = 0;

    /* Okay, install the structure. */
    d->grant_table = t;
    return 0;

 no_mem_4:
    for ( i = 0; i < INITIAL_NR_GRANT_FRAMES; i++ )
        free_xenheap_page(t->shared_raw[i]);
    xfree(t->shared_raw);
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
    grant_entry_header_t *sha;
    uint16_t             *status;
    struct page_info     *pg;

    BUG_ON(!d->is_dying);

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
        sha = shared_entry_header(rd->grant_table, ref);
        if (rd->grant_table->gt_version == 1)
            status = &sha->flags;
        else
            status = &status_entry(rd->grant_table, ref);

        pg = mfn_to_page(act->frame);

        if ( map->flags & GNTMAP_readonly )
        {
            if ( map->flags & GNTMAP_device_map )
            {
                BUG_ON(!(act->pin & GNTPIN_devr_mask));
                act->pin -= GNTPIN_devr_inc;
                if ( !is_iomem_page(act->frame) )
                    put_page(pg);
            }

            if ( map->flags & GNTMAP_host_map )
            {
                BUG_ON(!(act->pin & GNTPIN_hstr_mask));
                act->pin -= GNTPIN_hstr_inc;
                if ( gnttab_release_host_mappings(d) &&
                     !is_iomem_page(act->frame) )
                    put_page(pg);
            }
        }
        else
        {
            if ( map->flags & GNTMAP_device_map )
            {
                BUG_ON(!(act->pin & GNTPIN_devw_mask));
                act->pin -= GNTPIN_devw_inc;
                if ( !is_iomem_page(act->frame) )
                    put_page_and_type(pg);
            }

            if ( map->flags & GNTMAP_host_map )
            {
                BUG_ON(!(act->pin & GNTPIN_hstw_mask));
                act->pin -= GNTPIN_hstw_inc;
                if ( gnttab_release_host_mappings(d) &&
                     !is_iomem_page(act->frame) )
                {
                    if ( gnttab_host_mapping_get_page_type(map, d, rd) )
                        put_page_type(pg);
                    put_page(pg);
                }
            }

            if ( (act->pin & (GNTPIN_devw_mask|GNTPIN_hstw_mask)) == 0 )
                gnttab_clear_flag(_GTF_writing, status);
        }

        if ( act->pin == 0 )
            gnttab_clear_flag(_GTF_reading, status);

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
        free_xenheap_page(t->shared_raw[i]);
    xfree(t->shared_raw);

    for ( i = 0; i < nr_maptrack_frames(t); i++ )
        free_xenheap_page(t->maptrack[i]);
    xfree(t->maptrack);

    for ( i = 0; i < nr_active_grant_frames(t); i++ )
        free_xenheap_page(t->active[i]);
    xfree(t->active);

    for ( i = 0; i < nr_status_frames(t); i++ )
        free_xenheap_page(t->status[i]);
    xfree(t->status);

    xfree(t);
    d->grant_table = NULL;
}

void gnttab_usage_print(struct domain *rd)
{
    int first = 1;
    grant_ref_t ref;
    struct grant_table *gt = rd->grant_table;

    printk("      -------- active --------       -------- shared --------\n");
    printk("[ref] localdom mfn      pin          localdom gmfn     flags\n");

    spin_lock(&gt->lock);

    if ( gt->gt_version == 0 )
        goto out;

    for ( ref = 0; ref != nr_grant_entries(gt); ref++ )
    {
        struct active_grant_entry *act;
        struct grant_entry_header *sha;
        grant_entry_v1_t *sha1;
        grant_entry_v2_t *sha2;
        uint16_t status;
        uint64_t frame;

        act = &active_entry(gt, ref);
        if ( !act->pin )
            continue;

        sha = shared_entry_header(gt, ref);

        if ( gt->gt_version == 1 )
        {
            sha1 = &shared_entry_v1(gt, ref);
            sha2 = NULL;
            status = sha->flags;
            frame = sha1->frame;
        }
        else
        {
            sha2 = &shared_entry_v2(gt, ref);
            sha1 = NULL;
            frame = sha2->full_page.frame;
            status = status_entry(gt, ref);
        }

        if ( first )
        {
            printk("grant-table for remote domain:%5d (v%d)\n",
                   rd->domain_id, gt->gt_version);
            first = 0;
        }

        /*      [ddd]    ddddd 0xXXXXXX 0xXXXXXXXX      ddddd 0xXXXXXX 0xXX */
        printk("[%3d]    %5d 0x%06lx 0x%08x      %5d 0x%06"PRIx64" 0x%02x\n",
               ref, act->domid, act->frame, act->pin,
               sha->domid, frame, status);
    }

 out:
    spin_unlock(&gt->lock);

    if ( first )
        printk("grant-table for remote domain:%5d ... "
               "no active grant table entries\n", rd->domain_id);
}

static void gnttab_usage_print_all(unsigned char key)
{
    struct domain *d;
    printk("%s [ key '%c' pressed\n", __FUNCTION__, key);
    for_each_domain ( d )
        gnttab_usage_print(d);
    printk("%s ] done\n", __FUNCTION__);
}

static struct keyhandler gnttab_usage_print_all_keyhandler = {
    .diagnostic = 1,
    .u.fn = gnttab_usage_print_all,
    .desc = "print grant table usage"
};

static int __init gnttab_usage_init(void)
{
    register_keyhandler('g', &gnttab_usage_print_all_keyhandler);
    return 0;
}
__initcall(gnttab_usage_init);

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
