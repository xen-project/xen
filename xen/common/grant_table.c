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
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/err.h>
#include <xen/iocap.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/mm.h>
#include <xen/event.h>
#include <xen/trace.h>
#include <xen/grant_table.h>
#include <xen/guest_access.h>
#include <xen/domain_page.h>
#include <xen/iommu.h>
#include <xen/paging.h>
#include <xen/keyhandler.h>
#include <xen/vmap.h>
#include <xsm/xsm.h>
#include <asm/flushtlb.h>

/* 
 * This option is deprecated, use gnttab_max_frames and
 * gnttab_max_maptrack_frames instead.
 */
static unsigned int __initdata max_nr_grant_frames;
integer_param("gnttab_max_nr_frames", max_nr_grant_frames);

unsigned int __read_mostly max_grant_frames;
integer_param("gnttab_max_frames", max_grant_frames);

/* The maximum number of grant mappings is defined as a multiplier of the
 * maximum number of grant table entries. This defines the multiplier used.
 * Pretty arbitrary. [POLICY]
 * As gnttab_max_nr_frames has been deprecated, this multiplier is deprecated too.
 * New options allow to set max_maptrack_frames and
 * map_grant_table_frames independently.
 */
#define DEFAULT_MAX_MAPTRACK_FRAMES 1024

static unsigned int __read_mostly max_maptrack_frames;
integer_param("gnttab_max_maptrack_frames", max_maptrack_frames);

/*
 * Note that the three values below are effectively part of the ABI, even if
 * we don't need to make them a formal part of it: A guest suspended for
 * migration in the middle of a continuation would fail to work if resumed on
 * a hypervisor using different values.
 */
#define GNTTABOP_CONTINUATION_ARG_SHIFT 12
#define GNTTABOP_CMD_MASK               ((1<<GNTTABOP_CONTINUATION_ARG_SHIFT)-1)
#define GNTTABOP_ARG_MASK               (~GNTTABOP_CMD_MASK)

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
    u16 done;
    unsigned long frame;
    struct domain *rd;
    grant_ref_t ref;
};

/* Number of unmap operations that are done between each tlb flush */
#define GNTTAB_UNMAP_BATCH_SIZE 32


#define PIN_FAIL(_lbl, _rc, _f, _a...)          \
    do {                                        \
        gdprintk(XENLOG_WARNING, _f, ## _a );   \
        rc = (_rc);                             \
        goto _lbl;                              \
    } while ( 0 )

/*
 * Tracks a mapping of another domain's grant reference. Each domain has a
 * table of these, indexes into which are returned as a 'mapping handle'.
 */
struct grant_mapping {
    u32      ref;           /* grant ref */
    u16      flags;         /* 0-4: GNTMAP_* ; 5-15: unused */
    domid_t  domid;         /* granting domain */
    u32      vcpu;          /* vcpu which created the grant mapping */
    u32      pad;           /* round size to a power of 2 */
};

#define MAPTRACK_PER_PAGE (PAGE_SIZE / sizeof(struct grant_mapping))
#define maptrack_entry(t, e) \
    ((t)->maptrack[(e)/MAPTRACK_PER_PAGE][(e)%MAPTRACK_PER_PAGE])

static inline unsigned int
nr_maptrack_frames(struct grant_table *t)
{
    return t->maptrack_limit / MAPTRACK_PER_PAGE;
}

#define MAPTRACK_TAIL (~0u)

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

/* Active grant entry - used for shadowing GTF_permit_access grants. */
struct active_grant_entry {
    u32           pin;    /* Reference count information.             */
    domid_t       domid;  /* Domain being granted access.             */
    struct domain *trans_domain;
    uint32_t      trans_gref;
    unsigned long frame;  /* Frame being granted.                     */
    unsigned long gfn;    /* Guest's idea of the frame being granted. */
    unsigned      is_sub_page:1; /* True if this is a sub-page grant. */
    unsigned      start:15; /* For sub-page grants, the start offset
                               in the page.                           */
    unsigned      length:16; /* For sub-page grants, the length of the
                                grant.                                */
    spinlock_t    lock;      /* lock to protect access of this entry.
                                see docs/misc/grant-tables.txt for
                                locking protocol                      */
};

#define ACGNT_PER_PAGE (PAGE_SIZE / sizeof(struct active_grant_entry))
#define _active_entry(t, e) \
    ((t)->active[(e)/ACGNT_PER_PAGE][(e)%ACGNT_PER_PAGE])

DEFINE_PERCPU_RWLOCK_GLOBAL(grant_rwlock);

static inline void gnttab_flush_tlb(const struct domain *d)
{
    if ( !paging_mode_external(d) )
        flush_tlb_mask(d->domain_dirty_cpumask);
}

static inline unsigned int
num_act_frames_from_sha_frames(const unsigned int num)
{
    /* How many frames are needed for the active grant table,
     * given the size of the shared grant table? */
    unsigned int sha_per_page = PAGE_SIZE / sizeof(grant_entry_v1_t);
    unsigned int num_sha_entries = num * sha_per_page;
    return (num_sha_entries + (ACGNT_PER_PAGE - 1)) / ACGNT_PER_PAGE;
}

#define max_nr_active_grant_frames \
    num_act_frames_from_sha_frames(max_grant_frames)

static inline unsigned int
nr_active_grant_frames(struct grant_table *gt)
{
    return num_act_frames_from_sha_frames(nr_grant_frames(gt));
}

static inline struct active_grant_entry *
active_entry_acquire(struct grant_table *t, grant_ref_t e)
{
    struct active_grant_entry *act;

    /*
     * The grant table for the active entry should be locked but the
     * percpu rwlock cannot be checked for read lock without race conditions
     * or high overhead so we cannot use an ASSERT
     *
     *   ASSERT(rw_is_locked(&t->lock));
     */

    act = &_active_entry(t, e);
    spin_lock(&act->lock);

    return act;
}

static inline void active_entry_release(struct active_grant_entry *act)
{
    spin_unlock(&act->lock);
}

/* Check if the page has been paged out, or needs unsharing. 
   If rc == GNTST_okay, *page contains the page struct with a ref taken.
   Caller must do put_page(*page).
   If any error, *page = NULL, *frame = INVALID_MFN, no ref taken. */
static int __get_paged_frame(unsigned long gfn, unsigned long *frame, struct page_info **page,
                                int readonly, struct domain *rd)
{
    int rc = GNTST_okay;
#if defined(P2M_PAGED_TYPES) || defined(P2M_SHARED_TYPES)
    p2m_type_t p2mt;

    *page = get_page_from_gfn(rd, gfn, &p2mt, 
                              (readonly) ? P2M_ALLOC : P2M_UNSHARE);
    if ( !(*page) )
    {
        *frame = mfn_x(INVALID_MFN);
        if ( p2m_is_shared(p2mt) )
            return GNTST_eagain;
        if ( p2m_is_paging(p2mt) )
        {
            p2m_mem_paging_populate(rd, gfn);
            return GNTST_eagain;
        }
        return GNTST_bad_page;
    }
    *frame = page_to_mfn(*page);
#else
    *frame = mfn_x(gfn_to_mfn(rd, _gfn(gfn)));
    *page = mfn_valid(*frame) ? mfn_to_page(*frame) : NULL;
    if ( (!(*page)) || (!get_page(*page, rd)) )
    {
        *frame = mfn_x(INVALID_MFN);
        *page = NULL;
        rc = GNTST_bad_page;
    }
#endif

    return rc;
}

static inline void
double_gt_lock(struct grant_table *lgt, struct grant_table *rgt)
{
    /*
     * See mapkind() for why the write lock is also required for the
     * remote domain.
     */
    if ( lgt < rgt )
    {
        grant_write_lock(lgt);
        grant_write_lock(rgt);
    }
    else
    {
        if ( lgt != rgt )
            grant_write_lock(rgt);
        grant_write_lock(lgt);
    }
}

static inline void
double_gt_unlock(struct grant_table *lgt, struct grant_table *rgt)
{
    grant_write_unlock(lgt);
    if ( lgt != rgt )
        grant_write_unlock(rgt);
}

static inline int
__get_maptrack_handle(
    struct grant_table *t,
    struct vcpu *v)
{
    unsigned int head, next, prev_head;

    spin_lock(&v->maptrack_freelist_lock);

    do {
        /* No maptrack pages allocated for this VCPU yet? */
        head = read_atomic(&v->maptrack_head);
        if ( unlikely(head == MAPTRACK_TAIL) )
        {
            spin_unlock(&v->maptrack_freelist_lock);
            return -1;
        }

        /*
         * Always keep one entry in the free list to make it easier to
         * add free entries to the tail.
         */
        next = read_atomic(&maptrack_entry(t, head).ref);
        if ( unlikely(next == MAPTRACK_TAIL) )
        {
            spin_unlock(&v->maptrack_freelist_lock);
            return -1;
        }

        prev_head = head;
        head = cmpxchg(&v->maptrack_head, prev_head, next);
    } while ( head != prev_head );

    spin_unlock(&v->maptrack_freelist_lock);

    return head;
}

/*
 * Try to "steal" a free maptrack entry from another VCPU.
 *
 * A stolen entry is transferred to the thief, so the number of
 * entries for each VCPU should tend to the usage pattern.
 *
 * To avoid having to atomically count the number of free entries on
 * each VCPU and to avoid two VCPU repeatedly stealing entries from
 * each other, the initial victim VCPU is selected randomly.
 */
static int steal_maptrack_handle(struct grant_table *t,
                                 const struct vcpu *curr)
{
    const struct domain *currd = curr->domain;
    unsigned int first, i;

    /* Find an initial victim. */
    first = i = get_random() % currd->max_vcpus;

    do {
        if ( currd->vcpu[i] )
        {
            int handle;

            handle = __get_maptrack_handle(t, currd->vcpu[i]);
            if ( handle != -1 )
            {
                maptrack_entry(t, handle).vcpu = curr->vcpu_id;
                return handle;
            }
        }

        i++;
        if ( i == currd->max_vcpus )
            i = 0;
    } while ( i != first );

    /* No free handles on any VCPU. */
    return -1;
}

static inline void
put_maptrack_handle(
    struct grant_table *t, int handle)
{
    struct domain *currd = current->domain;
    struct vcpu *v;
    unsigned int prev_tail, cur_tail;

    /* 1. Set entry to be a tail. */
    maptrack_entry(t, handle).ref = MAPTRACK_TAIL;

    /* 2. Add entry to the tail of the list on the original VCPU. */
    v = currd->vcpu[maptrack_entry(t, handle).vcpu];

    spin_lock(&v->maptrack_freelist_lock);

    cur_tail = read_atomic(&v->maptrack_tail);
    do {
        prev_tail = cur_tail;
        cur_tail = cmpxchg(&v->maptrack_tail, prev_tail, handle);
    } while ( cur_tail != prev_tail );

    /* 3. Update the old tail entry to point to the new entry. */
    write_atomic(&maptrack_entry(t, prev_tail).ref, handle);

    spin_unlock(&v->maptrack_freelist_lock);
}

static inline int
get_maptrack_handle(
    struct grant_table *lgt)
{
    struct vcpu          *curr = current;
    unsigned int          i, head;
    grant_handle_t        handle;
    struct grant_mapping *new_mt = NULL;

    handle = __get_maptrack_handle(lgt, curr);
    if ( likely(handle != -1) )
        return handle;

    spin_lock(&lgt->maptrack_lock);

    /*
     * If we've run out of handles and still have frame headroom, try
     * allocating a new maptrack frame.  If there is no headroom, or we're
     * out of memory, try stealing an entry from another VCPU (in case the
     * guest isn't mapping across its VCPUs evenly).
     */
    if ( nr_maptrack_frames(lgt) < max_maptrack_frames )
        new_mt = alloc_xenheap_page();

    if ( !new_mt )
    {
        spin_unlock(&lgt->maptrack_lock);

        /*
         * Uninitialized free list? Steal an extra entry for the tail
         * sentinel.
         */
        if ( curr->maptrack_tail == MAPTRACK_TAIL )
        {
            handle = steal_maptrack_handle(lgt, curr);
            if ( handle == -1 )
                return -1;
            spin_lock(&curr->maptrack_freelist_lock);
            maptrack_entry(lgt, handle).ref = MAPTRACK_TAIL;
            curr->maptrack_tail = handle;
            if ( curr->maptrack_head == MAPTRACK_TAIL )
                write_atomic(&curr->maptrack_head, handle);
            spin_unlock(&curr->maptrack_freelist_lock);
        }
        return steal_maptrack_handle(lgt, curr);
    }

    clear_page(new_mt);

    /*
     * Use the first new entry and add the remaining entries to the
     * head of the free list.
     */
    handle = lgt->maptrack_limit;

    for ( i = 0; i < MAPTRACK_PER_PAGE; i++ )
    {
        new_mt[i].ref = handle + i + 1;
        new_mt[i].vcpu = curr->vcpu_id;
    }

    /* Set tail directly if this is the first page for this VCPU. */
    if ( curr->maptrack_tail == MAPTRACK_TAIL )
        curr->maptrack_tail = handle + MAPTRACK_PER_PAGE - 1;

    lgt->maptrack[nr_maptrack_frames(lgt)] = new_mt;
    smp_wmb();
    lgt->maptrack_limit += MAPTRACK_PER_PAGE;

    spin_unlock(&lgt->maptrack_lock);
    spin_lock(&curr->maptrack_freelist_lock);

    do {
        new_mt[i - 1].ref = read_atomic(&curr->maptrack_head);
        head = cmpxchg(&curr->maptrack_head, new_mt[i - 1].ref, handle + 1);
    } while ( head != new_mt[i - 1].ref );

    spin_unlock(&curr->maptrack_freelist_lock);

    return handle;
}

/* Number of grant table entries. Caller must hold d's grant table lock. */
static unsigned int nr_grant_entries(struct grant_table *gt)
{
    switch ( gt->gt_version )
    {
#define f2e(nr, ver) (((nr) << PAGE_SHIFT) / sizeof(grant_entry_v##ver##_t))
    case 1:
        BUILD_BUG_ON(f2e(INITIAL_NR_GRANT_FRAMES, 1) <
                     GNTTAB_NR_RESERVED_ENTRIES);
        return f2e(nr_grant_frames(gt), 1);
    case 2:
        BUILD_BUG_ON(f2e(INITIAL_NR_GRANT_FRAMES, 2) <
                     GNTTAB_NR_RESERVED_ENTRIES);
        return f2e(nr_grant_frames(gt), 2);
#undef f2e
    }

    return 0;
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
    smp_mb();

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
            gnttab_clear_flag(_GTF_writing, status);
            gnttab_clear_flag(_GTF_reading, status);
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

static int grant_map_exists(const struct domain *ld,
                            struct grant_table *rgt,
                            unsigned long mfn,
                            unsigned int *ref_count)
{
    unsigned int ref, max_iter;
    
    /*
     * The remote grant table should be locked but the percpu rwlock
     * cannot be checked for read lock without race conditions or high
     * overhead so we cannot use an ASSERT
     *
     *   ASSERT(rw_is_locked(&rgt->lock));
     */

    max_iter = min(*ref_count + (1 << GNTTABOP_CONTINUATION_ARG_SHIFT),
                   nr_grant_entries(rgt));
    for ( ref = *ref_count; ref < max_iter; ref++ )
    {
        struct active_grant_entry *act;
        bool_t exists;

        act = active_entry_acquire(rgt, ref);

        exists = act->pin
            && act->domid == ld->domain_id
            && act->frame == mfn;

        active_entry_release(act);

        if ( exists )
            return 0;
    }

    if ( ref < nr_grant_entries(rgt) )
    {
        *ref_count = ref;
        return 1;
    }

    return -EINVAL;
}

#define MAPKIND_READ 1
#define MAPKIND_WRITE 2
static unsigned int mapkind(
    struct grant_table *lgt, const struct domain *rd, unsigned long mfn)
{
    struct grant_mapping *map;
    grant_handle_t handle;
    unsigned int kind = 0;

    /*
     * Must have the local domain's grant table write lock when
     * iterating over its maptrack entries.
     */
    ASSERT(percpu_rw_is_write_locked(&lgt->lock));
    /*
     * Must have the remote domain's grant table write lock while
     * counting its active entries.
     */
    ASSERT(percpu_rw_is_write_locked(&rd->grant_table->lock));

    for ( handle = 0; !(kind & MAPKIND_WRITE) &&
                      handle < lgt->maptrack_limit; handle++ )
    {
        smp_rmb();
        map = &maptrack_entry(lgt, handle);
        if ( !(map->flags & (GNTMAP_device_map|GNTMAP_host_map)) ||
             map->domid != rd->domain_id )
            continue;
        if ( _active_entry(rd->grant_table, map->ref).frame == mfn )
            kind |= map->flags & GNTMAP_readonly ?
                    MAPKIND_READ : MAPKIND_WRITE;
    }

    return kind;
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
    struct domain *ld, *rd, *owner = NULL;
    struct grant_table *lgt, *rgt;
    struct vcpu   *led;
    int            handle;
    unsigned long  frame = 0;
    struct page_info *pg = NULL;
    int            rc = GNTST_okay;
    u32            old_pin;
    u32            act_pin;
    unsigned int   cache_flags, refcnt = 0, typecnt = 0;
    struct active_grant_entry *act = NULL;
    struct grant_mapping *mt;
    grant_entry_header_t *shah;
    uint16_t *status;
    bool_t need_iommu;

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

    rc = xsm_grant_mapref(XSM_HOOK, ld, rd, op->flags);
    if ( rc )
    {
        rcu_unlock_domain(rd);
        op->status = GNTST_permission_denied;
        return;
    }

    lgt = ld->grant_table;
    if ( unlikely((handle = get_maptrack_handle(lgt)) == -1) )
    {
        rcu_unlock_domain(rd);
        gdprintk(XENLOG_INFO, "Failed to obtain maptrack handle.\n");
        op->status = GNTST_no_device_space;
        return;
    }

    rgt = rd->grant_table;
    grant_read_lock(rgt);

    /* Bounds check on the grant ref */
    if ( unlikely(op->ref >= nr_grant_entries(rgt)))
        PIN_FAIL(unlock_out, GNTST_bad_gntref, "Bad ref (%d).\n", op->ref);

    act = active_entry_acquire(rgt, op->ref);
    shah = shared_entry_header(rgt, op->ref);
    status = rgt->gt_version == 1 ? &shah->flags : &status_entry(rgt, op->ref);

    /* If already pinned, check the active domid and avoid refcnt overflow. */
    if ( act->pin &&
         ((act->domid != ld->domain_id) ||
          (act->pin & 0x80808080U) != 0 ||
          (act->is_sub_page)) )
        PIN_FAIL(act_release_out, GNTST_general_error,
                 "Bad domain (%d != %d), or risk of counter overflow %08x, or subpage %d\n",
                 act->domid, ld->domain_id, act->pin, act->is_sub_page);

    if ( !act->pin ||
         (!(op->flags & GNTMAP_readonly) &&
          !(act->pin & (GNTPIN_hstw_mask|GNTPIN_devw_mask))) )
    {
        if ( (rc = _set_status(rgt->gt_version, ld->domain_id,
                               op->flags & GNTMAP_readonly,
                               1, shah, act, status) ) != GNTST_okay )
            goto act_release_out;

        if ( !act->pin )
        {
            unsigned long gfn = rgt->gt_version == 1 ?
                                shared_entry_v1(rgt, op->ref).frame :
                                shared_entry_v2(rgt, op->ref).full_page.frame;

            rc = __get_paged_frame(gfn, &frame, &pg, 
                                    !!(op->flags & GNTMAP_readonly), rd);
            if ( rc != GNTST_okay )
                goto unlock_out_clear;
            act->gfn = gfn;
            act->domid = ld->domain_id;
            act->frame = frame;
            act->start = 0;
            act->length = PAGE_SIZE;
            act->is_sub_page = 0;
            act->trans_domain = rd;
            act->trans_gref = op->ref;
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

    active_entry_release(act);
    grant_read_unlock(rgt);

    /* pg may be set, with a refcount included, from __get_paged_frame */
    if ( !pg )
    {
        pg = mfn_valid(frame) ? mfn_to_page(frame) : NULL;
        if ( pg )
            owner = page_get_owner_and_reference(pg);
    }
    else
        owner = page_get_owner(pg);

    if ( owner )
        refcnt++;

    if ( !pg || (owner == dom_io) )
    {
        /* Only needed the reference to confirm dom_io ownership. */
        if ( pg )
        {
            put_page(pg);
            refcnt--;
        }

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

        if ( op->flags & GNTMAP_host_map )
        {
            rc = create_grant_host_mapping(op->host_addr, frame, op->flags,
                                           cache_flags);
            if ( rc != GNTST_okay )
                goto undo_out;
        }
    }
    else if ( owner == rd || owner == dom_cow )
    {
        if ( (op->flags & GNTMAP_device_map) && !(op->flags & GNTMAP_readonly) )
        {
            if ( (owner == dom_cow) ||
                 !get_page_type(pg, PGT_writable_page) )
                goto could_not_pin;
            typecnt++;
        }

        if ( op->flags & GNTMAP_host_map )
        {
            /*
             * Only need to grab another reference if device_map claimed
             * the other one.
             */
            if ( op->flags & GNTMAP_device_map )
            {
                if ( !get_page(pg, rd) )
                    goto could_not_pin;
                refcnt++;
            }

            if ( gnttab_host_mapping_get_page_type(op->flags & GNTMAP_readonly,
                                                   ld, rd) )
            {
                if ( (owner == dom_cow) ||
                     !get_page_type(pg, PGT_writable_page) )
                    goto could_not_pin;
                typecnt++;
            }

            rc = create_grant_host_mapping(op->host_addr, frame, op->flags, 0);
            if ( rc != GNTST_okay )
                goto undo_out;
        }
    }
    else
    {
    could_not_pin:
        if ( !rd->is_dying )
            gdprintk(XENLOG_WARNING, "Could not pin grant frame %lx\n",
                     frame);
        rc = GNTST_general_error;
        goto undo_out;
    }

    need_iommu = gnttab_need_iommu_mapping(ld);
    if ( need_iommu )
    {
        unsigned int kind;
        int err = 0;

        double_gt_lock(lgt, rgt);

        /* We're not translated, so we know that gmfns and mfns are
           the same things, so the IOMMU entry is always 1-to-1. */
        kind = mapkind(lgt, rd, frame);
        if ( (act_pin & (GNTPIN_hstw_mask|GNTPIN_devw_mask)) &&
             !(old_pin & (GNTPIN_hstw_mask|GNTPIN_devw_mask)) )
        {
            if ( !(kind & MAPKIND_WRITE) )
                err = iommu_map_page(ld, frame, frame,
                                     IOMMUF_readable|IOMMUF_writable);
        }
        else if ( act_pin && !old_pin )
        {
            if ( !kind )
                err = iommu_map_page(ld, frame, frame, IOMMUF_readable);
        }
        if ( err )
        {
            double_gt_unlock(lgt, rgt);
            rc = GNTST_general_error;
            goto undo_out;
        }
    }

    TRACE_1D(TRC_MEM_PAGE_GRANT_MAP, op->dom);

    /*
     * All maptrack entry users check mt->flags first before using the
     * other fields so just ensure the flags field is stored last.
     *
     * However, if gnttab_need_iommu_mapping() then this would race
     * with a concurrent mapcount() call (on an unmap, for example)
     * and a lock is required.
     */
    mt = &maptrack_entry(lgt, handle);
    mt->domid = op->dom;
    mt->ref   = op->ref;
    wmb();
    write_atomic(&mt->flags, op->flags);

    if ( need_iommu )
        double_gt_unlock(lgt, rgt);

    op->dev_bus_addr = (u64)frame << PAGE_SHIFT;
    op->handle       = handle;
    op->status       = GNTST_okay;

    rcu_unlock_domain(rd);
    return;

 undo_out:
    while ( typecnt-- )
        put_page_type(pg);

    while ( refcnt-- )
        put_page(pg);

    grant_read_lock(rgt);

    act = active_entry_acquire(rgt, op->ref);

    if ( op->flags & GNTMAP_device_map )
        act->pin -= (op->flags & GNTMAP_readonly) ?
            GNTPIN_devr_inc : GNTPIN_devw_inc;
    if ( op->flags & GNTMAP_host_map )
        act->pin -= (op->flags & GNTMAP_readonly) ?
            GNTPIN_hstr_inc : GNTPIN_hstw_inc;
 
 unlock_out_clear:
    if ( !(op->flags & GNTMAP_readonly) &&
         !(act->pin & (GNTPIN_hstw_mask|GNTPIN_devw_mask)) )
        gnttab_clear_flag(_GTF_writing, status);

    if ( !act->pin )
        gnttab_clear_flag(_GTF_reading, status);

 act_release_out:
    active_entry_release(act);

 unlock_out:
    grant_read_unlock(rgt);
    op->status = rc;
    put_maptrack_handle(lgt, handle);
    rcu_unlock_domain(rd);
}

static long
gnttab_map_grant_ref(
    XEN_GUEST_HANDLE_PARAM(gnttab_map_grant_ref_t) uop, unsigned int count)
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
    struct grant_table *lgt, *rgt;
    struct active_grant_entry *act;
    s16              rc = 0;
    struct grant_mapping *map;
    unsigned int flags;
    bool put_handle = false;

    ld = current->domain;
    lgt = ld->grant_table;

    if ( unlikely(op->handle >= lgt->maptrack_limit) )
    {
        gdprintk(XENLOG_INFO, "Bad handle (%d).\n", op->handle);
        op->status = GNTST_bad_handle;
        return;
    }

    smp_rmb();
    map = &maptrack_entry(lgt, op->handle);

    grant_read_lock(lgt);

    if ( unlikely(!read_atomic(&map->flags)) )
    {
        grant_read_unlock(lgt);
        gdprintk(XENLOG_INFO, "Zero flags for handle (%d).\n", op->handle);
        op->status = GNTST_bad_handle;
        return;
    }

    dom = map->domid;
    grant_read_unlock(lgt);

    if ( unlikely((rd = rcu_lock_domain_by_id(dom)) == NULL) )
    {
        /* This can happen when a grant is implicitly unmapped. */
        gdprintk(XENLOG_INFO, "Could not find domain %d\n", dom);
        domain_crash(ld); /* naughty... */
        return;
    }

    rc = xsm_grant_unmapref(XSM_HOOK, ld, rd);
    if ( rc )
    {
        rcu_unlock_domain(rd);
        op->status = GNTST_permission_denied;
        return;
    }

    TRACE_1D(TRC_MEM_PAGE_GRANT_UNMAP, dom);

    rgt = rd->grant_table;

    grant_read_lock(rgt);

    if ( rgt->gt_version == 0 )
    {
        /*
         * This ought to be impossible, as such a mapping should not have
         * been established (see the nr_grant_entries(rgt) bounds check in
         * __gnttab_map_grant_ref()). Doing this check only in
         * __gnttab_unmap_common_complete() - as it used to be done - would,
         * however, be too late.
         */
        rc = GNTST_bad_gntref;
        flags = 0;
        goto unlock_out;
    }

    op->rd = rd;
    op->ref = map->ref;

    /*
     * We can't assume there was no racing unmap for this maptrack entry,
     * and hence we can't assume map->ref is valid for rd. While the checks
     * below (with the active entry lock held) will reject any such racing
     * requests, we still need to make sure we don't attempt to acquire an
     * invalid lock.
     */
    smp_rmb();
    if ( unlikely(op->ref >= nr_grant_entries(rgt)) )
    {
        gdprintk(XENLOG_WARNING, "Unstable handle %#x\n", op->handle);
        rc = GNTST_bad_handle;
        flags = 0;
        goto unlock_out;
    }

    act = active_entry_acquire(rgt, op->ref);

    /*
     * Note that we (ab)use the active entry lock here to protect against
     * multiple unmaps of the same mapping here. We don't want to hold lgt's
     * lock, and we only hold rgt's lock for reading (but the latter wouldn't
     * be the right one anyway). Hence the easiest is to rely on a lock we
     * hold anyway; see docs/misc/grant-tables.txt's "Locking" section.
     */

    flags = read_atomic(&map->flags);
    smp_rmb();
    if ( unlikely(!flags) || unlikely(map->domid != dom) ||
         unlikely(map->ref != op->ref) )
    {
        gdprintk(XENLOG_WARNING, "Unstable handle %u\n", op->handle);
        rc = GNTST_bad_handle;
        goto act_release_out;
    }

    op->frame = act->frame;

    if ( op->dev_bus_addr &&
         unlikely(op->dev_bus_addr != pfn_to_paddr(act->frame)) )
        PIN_FAIL(act_release_out, GNTST_general_error,
                 "Bus address doesn't match gntref (%"PRIx64" != %"PRIpaddr")\n",
                 op->dev_bus_addr, pfn_to_paddr(act->frame));

    if ( op->host_addr && (flags & GNTMAP_host_map) )
    {
        if ( (rc = replace_grant_host_mapping(op->host_addr,
                                              op->frame, op->new_addr, 
                                              flags)) < 0 )
            goto act_release_out;

        map->flags &= ~GNTMAP_host_map;
        op->done |= GNTMAP_host_map | (flags & GNTMAP_readonly);
    }

    if ( op->dev_bus_addr && (flags & GNTMAP_device_map) )
    {
        map->flags &= ~GNTMAP_device_map;
        op->done |= GNTMAP_device_map | (flags & GNTMAP_readonly);
    }

    if ( !(map->flags & (GNTMAP_device_map|GNTMAP_host_map)) )
    {
        map->flags = 0;
        put_handle = true;
    }

 act_release_out:
    active_entry_release(act);
 unlock_out:
    grant_read_unlock(rgt);

    if ( put_handle )
        put_maptrack_handle(lgt, op->handle);

    if ( rc == GNTST_okay && gnttab_need_iommu_mapping(ld) )
    {
        unsigned int kind;
        int err = 0;

        double_gt_lock(lgt, rgt);

        kind = mapkind(lgt, rd, op->frame);
        if ( !kind )
            err = iommu_unmap_page(ld, op->frame);
        else if ( !(kind & MAPKIND_WRITE) )
            err = iommu_map_page(ld, op->frame, op->frame, IOMMUF_readable);

        double_gt_unlock(lgt, rgt);

        if ( err )
            rc = GNTST_general_error;
    }

    /* If just unmapped a writable mapping, mark as dirtied */
    if ( rc == GNTST_okay && !(flags & GNTMAP_readonly) )
         gnttab_mark_dirty(rd, op->frame);

    op->status = rc;
    rcu_unlock_domain(rd);
}

static void
__gnttab_unmap_common_complete(struct gnttab_unmap_common *op)
{
    struct domain *ld, *rd = op->rd;
    struct grant_table *rgt;
    struct active_grant_entry *act;
    grant_entry_header_t *sha;
    struct page_info *pg;
    uint16_t *status;

    if ( !op->done )
    { 
        /* __gntab_unmap_common() didn't do anything - nothing to complete. */
        return;
    }

    ld = current->domain;

    rcu_lock_domain(rd);
    rgt = rd->grant_table;

    grant_read_lock(rgt);

    act = active_entry_acquire(rgt, op->ref);
    sha = shared_entry_header(rgt, op->ref);

    if ( rgt->gt_version == 1 )
        status = &sha->flags;
    else
        status = &status_entry(rgt, op->ref);

    pg = mfn_to_page(op->frame);

    if ( op->done & GNTMAP_device_map )
    {
        if ( !is_iomem_page(act->frame) )
        {
            if ( op->done & GNTMAP_readonly )
                put_page(pg);
            else
                put_page_and_type(pg);
        }

        ASSERT(act->pin & (GNTPIN_devw_mask | GNTPIN_devr_mask));
        if ( op->done & GNTMAP_readonly )
            act->pin -= GNTPIN_devr_inc;
        else
            act->pin -= GNTPIN_devw_inc;
    }

    if ( op->done & GNTMAP_host_map )
    {
        if ( !is_iomem_page(op->frame) ) 
        {
            if ( gnttab_host_mapping_get_page_type(op->done & GNTMAP_readonly,
                                                   ld, rd) )
                put_page_type(pg);
            put_page(pg);
        }

        ASSERT(act->pin & (GNTPIN_hstw_mask | GNTPIN_hstr_mask));
        if ( op->done & GNTMAP_readonly )
            act->pin -= GNTPIN_hstr_inc;
        else
            act->pin -= GNTPIN_hstw_inc;
    }

    if ( ((act->pin & (GNTPIN_devw_mask|GNTPIN_hstw_mask)) == 0) &&
         !(op->done & GNTMAP_readonly) )
        gnttab_clear_flag(_GTF_writing, status);

    if ( act->pin == 0 )
        gnttab_clear_flag(_GTF_reading, status);

    active_entry_release(act);
    grant_read_unlock(rgt);

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
    common->done = 0;
    common->new_addr = 0;
    common->rd = NULL;
    common->frame = 0;

    __gnttab_unmap_common(common);
    op->status = common->status;
}


static long
gnttab_unmap_grant_ref(
    XEN_GUEST_HANDLE_PARAM(gnttab_unmap_grant_ref_t) uop, unsigned int count)
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
            if ( unlikely(__copy_from_guest(&op, uop, 1)) )
                goto fault;
            __gnttab_unmap_grant_ref(&op, &(common[i]));
            ++partial_done;
            if ( unlikely(__copy_field_to_guest(uop, &op, status)) )
                goto fault;
            guest_handle_add_offset(uop, 1);
        }

        gnttab_flush_tlb(current->domain);

        for ( i = 0; i < partial_done; i++ )
            __gnttab_unmap_common_complete(&(common[i]));

        count -= c;
        done += c;

        if (count && hypercall_preempt_check())
            return done;
    }
     
    return 0;

fault:
    gnttab_flush_tlb(current->domain);

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
    common->done = 0;
    common->dev_bus_addr = 0;
    common->rd = NULL;
    common->frame = 0;

    __gnttab_unmap_common(common);
    op->status = common->status;
}

static long
gnttab_unmap_and_replace(
    XEN_GUEST_HANDLE_PARAM(gnttab_unmap_and_replace_t) uop, unsigned int count)
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
            if ( unlikely(__copy_from_guest(&op, uop, 1)) )
                goto fault;
            __gnttab_unmap_and_replace(&op, &(common[i]));
            ++partial_done;
            if ( unlikely(__copy_field_to_guest(uop, &op, status)) )
                goto fault;
            guest_handle_add_offset(uop, 1);
        }
        
        gnttab_flush_tlb(current->domain);
        
        for ( i = 0; i < partial_done; i++ )
            __gnttab_unmap_common_complete(&(common[i]));

        count -= c;
        done += c;

        if (count && hypercall_preempt_check())
            return done;
    }

    return 0;

fault:
    gnttab_flush_tlb(current->domain);

    for ( i = 0; i < partial_done; i++ )
        __gnttab_unmap_common_complete(&(common[i]));
    return -EFAULT;    
}

static int
gnttab_populate_status_frames(struct domain *d, struct grant_table *gt,
                              unsigned int req_nr_frames)
{
    unsigned i;
    unsigned req_status_frames;

    req_status_frames = grant_to_status_frames(req_nr_frames);
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
        struct page_info *pg = virt_to_page(gt->status[i]);

        BUG_ON(page_get_owner(pg) != d);
        if ( test_and_clear_bit(_PGC_allocated, &pg->count_info) )
            put_page(pg);
        BUG_ON(pg->count_info & ~PGC_xen_heap);
        free_xenheap_page(gt->status[i]);
        gt->status[i] = NULL;
    }
    gt->nr_status_frames = 0;
}

/*
 * Grow the grant table. The caller must hold the grant table's
 * write lock before calling this function.
 */
int
gnttab_grow_table(struct domain *d, unsigned int req_nr_frames)
{
    struct grant_table *gt = d->grant_table;
    unsigned int i, j;

    ASSERT(req_nr_frames <= max_grant_frames);

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
        for ( j = 0; j < ACGNT_PER_PAGE; j++ )
            spin_lock_init(&gt->active[i][j].lock);
    }

    /* Shared */
    for ( i = nr_grant_frames(gt); i < req_nr_frames; i++ )
    {
        if ( (gt->shared_raw[i] = alloc_xenheap_page()) == NULL )
            goto shared_alloc_failed;
        clear_page(gt->shared_raw[i]);
    }

    /* Status pages - version 2 */
    if (gt->gt_version > 1)
    {
        if ( gnttab_populate_status_frames(d, gt, req_nr_frames) )
            goto shared_alloc_failed;
    }

    /* Share the new shared frames with the recipient domain */
    for ( i = nr_grant_frames(gt); i < req_nr_frames; i++ )
        gnttab_create_shared_page(d, gt, i);
    gt->nr_grant_frames = req_nr_frames;

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
    XEN_GUEST_HANDLE_PARAM(gnttab_setup_table_t) uop, unsigned int count)
{
    struct gnttab_setup_table op;
    struct domain *d;
    struct grant_table *gt;
    int            i;
    xen_pfn_t  gmfn;

    if ( count != 1 )
        return -EINVAL;

    if ( unlikely(copy_from_guest(&op, uop, 1) != 0) )
    {
        gdprintk(XENLOG_INFO, "Fault while reading gnttab_setup_table_t.\n");
        return -EFAULT;
    }

    if ( unlikely(op.nr_frames > max_grant_frames) )
    {
        gdprintk(XENLOG_INFO, "Xen only supports up to %d grant-table frames"
                " per domain.\n",
                max_grant_frames);
        op.status = GNTST_general_error;
        goto out1;
    }

    if ( !guest_handle_okay(op.frame_list, op.nr_frames) )
        return -EFAULT;

    d = rcu_lock_domain_by_any_id(op.dom);
    if ( d == NULL )
    {
        gdprintk(XENLOG_INFO, "Bad domid %d.\n", op.dom);
        op.status = GNTST_bad_domain;
        goto out2;
    }

    if ( xsm_grant_setup(XSM_TARGET, current->domain, d) )
    {
        op.status = GNTST_permission_denied;
        goto out2;
    }

    gt = d->grant_table;
    grant_write_lock(gt);

    if ( gt->gt_version == 0 )
        gt->gt_version = 1;

    if ( (op.nr_frames > nr_grant_frames(gt) ||
          ((gt->gt_version > 1) &&
           (grant_to_status_frames(op.nr_frames) > nr_status_frames(gt)))) &&
         !gnttab_grow_table(d, op.nr_frames) )
    {
        gdprintk(XENLOG_INFO,
                 "Expand grant table to %u failed. Current: %u Max: %u\n",
                 op.nr_frames, nr_grant_frames(gt), max_grant_frames);
        op.status = GNTST_general_error;
        goto out3;
    }
 
    op.status = GNTST_okay;
    for ( i = 0; i < op.nr_frames; i++ )
    {
        gmfn = gnttab_shared_gmfn(d, gt, i);
        /* Grant tables cannot be shared */
        BUG_ON(SHARED_M2P(gmfn));
        if ( __copy_to_guest_offset(op.frame_list, i, &gmfn, 1) )
            op.status = GNTST_bad_virt_addr;
    }

 out3:
    grant_write_unlock(gt);
 out2:
    rcu_unlock_domain(d);
 out1:
    if ( unlikely(__copy_field_to_guest(uop, &op, status)) )
        return -EFAULT;

    return 0;
}

static long 
gnttab_query_size(
    XEN_GUEST_HANDLE_PARAM(gnttab_query_size_t) uop, unsigned int count)
{
    struct gnttab_query_size op;
    struct domain *d;
    int rc;

    if ( count != 1 )
        return -EINVAL;

    if ( unlikely(copy_from_guest(&op, uop, 1) != 0) )
    {
        gdprintk(XENLOG_INFO, "Fault while reading gnttab_query_size_t.\n");
        return -EFAULT;
    }

    d = rcu_lock_domain_by_any_id(op.dom);
    if ( d == NULL )
    {
        gdprintk(XENLOG_INFO, "Bad domid %d.\n", op.dom);
        op.status = GNTST_bad_domain;
        goto query_out;
    }

    rc = xsm_grant_query_size(XSM_TARGET, current->domain, d);
    if ( rc )
    {
        op.status = GNTST_permission_denied;
        goto query_out_unlock;
    }

    grant_read_lock(d->grant_table);

    op.nr_frames     = nr_grant_frames(d->grant_table);
    op.max_nr_frames = max_grant_frames;
    op.status        = GNTST_okay;

    grant_read_unlock(d->grant_table);

 
 query_out_unlock:
    rcu_unlock_domain(d);

 query_out:
    if ( unlikely(__copy_to_guest(uop, &op, 1)) )
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
    struct grant_table *rgt = rd->grant_table;
    grant_entry_header_t *sha;
    union grant_combo   scombo, prev_scombo, new_scombo;
    int                 retries = 0;

    grant_read_lock(rgt);

    if ( unlikely(ref >= nr_grant_entries(rgt)) )
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

    grant_read_unlock(rgt);
    return 1;

 fail:
    grant_read_unlock(rgt);
    return 0;
}

static long
gnttab_transfer(
    XEN_GUEST_HANDLE_PARAM(gnttab_transfer_t) uop, unsigned int count)
{
    struct domain *d = current->domain;
    struct domain *e;
    struct page_info *page;
    int i;
    struct gnttab_transfer gop;
    unsigned long mfn;
    unsigned int max_bitsize;
    struct active_grant_entry *act;

    for ( i = 0; i < count; i++ )
    {
        bool_t okay;
        int rc;

        if (i && hypercall_preempt_check())
            return i;

        /* Read from caller address space. */
        if ( unlikely(__copy_from_guest(&gop, uop, 1)) )
        {
            gdprintk(XENLOG_INFO, "gnttab_transfer: error reading req %d/%d\n",
                    i, count);
            return -EFAULT;
        }

#ifdef CONFIG_X86
        {
            p2m_type_t __p2mt;
            mfn = mfn_x(get_gfn_unshare(d, gop.mfn, &__p2mt));
            if ( p2m_is_shared(__p2mt) || !p2m_is_valid(__p2mt) )
                mfn = mfn_x(INVALID_MFN);
        }
#else
        mfn = mfn_x(gfn_to_mfn(d, _gfn(gop.mfn)));
#endif

        /* Check the passed page frame for basic validity. */
        if ( unlikely(!mfn_valid(mfn)) )
        { 
            put_gfn(d, gop.mfn);
            gdprintk(XENLOG_INFO, "gnttab_transfer: out-of-range %lx\n",
                    (unsigned long)gop.mfn);
            gop.status = GNTST_bad_page;
            goto copyback;
        }

        page = mfn_to_page(mfn);
        if ( unlikely(is_xen_heap_page(page)) )
        { 
            put_gfn(d, gop.mfn);
            gdprintk(XENLOG_INFO, "gnttab_transfer: xen frame %lx\n",
                    (unsigned long)gop.mfn);
            gop.status = GNTST_bad_page;
            goto copyback;
        }

        if ( steal_page(d, page, 0) < 0 )
        {
            put_gfn(d, gop.mfn);
            gop.status = GNTST_bad_page;
            goto copyback;
        }

        rc = guest_physmap_remove_page(d, _gfn(gop.mfn), _mfn(mfn), 0);
        gnttab_flush_tlb(d);
        if ( rc )
        {
            gdprintk(XENLOG_INFO,
                     "gnttab_transfer: can't remove GFN %"PRI_xen_pfn" (MFN %lx)\n",
                     gop.mfn, mfn);
            gop.status = GNTST_general_error;
            goto put_gfn_and_copyback;
        }

        /* Find the target domain. */
        if ( unlikely((e = rcu_lock_domain_by_id(gop.domid)) == NULL) )
        {
            gdprintk(XENLOG_INFO, "gnttab_transfer: can't find domain %d\n",
                    gop.domid);
            gop.status = GNTST_bad_domain;
            goto put_gfn_and_copyback;
        }

        if ( xsm_grant_transfer(XSM_HOOK, d, e) )
        {
            gop.status = GNTST_permission_denied;
        unlock_and_copyback:
            rcu_unlock_domain(e);
        put_gfn_and_copyback:
            put_gfn(d, gop.mfn);
            page->count_info &= ~(PGC_count_mask|PGC_allocated);
            free_domheap_page(page);
            goto copyback;
        }

        max_bitsize = domain_clamp_alloc_bitsize(
            e, e->grant_table->gt_version > 1 || paging_mode_translate(e)
               ? BITS_PER_LONG + PAGE_SHIFT : 32 + PAGE_SHIFT);
        if ( max_bitsize < BITS_PER_LONG + PAGE_SHIFT &&
             (mfn >> (max_bitsize - PAGE_SHIFT)) )
        {
            struct page_info *new_page;

            new_page = alloc_domheap_page(e, MEMF_no_owner |
                                             MEMF_bits(max_bitsize));
            if ( new_page == NULL )
            {
                gop.status = GNTST_address_too_big;
                goto unlock_and_copyback;
            }

            copy_domain_page(_mfn(page_to_mfn(new_page)), _mfn(mfn));

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
             unlikely(e->tot_pages >= e->max_pages) )
        {
            spin_unlock(&e->page_alloc_lock);

            if ( e->is_dying )
                gdprintk(XENLOG_INFO, "gnttab_transfer: "
                         "Transferee (d%d) is dying\n", e->domain_id);
            else
                gdprintk(XENLOG_INFO, "gnttab_transfer: "
                         "Transferee (d%d) has no headroom (tot %u, max %u)\n",
                         e->domain_id, e->tot_pages, e->max_pages);

            gop.status = GNTST_general_error;
            goto unlock_and_copyback;
        }

        /* Okay, add the page to 'e'. */
        if ( unlikely(domain_adjust_tot_pages(e, 1) == 1) )
            get_knownalive_domain(e);

        /*
         * We must drop the lock to avoid a possible deadlock in
         * gnttab_prepare_for_transfer.  We have reserved a page in e so can
         * safely drop the lock and re-aquire it later to add page to the
         * pagelist.
         */
        spin_unlock(&e->page_alloc_lock);
        okay = gnttab_prepare_for_transfer(e, d, gop.ref);
        spin_lock(&e->page_alloc_lock);

        if ( unlikely(!okay) || unlikely(e->is_dying) )
        {
            bool_t drop_dom_ref = !domain_adjust_tot_pages(e, -1);

            spin_unlock(&e->page_alloc_lock);

            if ( okay /* i.e. e->is_dying due to the surrounding if() */ )
                gdprintk(XENLOG_INFO, "gnttab_transfer: "
                         "Transferee (d%d) is now dying\n", e->domain_id);

            if ( drop_dom_ref )
                put_domain(e);
            gop.status = GNTST_general_error;
            goto unlock_and_copyback;
        }

        page_list_add_tail(page, &e->page_list);
        page_set_owner(page, e);

        spin_unlock(&e->page_alloc_lock);
        put_gfn(d, gop.mfn);

        TRACE_1D(TRC_MEM_PAGE_GRANT_TRANSFER, e->domain_id);

        /* Tell the guest about its new page frame. */
        grant_read_lock(e->grant_table);
        act = active_entry_acquire(e->grant_table, gop.ref);

        if ( e->grant_table->gt_version == 1 )
        {
            grant_entry_v1_t *sha = &shared_entry_v1(e->grant_table, gop.ref);

            guest_physmap_add_page(e, _gfn(sha->frame), _mfn(mfn), 0);
            if ( !paging_mode_translate(e) )
                sha->frame = mfn;
        }
        else
        {
            grant_entry_v2_t *sha = &shared_entry_v2(e->grant_table, gop.ref);

            guest_physmap_add_page(e, _gfn(sha->full_page.frame),
                                   _mfn(mfn), 0);
            if ( !paging_mode_translate(e) )
                sha->full_page.frame = mfn;
        }
        smp_wmb();
        shared_entry_header(e->grant_table, gop.ref)->flags |=
            GTF_transfer_completed;

        active_entry_release(act);
        grant_read_unlock(e->grant_table);

        rcu_unlock_domain(e);

        gop.status = GNTST_okay;

    copyback:
        if ( unlikely(__copy_field_to_guest(uop, &gop, status)) )
        {
            gdprintk(XENLOG_INFO, "gnttab_transfer: error writing resp "
                     "%d/%d\n", i, count);
            return -EFAULT;
        }
        guest_handle_add_offset(uop, 1);
    }

    return 0;
}

/* Undo __acquire_grant_for_copy.  Again, this has no effect on page
   type and reference counts. */
static void
__release_grant_for_copy(
    struct domain *rd, unsigned long gref, int readonly)
{
    struct grant_table *rgt = rd->grant_table;
    grant_entry_header_t *sha;
    struct active_grant_entry *act;
    unsigned long r_frame;
    uint16_t *status;
    grant_ref_t trans_gref;
    struct domain *td;

    grant_read_lock(rgt);

    act = active_entry_acquire(rgt, gref);
    sha = shared_entry_header(rgt, gref);
    r_frame = act->frame;

    if (rgt->gt_version == 1)
    {
        status = &sha->flags;
        td = rd;
        trans_gref = gref;
    }
    else
    {
        status = &status_entry(rgt, gref);
        td = act->trans_domain;
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
            gnttab_clear_flag(_GTF_writing, status);
    }

    if ( !act->pin )
        gnttab_clear_flag(_GTF_reading, status);

    active_entry_release(act);
    grant_read_unlock(rgt);

    if ( td != rd )
    {
        /*
         * Recursive call, but it is bounded (acquire permits only a single
         * level of transitivity), so it's okay.
         */
        __release_grant_for_copy(td, trans_gref, readonly);

        rcu_unlock_domain(td);
    }
}

/* The status for a grant indicates that we're taking more access than
   the pin requires.  Fix up the status to match the pin.  Called
   under the domain's grant table lock. */
/* Only safe on transitive grants.  Even then, note that we don't
   attempt to drop any pin on the referent grant. */
static void __fixup_status_for_copy_pin(const struct active_grant_entry *act,
                                   uint16_t *status)
{
    if ( !(act->pin & (GNTPIN_hstw_mask | GNTPIN_devw_mask)) )
        gnttab_clear_flag(_GTF_writing, status);

    if ( !act->pin )
        gnttab_clear_flag(_GTF_reading, status);
}

/* Grab a frame number from a grant entry and update the flags and pin
   count as appropriate. If rc == GNTST_okay, note that this *does* 
   take one ref count on the target page, stored in *page.
   If there is any error, *page = NULL, no ref taken. */
static int
__acquire_grant_for_copy(
    struct domain *rd, unsigned long gref, domid_t ldom, int readonly,
    unsigned long *frame, struct page_info **page, 
    uint16_t *page_off, uint16_t *length, unsigned allow_transitive)
{
    struct grant_table *rgt = rd->grant_table;
    grant_entry_v2_t *sha2;
    grant_entry_header_t *shah;
    struct active_grant_entry *act;
    grant_status_t *status;
    uint32_t old_pin;
    domid_t trans_domid;
    grant_ref_t trans_gref;
    struct domain *td;
    unsigned long grant_frame;
    uint16_t trans_page_off;
    uint16_t trans_length;
    int is_sub_page;
    s16 rc = GNTST_okay;

    *page = NULL;

    grant_read_lock(rgt);

    if ( unlikely(gref >= nr_grant_entries(rgt)) )
        PIN_FAIL(gt_unlock_out, GNTST_bad_gntref,
                 "Bad grant reference %ld\n", gref);

    act = active_entry_acquire(rgt, gref);
    shah = shared_entry_header(rgt, gref);
    if ( rgt->gt_version == 1 )
    {
        sha2 = NULL;
        status = &shah->flags;
    }
    else
    {
        sha2 = &shared_entry_v2(rgt, gref);
        status = &status_entry(rgt, gref);
    }

    /* If already pinned, check the active domid and avoid refcnt overflow. */
    if ( act->pin && ((act->domid != ldom) || (act->pin & 0x80808080U) != 0) )
        PIN_FAIL(unlock_out, GNTST_general_error,
                 "Bad domain (%d != %d), or risk of counter overflow %08x\n",
                 act->domid, ldom, act->pin);

    old_pin = act->pin;
    if ( sha2 && (shah->flags & GTF_type_mask) == GTF_transitive )
    {
        if ( (!old_pin || (!readonly &&
                           !(old_pin & (GNTPIN_devw_mask|GNTPIN_hstw_mask)))) &&
             (rc = _set_status_v2(ldom, readonly, 0, shah, act,
                                  status)) != GNTST_okay )
            goto unlock_out;

        if ( !allow_transitive )
            PIN_FAIL(unlock_out_clear, GNTST_general_error,
                     "transitive grant when transitivity not allowed\n");

        trans_domid = sha2->transitive.trans_domid;
        trans_gref = sha2->transitive.gref;
        barrier(); /* Stop the compiler from re-loading
                      trans_domid from shared memory */
        if ( trans_domid == rd->domain_id )
            PIN_FAIL(unlock_out_clear, GNTST_general_error,
                     "transitive grants cannot be self-referential\n");

        /*
         * We allow the trans_domid == ldom case, which corresponds to a
         * grant being issued by one domain, sent to another one, and then
         * transitively granted back to the original domain.  Allowing it
         * is easy, and means that you don't need to go out of your way to
         * avoid it in the guest.
         */

        /* We need to leave the rrd locked during the grant copy. */
        td = rcu_lock_domain_by_id(trans_domid);
        if ( td == NULL )
            PIN_FAIL(unlock_out_clear, GNTST_general_error,
                     "transitive grant referenced bad domain %d\n",
                     trans_domid);

        /*
         * __acquire_grant_for_copy() could take the lock on the
         * remote table (if rd == td), so we have to drop the lock
         * here and reacquire.
         */
        active_entry_release(act);
        grant_read_unlock(rgt);

        rc = __acquire_grant_for_copy(td, trans_gref, rd->domain_id,
                                      readonly, &grant_frame, page,
                                      &trans_page_off, &trans_length, 0);

        grant_read_lock(rgt);
        act = active_entry_acquire(rgt, gref);

        if ( rc != GNTST_okay )
        {
            __fixup_status_for_copy_pin(act, status);
            rcu_unlock_domain(td);
            active_entry_release(act);
            grant_read_unlock(rgt);
            return rc;
        }

        /*
         * We dropped the lock, so we have to check that the grant didn't
         * change, and that nobody else tried to pin/unpin it. If anything
         * changed, just give up and tell the caller to retry.
         */
        if ( rgt->gt_version != 2 ||
             act->pin != old_pin ||
             (old_pin && (act->domid != ldom || act->frame != grant_frame ||
                          act->start != trans_page_off ||
                          act->length != trans_length ||
                          act->trans_domain != td ||
                          act->trans_gref != trans_gref ||
                          !act->is_sub_page)) )
        {
            __release_grant_for_copy(td, trans_gref, readonly);
            __fixup_status_for_copy_pin(act, status);
            rcu_unlock_domain(td);
            active_entry_release(act);
            grant_read_unlock(rgt);
            put_page(*page);
            *page = NULL;
            return ERESTART;
        }

        if ( !old_pin )
        {
            act->domid = ldom;
            act->start = trans_page_off;
            act->length = trans_length;
            act->trans_domain = td;
            act->trans_gref = trans_gref;
            act->frame = grant_frame;
            act->gfn = -1ul;
            /*
             * The actual remote remote grant may or may not be a sub-page,
             * but we always treat it as one because that blocks mappings of
             * transitive grants.
             */
            act->is_sub_page = 1;
        }
    }
    else if ( !old_pin ||
              (!readonly && !(old_pin & (GNTPIN_devw_mask|GNTPIN_hstw_mask))) )
    {
        if ( (rc = _set_status(rgt->gt_version, ldom,
                               readonly, 0, shah, act,
                               status) ) != GNTST_okay )
             goto unlock_out;

        td = rd;
        trans_gref = gref;
        if ( !sha2 )
        {
            unsigned long gfn = shared_entry_v1(rgt, gref).frame;

            rc = __get_paged_frame(gfn, &grant_frame, page, readonly, rd);
            if ( rc != GNTST_okay )
                goto unlock_out_clear;
            act->gfn = gfn;
            is_sub_page = 0;
            trans_page_off = 0;
            trans_length = PAGE_SIZE;
        }
        else if ( !(sha2->hdr.flags & GTF_sub_page) )
        {
            rc = __get_paged_frame(sha2->full_page.frame, &grant_frame, page, readonly, rd);
            if ( rc != GNTST_okay )
                goto unlock_out_clear;
            act->gfn = sha2->full_page.frame;
            is_sub_page = 0;
            trans_page_off = 0;
            trans_length = PAGE_SIZE;
        }
        else
        {
            rc = __get_paged_frame(sha2->sub_page.frame, &grant_frame, page, readonly, rd);
            if ( rc != GNTST_okay )
                goto unlock_out_clear;
            act->gfn = sha2->sub_page.frame;
            is_sub_page = 1;
            trans_page_off = sha2->sub_page.page_off;
            trans_length = sha2->sub_page.length;
        }

        if ( !act->pin )
        {
            act->domid = ldom;
            act->is_sub_page = is_sub_page;
            act->start = trans_page_off;
            act->length = trans_length;
            act->trans_domain = td;
            act->trans_gref = trans_gref;
            act->frame = grant_frame;
        }
    }
    else
    {
        ASSERT(mfn_valid(act->frame));
        *page = mfn_to_page(act->frame);
        td = page_get_owner_and_reference(*page);
        /*
         * act->pin being non-zero should guarantee the page to have a
         * non-zero refcount and hence a valid owner (matching the one on
         * record), with one exception: If the owning domain is dying we
         * had better not make implications from pin count (map_grant_ref()
         * updates pin counts before obtaining page references, for
         * example).
         */
        if ( td != rd || rd->is_dying )
        {
            if ( td )
                put_page(*page);
            *page = NULL;
            rc = GNTST_bad_domain;
            goto unlock_out_clear;
        }
    }

    act->pin += readonly ? GNTPIN_hstr_inc : GNTPIN_hstw_inc;

    *page_off = act->start;
    *length = act->length;
    *frame = act->frame;

    active_entry_release(act);
    grant_read_unlock(rgt);
    return rc;
 
 unlock_out_clear:
    if ( !(readonly) &&
         !(act->pin & (GNTPIN_hstw_mask | GNTPIN_devw_mask)) )
        gnttab_clear_flag(_GTF_writing, status);

    if ( !act->pin )
        gnttab_clear_flag(_GTF_reading, status);

 unlock_out:
    active_entry_release(act);

 gt_unlock_out:
    grant_read_unlock(rgt);

    return rc;
}

struct gnttab_copy_buf {
    /* Guest provided. */
    struct gnttab_copy_ptr ptr;
    uint16_t len;

    /* Mapped etc. */
    struct domain *domain;
    unsigned long frame;
    struct page_info *page;
    void *virt;
    bool_t read_only;
    bool_t have_grant;
    bool_t have_type;
};

static int gnttab_copy_lock_domain(domid_t domid, unsigned int gref_flag,
                                   struct gnttab_copy_buf *buf)
{
    int rc;

    if ( domid != DOMID_SELF && !gref_flag )
        PIN_FAIL(out, GNTST_permission_denied,
                 "only allow copy-by-mfn for DOMID_SELF.\n");

    if ( domid == DOMID_SELF )
        buf->domain = rcu_lock_current_domain();
    else
    {
        buf->domain = rcu_lock_domain_by_id(domid);
        if ( buf->domain == NULL )
            PIN_FAIL(out, GNTST_bad_domain, "couldn't find %d\n", domid);
    }

    buf->ptr.domid = domid;
    rc = GNTST_okay;
 out:
    return rc;
}

static void gnttab_copy_unlock_domains(struct gnttab_copy_buf *src,
                                       struct gnttab_copy_buf *dest)
{
    if ( src->domain )
    {
        rcu_unlock_domain(src->domain);
        src->domain = NULL;
    }
    if ( dest->domain )
    {
        rcu_unlock_domain(dest->domain);
        dest->domain = NULL;
    }
}

static int gnttab_copy_lock_domains(const struct gnttab_copy *op,
                                    struct gnttab_copy_buf *src,
                                    struct gnttab_copy_buf *dest)
{
    int rc;

    rc = gnttab_copy_lock_domain(op->source.domid,
                                 op->flags & GNTCOPY_source_gref, src);
    if ( rc < 0 )
        goto error;
    rc = gnttab_copy_lock_domain(op->dest.domid,
                                 op->flags & GNTCOPY_dest_gref, dest);
    if ( rc < 0 )
        goto error;

    rc = xsm_grant_copy(XSM_HOOK, src->domain, dest->domain);
    if ( rc < 0 )
    {
        rc = GNTST_permission_denied;
        goto error;
    }
    return 0;

 error:
    gnttab_copy_unlock_domains(src, dest);
    return rc;
}

static void gnttab_copy_release_buf(struct gnttab_copy_buf *buf)
{
    if ( buf->virt )
    {
        unmap_domain_page(buf->virt);
        buf->virt = NULL;
    }
    if ( buf->have_grant )
    {
        __release_grant_for_copy(buf->domain, buf->ptr.u.ref, buf->read_only);
        buf->have_grant = 0;
    }
    if ( buf->have_type )
    {
        put_page_type(buf->page);
        buf->have_type = 0;
    }
    if ( buf->page )
    {
        put_page(buf->page);
        buf->page = NULL;
    }
}

static int gnttab_copy_claim_buf(const struct gnttab_copy *op,
                                 const struct gnttab_copy_ptr *ptr,
                                 struct gnttab_copy_buf *buf,
                                 unsigned int gref_flag)
{
    int rc;

    buf->read_only = gref_flag == GNTCOPY_source_gref;

    if ( op->flags & gref_flag )
    {
        rc = __acquire_grant_for_copy(buf->domain, ptr->u.ref,
                                      current->domain->domain_id,
                                      buf->read_only,
                                      &buf->frame, &buf->page,
                                      &buf->ptr.offset, &buf->len, 1);
        if ( rc != GNTST_okay )
            goto out;
        buf->ptr.u.ref = ptr->u.ref;
        buf->have_grant = 1;
    }
    else
    {
        rc = __get_paged_frame(ptr->u.gmfn, &buf->frame, &buf->page,
                               buf->read_only, buf->domain);
        if ( rc != GNTST_okay )
            PIN_FAIL(out, rc,
                     "source frame %"PRI_xen_pfn" invalid.\n", ptr->u.gmfn);

        buf->ptr.u.gmfn = ptr->u.gmfn;
        buf->ptr.offset = 0;
        buf->len = PAGE_SIZE;
    }

    if ( !buf->read_only )
    {
        if ( !get_page_type(buf->page, PGT_writable_page) )
        {
            if ( !buf->domain->is_dying )
                gdprintk(XENLOG_WARNING, "Could not get writable frame %lx\n", buf->frame);
            rc = GNTST_general_error;
            goto out;
        }
        buf->have_type = 1;
    }

    buf->virt = map_domain_page(_mfn(buf->frame));
    rc = GNTST_okay;

 out:
    return rc;
}

static bool_t gnttab_copy_buf_valid(const struct gnttab_copy_ptr *p,
                                    const struct gnttab_copy_buf *b,
                                    bool_t has_gref)
{
    if ( !b->virt )
        return 0;
    if ( has_gref )
        return b->have_grant && p->u.ref == b->ptr.u.ref;
    return p->u.gmfn == b->ptr.u.gmfn;
}

static int gnttab_copy_buf(const struct gnttab_copy *op,
                           struct gnttab_copy_buf *dest,
                           const struct gnttab_copy_buf *src)
{
    int rc;

    if ( ((op->source.offset + op->len) > PAGE_SIZE) ||
         ((op->dest.offset + op->len) > PAGE_SIZE) )
        PIN_FAIL(out, GNTST_bad_copy_arg, "copy beyond page area.\n");

    if ( op->source.offset < src->ptr.offset ||
         op->source.offset + op->len > src->ptr.offset + src->len )
        PIN_FAIL(out, GNTST_general_error,
                 "copy source out of bounds: %d < %d || %d > %d\n",
                 op->source.offset, src->ptr.offset,
                 op->len, src->len);

    if ( op->dest.offset < dest->ptr.offset ||
         op->dest.offset + op->len > dest->ptr.offset + dest->len )
        PIN_FAIL(out, GNTST_general_error,
                 "copy dest out of bounds: %d < %d || %d > %d\n",
                 op->dest.offset, dest->ptr.offset,
                 op->len, dest->len);

    memcpy(dest->virt + op->dest.offset, src->virt + op->source.offset,
           op->len);
    gnttab_mark_dirty(dest->domain, dest->frame);
    rc = GNTST_okay;
 out:
    return rc;
}

static int gnttab_copy_one(const struct gnttab_copy *op,
                           struct gnttab_copy_buf *dest,
                           struct gnttab_copy_buf *src)
{
    int rc;

    if ( !src->domain || op->source.domid != src->ptr.domid ||
         !dest->domain || op->dest.domid != dest->ptr.domid )
    {
        gnttab_copy_release_buf(src);
        gnttab_copy_release_buf(dest);
        gnttab_copy_unlock_domains(src, dest);

        rc = gnttab_copy_lock_domains(op, src, dest);
        if ( rc < 0 )
            goto out;
    }

    /* Different source? */
    if ( !gnttab_copy_buf_valid(&op->source, src,
                                op->flags & GNTCOPY_source_gref) )
    {
        gnttab_copy_release_buf(src);
        rc = gnttab_copy_claim_buf(op, &op->source, src, GNTCOPY_source_gref);
        if ( rc )
            goto out;
    }

    /* Different dest? */
    if ( !gnttab_copy_buf_valid(&op->dest, dest,
                                op->flags & GNTCOPY_dest_gref) )
    {
        gnttab_copy_release_buf(dest);
        rc = gnttab_copy_claim_buf(op, &op->dest, dest, GNTCOPY_dest_gref);
        if ( rc )
            goto out;
    }

    rc = gnttab_copy_buf(op, dest, src);
 out:
    return rc;
}

/*
 * gnttab_copy(), other than the various other helpers of
 * do_grant_table_op(), returns (besides possible error indicators)
 * "count - i" rather than "i" to ensure that even if no progress
 * was made at all (perhaps due to gnttab_copy_one() returning a
 * positive value) a non-zero value is being handed back (zero needs
 * to be avoided, as that means "success, all done").
 */
static long gnttab_copy(
    XEN_GUEST_HANDLE_PARAM(gnttab_copy_t) uop, unsigned int count)
{
    unsigned int i;
    struct gnttab_copy op;
    struct gnttab_copy_buf src = {};
    struct gnttab_copy_buf dest = {};
    long rc = 0;

    for ( i = 0; i < count; i++ )
    {
        if ( i && hypercall_preempt_check() )
        {
            rc = count - i;
            break;
        }

        if ( unlikely(__copy_from_guest(&op, uop, 1)) )
        {
            rc = -EFAULT;
            break;
        }

        rc = gnttab_copy_one(&op, &dest, &src);
        if ( rc > 0 )
        {
            rc = count - i;
            break;
        }
        if ( rc != GNTST_okay )
        {
            gnttab_copy_release_buf(&src);
            gnttab_copy_release_buf(&dest);
        }

        op.status = rc;
        rc = 0;
        if ( unlikely(__copy_field_to_guest(uop, &op, status)) )
        {
            rc = -EFAULT;
            break;
        }
        guest_handle_add_offset(uop, 1);
    }

    gnttab_copy_release_buf(&src);
    gnttab_copy_release_buf(&dest);
    gnttab_copy_unlock_domains(&src, &dest);

    return rc;
}

static long
gnttab_set_version(XEN_GUEST_HANDLE_PARAM(gnttab_set_version_t) uop)
{
    gnttab_set_version_t op;
    struct domain *currd = current->domain;
    struct grant_table *gt = currd->grant_table;
    grant_entry_v1_t reserved_entries[GNTTAB_NR_RESERVED_ENTRIES];
    int res;
    unsigned int i;

    if ( copy_from_guest(&op, uop, 1) )
        return -EFAULT;

    res = -EINVAL;
    if ( op.version != 1 && op.version != 2 )
        goto out;

    res = 0;
    if ( gt->gt_version == op.version )
        goto out;

    grant_write_lock(gt);
    /*
     * Make sure that the grant table isn't currently in use when we
     * change the version number, except for the first 8 entries which
     * are allowed to be in use (xenstore/xenconsole keeps them mapped).
     * (You need to change the version number for e.g. kexec.)
     */
    for ( i = GNTTAB_NR_RESERVED_ENTRIES; i < nr_grant_entries(gt); i++ )
    {
        if ( read_atomic(&_active_entry(gt, i).pin) != 0 )
        {
            gdprintk(XENLOG_WARNING,
                     "tried to change grant table version from %u to %u, but some grant entries still in use\n",
                     gt->gt_version, op.version);
            res = -EBUSY;
            goto out_unlock;
        }
    }

    switch ( gt->gt_version )
    {
    case 0:
        if ( op.version == 2 )
        {
    case 1:
            /* XXX: We could maybe shrink the active grant table here. */
            res = gnttab_populate_status_frames(currd, gt, nr_grant_frames(gt));
            if ( res < 0)
                goto out_unlock;
        }
        break;
    case 2:
        for ( i = 0; i < GNTTAB_NR_RESERVED_ENTRIES; i++ )
        {
            switch ( shared_entry_v2(gt, i).hdr.flags & GTF_type_mask )
            {
            case GTF_permit_access:
                 if ( !(shared_entry_v2(gt, i).full_page.frame >> 32) )
                     break;
                 /* fall through */
            case GTF_transitive:
                gdprintk(XENLOG_WARNING,
                         "tried to change grant table version to 1 with non-representable entries\n");
                res = -ERANGE;
                goto out_unlock;
            }
        }
        break;
    }

    /* Preserve the first 8 entries (toolstack reserved grants). */
    switch ( gt->gt_version )
    {
    case 1:
        memcpy(reserved_entries, &shared_entry_v1(gt, 0),
               sizeof(reserved_entries));
        break;
    case 2:
        for ( i = 0; i < GNTTAB_NR_RESERVED_ENTRIES; i++ )
        {
            unsigned int flags = shared_entry_v2(gt, i).hdr.flags;

            switch ( flags & GTF_type_mask )
            {
            case GTF_permit_access:
                reserved_entries[i].flags = flags | status_entry(gt, i);
                reserved_entries[i].domid = shared_entry_v2(gt, i).hdr.domid;
                reserved_entries[i].frame = shared_entry_v2(gt, i).full_page.frame;
                break;
            default:
                gdprintk(XENLOG_INFO,
                         "bad flags %#x in grant %u when switching version\n",
                         flags, i);
                /* fall through */
            case GTF_invalid:
                memset(&reserved_entries[i], 0, sizeof(reserved_entries[i]));
                break;
            }
        }
        break;
    }

    if ( op.version < 2 && gt->gt_version == 2 )
        gnttab_unpopulate_status_frames(currd, gt);

    /* Make sure there's no crud left over from the old version. */
    for ( i = 0; i < nr_grant_frames(gt); i++ )
        clear_page(gt->shared_raw[i]);

    /* Restore the first 8 entries (toolstack reserved grants). */
    if ( gt->gt_version )
    {
        switch ( op.version )
        {
        case 1:
            memcpy(&shared_entry_v1(gt, 0), reserved_entries, sizeof(reserved_entries));
            break;
        case 2:
            for ( i = 0; i < GNTTAB_NR_RESERVED_ENTRIES; i++ )
            {
                status_entry(gt, i) =
                    reserved_entries[i].flags & (GTF_reading | GTF_writing);
                shared_entry_v2(gt, i).hdr.flags =
                    reserved_entries[i].flags & ~(GTF_reading | GTF_writing);
                shared_entry_v2(gt, i).hdr.domid =
                    reserved_entries[i].domid;
                shared_entry_v2(gt, i).full_page.frame =
                    reserved_entries[i].frame;
            }
            break;
        }
    }

    gt->gt_version = op.version;

 out_unlock:
    grant_write_unlock(gt);

 out:
    op.version = gt->gt_version;

    if ( __copy_to_guest(uop, &op, 1) )
        res = -EFAULT;

    return res;
}

static long
gnttab_get_status_frames(XEN_GUEST_HANDLE_PARAM(gnttab_get_status_frames_t) uop,
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

    d = rcu_lock_domain_by_any_id(op.dom);
    if ( d == NULL )
    {
        op.status = GNTST_bad_domain;
        goto out1;
    }
    rc = xsm_grant_setup(XSM_TARGET, current->domain, d);
    if ( rc ) {
        op.status = GNTST_permission_denied;
        goto out2;
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

    grant_read_lock(gt);

    for ( i = 0; i < op.nr_frames; i++ )
    {
        gmfn = gnttab_status_gmfn(d, gt, i);
        if (copy_to_guest_offset(op.frame_list, i, &gmfn, 1))
            op.status = GNTST_bad_virt_addr;
    }

    grant_read_unlock(gt);
out2:
    rcu_unlock_domain(d);
out1:
    if ( unlikely(__copy_field_to_guest(uop, &op, status)) )
        return -EFAULT;

    return 0;
}

static long
gnttab_get_version(XEN_GUEST_HANDLE_PARAM(gnttab_get_version_t) uop)
{
    gnttab_get_version_t op;
    struct domain *d;
    int rc;

    if ( copy_from_guest(&op, uop, 1) )
        return -EFAULT;

    d = rcu_lock_domain_by_any_id(op.dom);
    if ( d == NULL )
        return -ESRCH;

    rc = xsm_grant_query_size(XSM_TARGET, current->domain, d);
    if ( rc )
    {
        rcu_unlock_domain(d);
        return rc;
    }

    op.version = d->grant_table->gt_version;

    rcu_unlock_domain(d);

    if ( __copy_field_to_guest(uop, &op, version) )
        return -EFAULT;

    return 0;
}

static s16
__gnttab_swap_grant_ref(grant_ref_t ref_a, grant_ref_t ref_b)
{
    struct domain *d = rcu_lock_current_domain();
    struct grant_table *gt = d->grant_table;
    struct active_grant_entry *act_a = NULL;
    struct active_grant_entry *act_b = NULL;
    s16 rc = GNTST_okay;

    grant_write_lock(gt);

    /* Bounds check on the grant refs */
    if ( unlikely(ref_a >= nr_grant_entries(d->grant_table)))
        PIN_FAIL(out, GNTST_bad_gntref, "Bad ref-a (%d).\n", ref_a);
    if ( unlikely(ref_b >= nr_grant_entries(d->grant_table)))
        PIN_FAIL(out, GNTST_bad_gntref, "Bad ref-b (%d).\n", ref_b);

    /* Swapping the same ref is a no-op. */
    if ( ref_a == ref_b )
        goto out;

    act_a = active_entry_acquire(gt, ref_a);
    if ( act_a->pin )
        PIN_FAIL(out, GNTST_eagain, "ref a %ld busy\n", (long)ref_a);

    act_b = active_entry_acquire(gt, ref_b);
    if ( act_b->pin )
        PIN_FAIL(out, GNTST_eagain, "ref b %ld busy\n", (long)ref_b);

    if ( gt->gt_version == 1 )
    {
        grant_entry_v1_t shared;

        shared = shared_entry_v1(gt, ref_a);
        shared_entry_v1(gt, ref_a) = shared_entry_v1(gt, ref_b);
        shared_entry_v1(gt, ref_b) = shared;
    }
    else
    {
        grant_entry_v2_t shared;
        grant_status_t status;

        shared = shared_entry_v2(gt, ref_a);
        status = status_entry(gt, ref_a);

        shared_entry_v2(gt, ref_a) = shared_entry_v2(gt, ref_b);
        status_entry(gt, ref_a) = status_entry(gt, ref_b);

        shared_entry_v2(gt, ref_b) = shared;
        status_entry(gt, ref_b) = status;
    }

out:
    if ( act_b != NULL )
        active_entry_release(act_b);
    if ( act_a != NULL )
        active_entry_release(act_a);
    grant_write_unlock(gt);

    rcu_unlock_domain(d);

    return rc;
}

static long
gnttab_swap_grant_ref(XEN_GUEST_HANDLE_PARAM(gnttab_swap_grant_ref_t) uop,
                      unsigned int count)
{
    int i;
    gnttab_swap_grant_ref_t op;

    for ( i = 0; i < count; i++ )
    {
        if ( i && hypercall_preempt_check() )
            return i;
        if ( unlikely(__copy_from_guest(&op, uop, 1)) )
            return -EFAULT;
        op.status = __gnttab_swap_grant_ref(op.ref_a, op.ref_b);
        if ( unlikely(__copy_field_to_guest(uop, &op, status)) )
            return -EFAULT;
        guest_handle_add_offset(uop, 1);
    }
    return 0;
}

static int __gnttab_cache_flush(gnttab_cache_flush_t *cflush,
                                unsigned int *ref_count)
{
    struct domain *d, *owner;
    struct page_info *page;
    unsigned long mfn;
    void *v;
    int ret;

    if ( (cflush->offset >= PAGE_SIZE) ||
         (cflush->length > PAGE_SIZE) ||
         (cflush->offset + cflush->length > PAGE_SIZE) )
        return -EINVAL;

    if ( cflush->length == 0 || cflush->op == 0 )
        return 0;

    /* currently unimplemented */
    if ( cflush->op & GNTTAB_CACHE_SOURCE_GREF )
        return -EOPNOTSUPP;

    if ( cflush->op & ~(GNTTAB_CACHE_INVAL|GNTTAB_CACHE_CLEAN) )
        return -EINVAL;

    d = rcu_lock_current_domain();
    mfn = cflush->a.dev_bus_addr >> PAGE_SHIFT;

    if ( !mfn_valid(mfn) )
    {
        rcu_unlock_domain(d);
        return -EINVAL;
    }

    page = mfn_to_page(mfn);
    owner = page_get_owner_and_reference(page);
    if ( !owner || !owner->grant_table )
    {
        rcu_unlock_domain(d);
        return -EPERM;
    }

    if ( d != owner )
    {
        grant_read_lock(owner->grant_table);

        ret = grant_map_exists(d, owner->grant_table, mfn, ref_count);
        if ( ret != 0 )
        {
            grant_read_unlock(owner->grant_table);
            rcu_unlock_domain(d);
            put_page(page);
            return ret;
        }
    }

    v = map_domain_page(_mfn(mfn));
    v += cflush->offset;

    if ( (cflush->op & GNTTAB_CACHE_INVAL) && (cflush->op & GNTTAB_CACHE_CLEAN) )
        ret = clean_and_invalidate_dcache_va_range(v, cflush->length);
    else if ( cflush->op & GNTTAB_CACHE_INVAL )
        ret = invalidate_dcache_va_range(v, cflush->length);
    else if ( cflush->op & GNTTAB_CACHE_CLEAN )
        ret = clean_dcache_va_range(v, cflush->length);
    else
        ret = 0;

    if ( d != owner )
        grant_read_unlock(owner->grant_table);
    unmap_domain_page(v);
    put_page(page);

    return ret;
}

static long
gnttab_cache_flush(XEN_GUEST_HANDLE_PARAM(gnttab_cache_flush_t) uop,
                      unsigned int *ref_count,
                      unsigned int count)
{
    unsigned int i;
    gnttab_cache_flush_t op;

    for ( i = 0; i < count; i++ )
    {
        if ( i && hypercall_preempt_check() )
            return i;
        if ( unlikely(__copy_from_guest(&op, uop, 1)) )
            return -EFAULT;
        for ( ; ; )
        {
            int ret = __gnttab_cache_flush(&op, ref_count);

            if ( ret < 0 )
                return ret;
            if ( ret == 0 )
                break;
            if ( hypercall_preempt_check() )
                return i;
        }
        *ref_count = 0;
        guest_handle_add_offset(uop, 1);
    }
    return 0;
}

long
do_grant_table_op(
    unsigned int cmd, XEN_GUEST_HANDLE_PARAM(void) uop, unsigned int count)
{
    long rc;
    unsigned int opaque_in = cmd & GNTTABOP_ARG_MASK, opaque_out = 0;
    
    if ( (int)count < 0 )
        return -EINVAL;

    if ( (cmd &= GNTTABOP_CMD_MASK) != GNTTABOP_cache_flush && opaque_in )
        return -EINVAL;
    
    rc = -EFAULT;
    switch ( cmd )
    {
    case GNTTABOP_map_grant_ref:
    {
        XEN_GUEST_HANDLE_PARAM(gnttab_map_grant_ref_t) map =
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
        XEN_GUEST_HANDLE_PARAM(gnttab_unmap_grant_ref_t) unmap =
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
        XEN_GUEST_HANDLE_PARAM(gnttab_unmap_and_replace_t) unmap =
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
        XEN_GUEST_HANDLE_PARAM(gnttab_transfer_t) transfer =
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
        XEN_GUEST_HANDLE_PARAM(gnttab_copy_t) copy =
            guest_handle_cast(uop, gnttab_copy_t);
        if ( unlikely(!guest_handle_okay(copy, count)) )
            goto out;
        rc = gnttab_copy(copy, count);
        if ( rc > 0 )
        {
            rc = count - rc;
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
    case GNTTABOP_swap_grant_ref:
    {
        XEN_GUEST_HANDLE_PARAM(gnttab_swap_grant_ref_t) swap =
            guest_handle_cast(uop, gnttab_swap_grant_ref_t);
        if ( unlikely(!guest_handle_okay(swap, count)) )
            goto out;
        rc = gnttab_swap_grant_ref(swap, count);
        if ( rc > 0 )
        {
            guest_handle_add_offset(swap, rc);
            uop = guest_handle_cast(swap, void);
        }
        break;
    }
    case GNTTABOP_cache_flush:
    {
        XEN_GUEST_HANDLE_PARAM(gnttab_cache_flush_t) cflush =
            guest_handle_cast(uop, gnttab_cache_flush_t);

        if ( unlikely(!guest_handle_okay(cflush, count)) )
            goto out;
        rc = gnttab_cache_flush(cflush, &opaque_in, count);
        if ( rc > 0 )
        {
            guest_handle_add_offset(cflush, rc);
            uop = guest_handle_cast(cflush, void);
        }
        opaque_out = opaque_in;
        break;
    }
    default:
        rc = -ENOSYS;
        break;
    }
    
  out:
    if ( rc > 0 || opaque_out != 0 )
    {
        ASSERT(rc < count);
        ASSERT((opaque_out & GNTTABOP_CMD_MASK) == 0);
        rc = hypercall_create_continuation(__HYPERVISOR_grant_table_op, "ihi",
                                           opaque_out | cmd, uop, count - rc);
    }
    
    return rc;
}

#ifdef CONFIG_COMPAT
#include "compat/grant_table.c"
#endif

int 
grant_table_create(
    struct domain *d)
{
    struct grant_table *t;
    unsigned int i, j;

    if ( (t = xzalloc(struct grant_table)) == NULL )
        goto no_mem_0;

    /* Simple stuff. */
    percpu_rwlock_resource_init(&t->lock, grant_rwlock);
    spin_lock_init(&t->maptrack_lock);
    t->nr_grant_frames = INITIAL_NR_GRANT_FRAMES;

    /* Active grant table. */
    if ( (t->active = xzalloc_array(struct active_grant_entry *,
                                    max_nr_active_grant_frames)) == NULL )
        goto no_mem_1;
    for ( i = 0;
          i < num_act_frames_from_sha_frames(INITIAL_NR_GRANT_FRAMES); i++ )
    {
        if ( (t->active[i] = alloc_xenheap_page()) == NULL )
            goto no_mem_2;
        clear_page(t->active[i]);
        for ( j = 0; j < ACGNT_PER_PAGE; j++ )
            spin_lock_init(&t->active[i][j].lock);
    }

    /* Tracking of mapped foreign frames table */
    t->maptrack = vzalloc(max_maptrack_frames * sizeof(*t->maptrack));
    if ( t->maptrack == NULL )
        goto no_mem_2;

    /* Shared grant table. */
    if ( (t->shared_raw = xzalloc_array(void *, max_grant_frames)) == NULL )
        goto no_mem_3;
    for ( i = 0; i < INITIAL_NR_GRANT_FRAMES; i++ )
    {
        if ( (t->shared_raw[i] = alloc_xenheap_page()) == NULL )
            goto no_mem_4;
        clear_page(t->shared_raw[i]);
    }
    
    /* Status pages for grant table - for version 2 */
    t->status = xzalloc_array(grant_status_t *,
                              grant_to_status_frames(max_grant_frames));
    if ( t->status == NULL )
        goto no_mem_4;

    for ( i = 0; i < INITIAL_NR_GRANT_FRAMES; i++ )
        gnttab_create_shared_page(d, t, i);

    t->nr_status_frames = 0;

    /* Okay, install the structure. */
    d->grant_table = t;
    return 0;

 no_mem_4:
    for ( i = 0; i < INITIAL_NR_GRANT_FRAMES; i++ )
        free_xenheap_page(t->shared_raw[i]);
    xfree(t->shared_raw);
 no_mem_3:
    vfree(t->maptrack);
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
    struct grant_table   *gt = d->grant_table, *rgt;
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

        rgt = rd->grant_table;
        grant_read_lock(rgt);

        act = active_entry_acquire(rgt, ref);
        sha = shared_entry_header(rgt, ref);
        if (rgt->gt_version == 1)
            status = &sha->flags;
        else
            status = &status_entry(rgt, ref);

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
                    if ( gnttab_host_mapping_get_page_type((map->flags &
                                                            GNTMAP_readonly),
                                                           d, rd) )
                        put_page_type(pg);
                    put_page(pg);
                }
            }

            if ( (act->pin & (GNTPIN_devw_mask|GNTPIN_hstw_mask)) == 0 )
                gnttab_clear_flag(_GTF_writing, status);
        }

        if ( act->pin == 0 )
            gnttab_clear_flag(_GTF_reading, status);

        active_entry_release(act);
        grant_read_unlock(rgt);

        rcu_unlock_domain(rd);

        map->flags = 0;
    }
}

void grant_table_warn_active_grants(struct domain *d)
{
    struct grant_table *gt = d->grant_table;
    struct active_grant_entry *act;
    grant_ref_t ref;
    unsigned int nr_active = 0;

#define WARN_GRANT_MAX 10

    grant_read_lock(gt);

    for ( ref = 0; ref != nr_grant_entries(gt); ref++ )
    {
        act = active_entry_acquire(gt, ref);
        if ( !act->pin )
        {
            active_entry_release(act);
            continue;
        }

        nr_active++;
        if ( nr_active <= WARN_GRANT_MAX )
            printk(XENLOG_G_DEBUG "Dom%d has an active grant: GFN: %lx (MFN: %lx)\n",
                   d->domain_id, act->gfn, act->frame);
        active_entry_release(act);
    }

    if ( nr_active > WARN_GRANT_MAX )
        printk(XENLOG_G_DEBUG "Dom%d has too many (%d) active grants to report\n",
               d->domain_id, nr_active);

    grant_read_unlock(gt);

#undef WARN_GRANT_MAX
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
    vfree(t->maptrack);

    for ( i = 0; i < nr_active_grant_frames(t); i++ )
        free_xenheap_page(t->active[i]);
    xfree(t->active);

    for ( i = 0; i < nr_status_frames(t); i++ )
        free_xenheap_page(t->status[i]);
    xfree(t->status);

    xfree(t);
    d->grant_table = NULL;
}

void grant_table_init_vcpu(struct vcpu *v)
{
    spin_lock_init(&v->maptrack_freelist_lock);
    v->maptrack_head = MAPTRACK_TAIL;
    v->maptrack_tail = MAPTRACK_TAIL;
}

#ifdef CONFIG_HAS_MEM_SHARING
int mem_sharing_gref_to_gfn(struct grant_table *gt, grant_ref_t ref,
                            gfn_t *gfn, uint16_t *status)
{
    int rc = 0;
    uint16_t flags = 0;

    grant_read_lock(gt);

    if ( gt->gt_version < 1 )
        rc = -EINVAL;
    else if ( ref >= nr_grant_entries(gt) )
        rc = -ENOENT;
    else if ( gt->gt_version == 1 )
    {
        const grant_entry_v1_t *sha1 = &shared_entry_v1(gt, ref);

        flags = sha1->flags;
        *gfn = _gfn(sha1->frame);
    }
    else
    {
        const grant_entry_v2_t *sha2 = &shared_entry_v2(gt, ref);

        flags = sha2->hdr.flags;
        if ( flags & GTF_sub_page )
           *gfn = _gfn(sha2->sub_page.frame);
        else
           *gfn = _gfn(sha2->full_page.frame);
    }

    if ( !rc && (flags & GTF_type_mask) != GTF_permit_access )
        rc = -ENXIO;
    else if ( !rc && status )
    {
        if ( gt->gt_version == 1 )
            *status = flags;
        else
            *status = status_entry(gt, ref);
    }

    grant_read_unlock(gt);

    return rc;
}
#endif

static void gnttab_usage_print(struct domain *rd)
{
    int first = 1;
    grant_ref_t ref;
    struct grant_table *gt = rd->grant_table;

    printk("      -------- active --------       -------- shared --------\n");
    printk("[ref] localdom mfn      pin          localdom gmfn     flags\n");

    grant_read_lock(gt);

    for ( ref = 0; ref != nr_grant_entries(gt); ref++ )
    {
        struct active_grant_entry *act;
        struct grant_entry_header *sha;
        uint16_t status;
        uint64_t frame;

        act = active_entry_acquire(gt, ref);
        if ( !act->pin )
        {
            active_entry_release(act);
            continue;
        }

        sha = shared_entry_header(gt, ref);

        if ( gt->gt_version == 1 )
        {
            status = sha->flags;
            frame = shared_entry_v1(gt, ref).frame;
        }
        else
        {
            frame = shared_entry_v2(gt, ref).full_page.frame;
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
        active_entry_release(act);
    }

    grant_read_unlock(gt);

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

static int __init gnttab_usage_init(void)
{
    if ( max_nr_grant_frames )
    {
        printk(XENLOG_WARNING
               "gnttab_max_nr_frames is deprecated, use gnttab_max_frames instead\n");
        if ( !max_grant_frames )
            max_grant_frames = max_nr_grant_frames;
        BUILD_BUG_ON(DEFAULT_MAX_MAPTRACK_FRAMES < DEFAULT_MAX_NR_GRANT_FRAMES);
        if ( !max_maptrack_frames )
            max_maptrack_frames = max_nr_grant_frames *
                (DEFAULT_MAX_MAPTRACK_FRAMES / DEFAULT_MAX_NR_GRANT_FRAMES);
    }

    if ( !max_grant_frames )
        max_grant_frames = DEFAULT_MAX_NR_GRANT_FRAMES;

    if ( !max_maptrack_frames )
        max_maptrack_frames = DEFAULT_MAX_MAPTRACK_FRAMES;

    register_keyhandler('g', gnttab_usage_print_all,
                        "print grant table usage", 1);
    return 0;
}
__initcall(gnttab_usage_init);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
