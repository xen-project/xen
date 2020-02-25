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
#include <xen/param.h>
#include <xen/event.h>
#include <xen/trace.h>
#include <xen/grant_table.h>
#include <xen/guest_access.h>
#include <xen/domain_page.h>
#include <xen/iommu.h>
#include <xen/paging.h>
#include <xen/keyhandler.h>
#include <xen/vmap.h>
#include <xen/nospec.h>
#include <xsm/xsm.h>
#include <asm/flushtlb.h>
#include <asm/guest_atomics.h>

/* Per-domain grant information. */
struct grant_table {
    /*
     * Lock protecting updates to grant table state (version, active
     * entry list, etc.)
     */
    percpu_rwlock_t       lock;
    /* Lock protecting the maptrack limit */
    spinlock_t            maptrack_lock;
    /*
     * Defaults to v1.  May be changed with GNTTABOP_set_version.  All other
     * values are invalid.
     */
    unsigned int          gt_version;
    /* Resource limits of the domain. */
    unsigned int          max_grant_frames;
    unsigned int          max_maptrack_frames;
    /* Table size. Number of frames shared with guest */
    unsigned int          nr_grant_frames;
    /* Number of grant status frames shared with guest (for version 2) */
    unsigned int          nr_status_frames;
    /* Number of available maptrack entries. */
    unsigned int          maptrack_limit;
    /* Shared grant table (see include/public/grant_table.h). */
    union {
        void **shared_raw;
        struct grant_entry_v1 **shared_v1;
        union grant_entry_v2 **shared_v2;
    };
    /* State grant table (see include/public/grant_table.h). */
    grant_status_t       **status;
    /* Active grant table. */
    struct active_grant_entry **active;
    /* Mapping tracking table per vcpu. */
    struct grant_mapping **maptrack;

    /* Domain to which this struct grant_table belongs. */
    const struct domain *domain;

    struct grant_table_arch arch;
};

static int parse_gnttab_limit(const char *param, const char *arg,
                              unsigned int *valp)
{
    const char *e;
    unsigned long val;

    val = simple_strtoul(arg, &e, 0);
    if ( *e )
        return -EINVAL;

    if ( val > INT_MAX )
        return -ERANGE;

    *valp = val;

    return 0;
}

unsigned int __read_mostly opt_max_grant_frames = 64;

static int parse_gnttab_max_frames(const char *arg)
{
    return parse_gnttab_limit("gnttab_max_frames", arg,
                              &opt_max_grant_frames);
}
custom_runtime_param("gnttab_max_frames", parse_gnttab_max_frames);

static unsigned int __read_mostly opt_max_maptrack_frames = 1024;

static int parse_gnttab_max_maptrack_frames(const char *arg)
{
    return parse_gnttab_limit("gnttab_max_maptrack_frames", arg,
                              &opt_max_maptrack_frames);
}
custom_runtime_param("gnttab_max_maptrack_frames",
                     parse_gnttab_max_maptrack_frames);

#ifndef GNTTAB_MAX_VERSION
#define GNTTAB_MAX_VERSION 2
#endif

static unsigned int __read_mostly opt_gnttab_max_version = GNTTAB_MAX_VERSION;
static bool __read_mostly opt_transitive_grants = true;

static int __init parse_gnttab(const char *s)
{
    const char *ss, *e;
    int val, rc = 0;

    do {
        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        if ( !strncmp(s, "max-ver:", 8) ||
             !strncmp(s, "max_ver:", 8) ) /* Alias for original XSA-226 patch */
        {
            long ver = simple_strtol(s + 8, &e, 10);

            if ( e == ss && ver >= 1 && ver <= 2 )
                opt_gnttab_max_version = ver;
            else
                rc = -EINVAL;
        }
        else if ( (val = parse_boolean("transitive", s, ss)) >= 0 )
            opt_transitive_grants = val;
        else
            rc = -EINVAL;

        s = ss + 1;
    } while ( *ss );

    return rc;
}
custom_param("gnttab", parse_gnttab);

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
    uint32_t raw;
    struct {
        uint16_t flags;
        domid_t  domid;
    };
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
    uint16_t done;
    mfn_t mfn;
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
    grant_ref_t ref;        /* grant ref */
    uint16_t flags;         /* 0-4: GNTMAP_* ; 5-15: unused */
    domid_t  domid;         /* granting domain */
    uint32_t vcpu;          /* vcpu which created the grant mapping */
    uint32_t pad;           /* round size to a power of 2 */
};

/* Number of grant table frames. Caller must hold d's grant table lock. */
static inline unsigned int nr_grant_frames(const struct grant_table *gt)
{
    return gt->nr_grant_frames;
}

/* Number of status grant table frames. Caller must hold d's gr. table lock.*/
static inline unsigned int nr_status_frames(const struct grant_table *gt)
{
    return gt->nr_status_frames;
}

#define MAPTRACK_PER_PAGE (PAGE_SIZE / sizeof(struct grant_mapping))
#define maptrack_entry(t, e)                                                   \
    ((t)->maptrack[array_index_nospec(e, (t)->maptrack_limit) /                \
                                    MAPTRACK_PER_PAGE][(e) % MAPTRACK_PER_PAGE])

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
    switch ( t->gt_version )
    {
    case 1:
        /* Returned values should be independent of speculative execution */
        block_speculation();
        return (grant_entry_header_t*)&shared_entry_v1(t, ref);

    case 2:
        /* Returned values should be independent of speculative execution */
        block_speculation();
        return &shared_entry_v2(t, ref).hdr;
    }

    ASSERT_UNREACHABLE();
    block_speculation();

    return NULL;
}

/* Active grant entry - used for shadowing GTF_permit_access grants. */
struct active_grant_entry {
    uint32_t      pin;    /* Reference count information:             */
                          /* Count of writable host-CPU mappings.     */
#define GNTPIN_hstw_shift    0
#define GNTPIN_hstw_inc      (1U << GNTPIN_hstw_shift)
#define GNTPIN_hstw_mask     (0xFFU << GNTPIN_hstw_shift)
                          /* Count of read-only host-CPU mappings.    */
#define GNTPIN_hstr_shift    8
#define GNTPIN_hstr_inc      (1U << GNTPIN_hstr_shift)
#define GNTPIN_hstr_mask     (0xFFU << GNTPIN_hstr_shift)
                          /* Count of writable device-bus mappings.   */
#define GNTPIN_devw_shift    16
#define GNTPIN_devw_inc      (1U << GNTPIN_devw_shift)
#define GNTPIN_devw_mask     (0xFFU << GNTPIN_devw_shift)
                          /* Count of read-only device-bus mappings.  */
#define GNTPIN_devr_shift    24
#define GNTPIN_devr_inc      (1U << GNTPIN_devr_shift)
#define GNTPIN_devr_mask     (0xFFU << GNTPIN_devr_shift)

    domid_t       domid;  /* Domain being granted access.             */
    unsigned int  start:15; /* For sub-page grants, the start offset
                               in the page.                           */
    bool          is_sub_page:1; /* True if this is a sub-page grant. */
    unsigned int  length:16; /* For sub-page grants, the length of the
                                grant.                                */
    grant_ref_t   trans_gref;
    struct domain *trans_domain;
    mfn_t         mfn;    /* Machine frame being granted.             */
#ifndef NDEBUG
    gfn_t         gfn;    /* Guest's idea of the frame being granted. */
#endif
    spinlock_t    lock;      /* lock to protect access of this entry.
                                see docs/misc/grant-tables.txt for
                                locking protocol                      */
};

#define ACGNT_PER_PAGE (PAGE_SIZE / sizeof(struct active_grant_entry))
#define _active_entry(t, e) \
    ((t)->active[(e)/ACGNT_PER_PAGE][(e)%ACGNT_PER_PAGE])

static inline void act_set_gfn(struct active_grant_entry *act, gfn_t gfn)
{
#ifndef NDEBUG
    act->gfn = gfn;
#endif
}

static DEFINE_PERCPU_RWLOCK_GLOBAL(grant_rwlock);

static inline void grant_read_lock(struct grant_table *gt)
{
    percpu_read_lock(grant_rwlock, &gt->lock);
}

static inline void grant_read_unlock(struct grant_table *gt)
{
    percpu_read_unlock(grant_rwlock, &gt->lock);
}

static inline void grant_write_lock(struct grant_table *gt)
{
    percpu_write_lock(grant_rwlock, &gt->lock);
}

static inline void grant_write_unlock(struct grant_table *gt)
{
    percpu_write_unlock(grant_rwlock, &gt->lock);
}

static inline void gnttab_flush_tlb(const struct domain *d)
{
    if ( !paging_mode_external(d) )
        flush_tlb_mask(d->dirty_cpumask);
}

static inline unsigned int
num_act_frames_from_sha_frames(const unsigned int num)
{
    /*
     * How many frames are needed for the active grant table,
     * given the size of the shared grant table?
     */
    unsigned int sha_per_page = PAGE_SIZE / sizeof(grant_entry_v1_t);

    return DIV_ROUND_UP(num * sha_per_page, ACGNT_PER_PAGE);
}

#define max_nr_active_grant_frames(gt) \
    num_act_frames_from_sha_frames((gt)->max_grant_frames)

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

#define GRANT_STATUS_PER_PAGE (PAGE_SIZE / sizeof(grant_status_t))
#define GRANT_PER_PAGE (PAGE_SIZE / sizeof(grant_entry_v2_t))

static inline unsigned int grant_to_status_frames(unsigned int grant_frames)
{
    return DIV_ROUND_UP(grant_frames * GRANT_PER_PAGE, GRANT_STATUS_PER_PAGE);
}

static inline unsigned int status_to_grant_frames(unsigned int status_frames)
{
    return DIV_ROUND_UP(status_frames * GRANT_STATUS_PER_PAGE, GRANT_PER_PAGE);
}

/* Check if the page has been paged out, or needs unsharing.
   If rc == GNTST_okay, *page contains the page struct with a ref taken.
   Caller must do put_page(*page).
   If any error, *page = NULL, *mfn = INVALID_MFN, no ref taken. */
static int get_paged_frame(unsigned long gfn, mfn_t *mfn,
                           struct page_info **page, bool readonly,
                           struct domain *rd)
{
    p2m_type_t p2mt;
    int rc;

    rc = check_get_page_from_gfn(rd, _gfn(gfn), readonly, &p2mt, page);
    switch ( rc )
    {
    case 0:
        break;

    case -EAGAIN:
        return GNTST_eagain;

    default:
        ASSERT_UNREACHABLE();
        /* Fallthrough */

    case -EINVAL:
        return GNTST_bad_page;
    }

    if ( p2m_is_foreign(p2mt) )
    {
        put_page(*page);
        *page = NULL;

        return GNTST_bad_page;
    }

    *mfn = page_to_mfn(*page);

    return GNTST_okay;
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

#define INVALID_MAPTRACK_HANDLE UINT_MAX

static inline grant_handle_t
_get_maptrack_handle(struct grant_table *t, struct vcpu *v)
{
    unsigned int head, next, prev_head;

    spin_lock(&v->maptrack_freelist_lock);

    do {
        /* No maptrack pages allocated for this VCPU yet? */
        head = read_atomic(&v->maptrack_head);
        if ( unlikely(head == MAPTRACK_TAIL) )
        {
            spin_unlock(&v->maptrack_freelist_lock);
            return INVALID_MAPTRACK_HANDLE;
        }

        /*
         * Always keep one entry in the free list to make it easier to
         * add free entries to the tail.
         */
        next = read_atomic(&maptrack_entry(t, head).ref);
        if ( unlikely(next == MAPTRACK_TAIL) )
        {
            spin_unlock(&v->maptrack_freelist_lock);
            return INVALID_MAPTRACK_HANDLE;
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
static grant_handle_t steal_maptrack_handle(struct grant_table *t,
                                            const struct vcpu *curr)
{
    const struct domain *currd = curr->domain;
    unsigned int first, i;

    /* Find an initial victim. */
    first = i = get_random() % currd->max_vcpus;

    do {
        if ( currd->vcpu[i] )
        {
            grant_handle_t handle;

            handle = _get_maptrack_handle(t, currd->vcpu[i]);
            if ( handle != INVALID_MAPTRACK_HANDLE )
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
    return INVALID_MAPTRACK_HANDLE;
}

static inline void
put_maptrack_handle(
    struct grant_table *t, grant_handle_t handle)
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

static inline grant_handle_t
get_maptrack_handle(
    struct grant_table *lgt)
{
    struct vcpu          *curr = current;
    unsigned int          i, head;
    grant_handle_t        handle;
    struct grant_mapping *new_mt = NULL;

    handle = _get_maptrack_handle(lgt, curr);
    if ( likely(handle != INVALID_MAPTRACK_HANDLE) )
        return handle;

    spin_lock(&lgt->maptrack_lock);

    /*
     * If we've run out of handles and still have frame headroom, try
     * allocating a new maptrack frame.  If there is no headroom, or we're
     * out of memory, try stealing an entry from another VCPU (in case the
     * guest isn't mapping across its VCPUs evenly).
     */
    if ( nr_maptrack_frames(lgt) < lgt->max_maptrack_frames )
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
            if ( handle == INVALID_MAPTRACK_HANDLE )
                return handle;
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
        BUILD_BUG_ON(sizeof(new_mt->ref) < sizeof(handle));
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

        /* Make sure we return a value independently of speculative execution */
        block_speculation();
        return f2e(nr_grant_frames(gt), 1);

    case 2:
        BUILD_BUG_ON(f2e(INITIAL_NR_GRANT_FRAMES, 2) <
                     GNTTAB_NR_RESERVED_ENTRIES);

        /* Make sure we return a value independently of speculative execution */
        block_speculation();
        return f2e(nr_grant_frames(gt), 2);
#undef f2e
    }

    ASSERT_UNREACHABLE();
    block_speculation();

    return 0;
}

static int _set_status_v1(const grant_entry_header_t *shah,
                          struct domain *rd,
                          struct active_grant_entry *act,
                          int readonly,
                          int mapflag,
                          domid_t  ldomid)
{
    int rc = GNTST_okay;
    uint32_t *raw_shah = (uint32_t *)shah;
    union grant_combo scombo;
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
    if ( mapflag )
        mask |= GTF_sub_page;

    scombo.raw = ACCESS_ONCE(*raw_shah);

    /*
     * This loop attempts to set the access (reading/writing) flags
     * in the grant table entry.  It tries a cmpxchg on the field
     * up to five times, and then fails under the assumption that
     * the guest is misbehaving.
     */
    for ( ; ; )
    {
        union grant_combo prev, new;

        /* If not already pinned, check the grant domid and type. */
        if ( !act->pin && (((scombo.flags & mask) != GTF_permit_access) ||
                           (scombo.domid != ldomid)) )
            PIN_FAIL(done, GNTST_general_error,
                     "Bad flags (%x) or dom (%d); expected d%d\n",
                     scombo.flags, scombo.domid, ldomid);

        new = scombo;
        new.flags |= GTF_reading;

        if ( !readonly )
        {
            new.flags |= GTF_writing;
            if ( unlikely(scombo.flags & GTF_readonly) )
                PIN_FAIL(done, GNTST_general_error,
                         "Attempt to write-pin a r/o grant entry\n");
        }

        prev.raw = guest_cmpxchg(rd, raw_shah, scombo.raw, new.raw);
        if ( likely(prev.raw == scombo.raw) )
            break;

        if ( retries++ == 4 )
            PIN_FAIL(done, GNTST_general_error,
                     "Shared grant entry is unstable\n");

        scombo = prev;
    }

done:
    return rc;
}

static int _set_status_v2(const grant_entry_header_t *shah,
                          grant_status_t *status,
                          struct domain *rd,
                          struct active_grant_entry *act,
                          int readonly,
                          int mapflag,
                          domid_t  ldomid)
{
    int      rc    = GNTST_okay;
    uint32_t *raw_shah = (uint32_t *)shah;
    union grant_combo scombo;
    uint16_t mask  = GTF_type_mask;

    scombo.raw = ACCESS_ONCE(*raw_shah);

    /* if this is a grant mapping operation we should ensure GTF_sub_page
       is not set */
    if ( mapflag )
        mask |= GTF_sub_page;

    /* If not already pinned, check the grant domid and type. */
    if ( !act->pin && ((((scombo.flags & mask) != GTF_permit_access) &&
                        ((scombo.flags & mask) != GTF_transitive)) ||
                       (scombo.domid != ldomid)) )
        PIN_FAIL(done, GNTST_general_error,
                 "Bad flags (%x) or dom (%d); expected d%d, flags %x\n",
                 scombo.flags, scombo.domid, ldomid, mask);

    if ( readonly )
    {
        *status |= GTF_reading;
    }
    else
    {
        if ( unlikely(scombo.flags & GTF_readonly) )
            PIN_FAIL(done, GNTST_general_error,
                     "Attempt to write-pin a r/o grant entry\n");
        *status |= GTF_reading | GTF_writing;
    }

    /* Make sure guest sees status update before checking if flags are
       still valid */
    smp_mb();

    scombo.raw = ACCESS_ONCE(*raw_shah);

    if ( !act->pin )
    {
        if ( (((scombo.flags & mask) != GTF_permit_access) &&
              ((scombo.flags & mask) != GTF_transitive)) ||
             (scombo.domid != ldomid) ||
             (!readonly && (scombo.flags & GTF_readonly)) )
        {
            gnttab_clear_flags(rd, GTF_writing | GTF_reading, status);
            PIN_FAIL(done, GNTST_general_error,
                     "Unstable flags (%x) or dom (%d); expected d%d (r/w: %d)\n",
                     scombo.flags, scombo.domid, ldomid, !readonly);
        }
    }
    else
    {
        if ( unlikely(scombo.flags & GTF_readonly) )
        {
            gnttab_clear_flags(rd, GTF_writing, status);
            PIN_FAIL(done, GNTST_general_error,
                     "Unstable grant readonly flag\n");
        }
    }

done:
    return rc;
}


static int _set_status(const grant_entry_header_t *shah,
                       grant_status_t *status,
                       struct domain *rd,
                       unsigned rgt_version,
                       struct active_grant_entry *act,
                       int readonly,
                       int mapflag,
                       domid_t ldomid)
{

    if ( evaluate_nospec(rgt_version == 1) )
        return _set_status_v1(shah, rd, act, readonly, mapflag, ldomid);
    else
        return _set_status_v2(shah, status, rd, act, readonly, mapflag, ldomid);
}

static struct active_grant_entry *grant_map_exists(const struct domain *ld,
                                                   struct grant_table *rgt,
                                                   mfn_t mfn,
                                                   grant_ref_t *cur_ref)
{
    grant_ref_t ref, max_iter;

    /*
     * The remote grant table should be locked but the percpu rwlock
     * cannot be checked for read lock without race conditions or high
     * overhead so we cannot use an ASSERT
     *
     *   ASSERT(rw_is_locked(&rgt->lock));
     */

    max_iter = min(*cur_ref + (1 << GNTTABOP_CONTINUATION_ARG_SHIFT),
                   nr_grant_entries(rgt));
    for ( ref = *cur_ref; ref < max_iter; ref++ )
    {
        struct active_grant_entry *act = active_entry_acquire(rgt, ref);

        if ( act->pin && act->domid == ld->domain_id &&
             mfn_eq(act->mfn, mfn) )
            return act;
        active_entry_release(act);
    }

    if ( ref < nr_grant_entries(rgt) )
    {
        *cur_ref = ref;
        return NULL;
    }

    return ERR_PTR(-EINVAL);
}

#define MAPKIND_READ 1
#define MAPKIND_WRITE 2
static unsigned int mapkind(
    struct grant_table *lgt, const struct domain *rd, mfn_t mfn)
{
    struct grant_mapping *map;
    grant_handle_t handle, limit = lgt->maptrack_limit;
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

    smp_rmb();

    for ( handle = 0; !(kind & MAPKIND_WRITE) && handle < limit; handle++ )
    {
        map = &maptrack_entry(lgt, handle);
        if ( !(map->flags & (GNTMAP_device_map|GNTMAP_host_map)) ||
             map->domid != rd->domain_id )
            continue;
        if ( mfn_eq(_active_entry(rd->grant_table, map->ref).mfn, mfn) )
            kind |= map->flags & GNTMAP_readonly ?
                    MAPKIND_READ : MAPKIND_WRITE;
    }

    return kind;
}

static void
map_grant_ref(
    struct gnttab_map_grant_ref *op)
{
    struct domain *ld, *rd, *owner = NULL;
    struct grant_table *lgt, *rgt;
    grant_ref_t ref;
    struct vcpu   *led;
    grant_handle_t handle;
    mfn_t mfn;
    struct page_info *pg = NULL;
    int            rc = GNTST_okay;
    unsigned int   cache_flags, clear_flags = 0, refcnt = 0, typecnt = 0;
    bool           host_map_created = false;
    struct active_grant_entry *act = NULL;
    struct grant_mapping *mt;
    grant_entry_header_t *shah;
    uint16_t *status;
    bool_t need_iommu;

    led = current;
    ld = led->domain;

    if ( unlikely((op->flags & (GNTMAP_device_map|GNTMAP_host_map)) == 0) )
    {
        gdprintk(XENLOG_INFO, "Bad flags in grant map op: %x\n", op->flags);
        op->status = GNTST_bad_gntref;
        return;
    }

    if ( unlikely(paging_mode_external(ld) &&
                  (op->flags & (GNTMAP_device_map|GNTMAP_application_map|
                            GNTMAP_contains_pte))) )
    {
        gdprintk(XENLOG_INFO, "No device mapping in HVM domain\n");
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
    handle = get_maptrack_handle(lgt);
    if ( unlikely(handle == INVALID_MAPTRACK_HANDLE) )
    {
        rcu_unlock_domain(rd);
        gdprintk(XENLOG_INFO, "Failed to obtain maptrack handle\n");
        op->status = GNTST_no_device_space;
        return;
    }

    rgt = rd->grant_table;
    grant_read_lock(rgt);

    /* Bounds check on the grant ref */
    ref = op->ref;
    if ( unlikely(ref >= nr_grant_entries(rgt)))
        PIN_FAIL(unlock_out, GNTST_bad_gntref, "Bad ref %#x for d%d\n",
                 ref, rgt->domain->domain_id);

    /* This call also ensures the above check cannot be passed speculatively */
    shah = shared_entry_header(rgt, ref);
    act = active_entry_acquire(rgt, ref);

    /* Make sure we do not access memory speculatively */
    status = evaluate_nospec(rgt->gt_version == 1) ? &shah->flags
                                                 : &status_entry(rgt, ref);

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
        if ( (rc = _set_status(shah, status, rd, rgt->gt_version, act,
                               op->flags & GNTMAP_readonly, 1,
                               ld->domain_id) != GNTST_okay) )
            goto act_release_out;

        if ( !act->pin )
        {
            unsigned long gfn = evaluate_nospec(rgt->gt_version == 1) ?
                                shared_entry_v1(rgt, ref).frame :
                                shared_entry_v2(rgt, ref).full_page.frame;

            rc = get_paged_frame(gfn, &mfn, &pg,
                                 op->flags & GNTMAP_readonly, rd);
            if ( rc != GNTST_okay )
                goto unlock_out_clear;
            act_set_gfn(act, _gfn(gfn));
            act->domid = ld->domain_id;
            act->mfn = mfn;
            act->start = 0;
            act->length = PAGE_SIZE;
            act->is_sub_page = false;
            act->trans_domain = rd;
            act->trans_gref = ref;
        }
    }

    if ( op->flags & GNTMAP_device_map )
        act->pin += (op->flags & GNTMAP_readonly) ?
            GNTPIN_devr_inc : GNTPIN_devw_inc;
    if ( op->flags & GNTMAP_host_map )
        act->pin += (op->flags & GNTMAP_readonly) ?
            GNTPIN_hstr_inc : GNTPIN_hstw_inc;

    mfn = act->mfn;

    cache_flags = (shah->flags & (GTF_PAT | GTF_PWT | GTF_PCD) );

    active_entry_release(act);
    grant_read_unlock(rgt);

    /* pg may be set, with a refcount included, from get_paged_frame(). */
    if ( !pg )
    {
        pg = mfn_valid(mfn) ? mfn_to_page(mfn) : NULL;
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

        if ( !iomem_access_permitted(rd, mfn_x(mfn), mfn_x(mfn)) )
        {
            gdprintk(XENLOG_WARNING,
                     "Iomem mapping not permitted %#"PRI_mfn" (domain %d)\n",
                     mfn_x(mfn), rd->domain_id);
            rc = GNTST_general_error;
            goto undo_out;
        }

        if ( op->flags & GNTMAP_host_map )
        {
            rc = create_grant_host_mapping(op->host_addr, mfn, op->flags,
                                           cache_flags);
            if ( rc != GNTST_okay )
                goto undo_out;

            host_map_created = true;
        }
    }
    else if ( owner == rd || (dom_cow && owner == dom_cow) )
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

            rc = create_grant_host_mapping(op->host_addr, mfn, op->flags, 0);
            if ( rc != GNTST_okay )
                goto undo_out;

            host_map_created = true;
        }
    }
    else
    {
    could_not_pin:
        if ( !rd->is_dying )
            gdprintk(XENLOG_WARNING, "Could not pin grant frame %#"PRI_mfn"\n",
                     mfn_x(mfn));
        rc = GNTST_general_error;
        goto undo_out;
    }

    need_iommu = gnttab_need_iommu_mapping(ld);
    if ( need_iommu )
    {
        unsigned int kind;

        double_gt_lock(lgt, rgt);

        /*
         * We're not translated, so we know that dfns and mfns are
         * the same things, so the IOMMU entry is always 1-to-1.
         */
        kind = mapkind(lgt, rd, mfn);
        if ( !(op->flags & GNTMAP_readonly) &&
             !(kind & MAPKIND_WRITE) )
            kind = IOMMUF_readable | IOMMUF_writable;
        else if ( !kind )
            kind = IOMMUF_readable;
        else
            kind = 0;
        if ( kind && iommu_legacy_map(ld, _dfn(mfn_x(mfn)), mfn, 0, kind) )
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
     * with a concurrent mapkind() call (on an unmap, for example)
     * and a lock is required.
     */
    mt = &maptrack_entry(lgt, handle);
    mt->domid = op->dom;
    mt->ref   = op->ref;
    smp_wmb();
    write_atomic(&mt->flags, op->flags);

    if ( need_iommu )
        double_gt_unlock(lgt, rgt);

    op->dev_bus_addr = mfn_to_maddr(mfn);
    op->handle       = handle;
    op->status       = GNTST_okay;

    rcu_unlock_domain(rd);
    return;

 undo_out:
    if ( host_map_created )
    {
        replace_grant_host_mapping(op->host_addr, mfn, 0, op->flags);
        gnttab_flush_tlb(ld);
    }

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
        clear_flags |= GTF_writing;

    if ( !act->pin )
        clear_flags |= GTF_reading;

    if ( clear_flags )
        gnttab_clear_flags(rd, clear_flags, status);

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
        if ( i && hypercall_preempt_check() )
            return i;

        if ( unlikely(__copy_from_guest_offset(&op, uop, i, 1)) )
            return -EFAULT;

        map_grant_ref(&op);

        if ( unlikely(__copy_to_guest_offset(uop, i, &op, 1)) )
            return -EFAULT;
    }

    return 0;
}

static void
unmap_common(
    struct gnttab_unmap_common *op)
{
    domid_t          dom;
    struct domain   *ld, *rd;
    struct grant_table *lgt, *rgt;
    grant_ref_t ref;
    struct active_grant_entry *act;
    s16              rc = 0;
    struct grant_mapping *map;
    unsigned int flags;
    bool put_handle = false;

    ld = current->domain;
    lgt = ld->grant_table;

    if ( unlikely(op->handle >= lgt->maptrack_limit) )
    {
        gdprintk(XENLOG_INFO, "Bad d%d handle %#x\n",
                 lgt->domain->domain_id, op->handle);
        op->status = GNTST_bad_handle;
        return;
    }

    smp_rmb();
    map = &maptrack_entry(lgt, op->handle);

    if ( unlikely(!read_atomic(&map->flags)) )
    {
        gdprintk(XENLOG_INFO, "Zero flags for d%d handle %#x\n",
                 lgt->domain->domain_id, op->handle);
        op->status = GNTST_bad_handle;
        return;
    }

    dom = map->domid;
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

    op->rd = rd;
    op->ref = map->ref;
    ref = map->ref;

    /*
     * We can't assume there was no racing unmap for this maptrack entry,
     * and hence we can't assume map->ref is valid for rd. While the checks
     * below (with the active entry lock held) will reject any such racing
     * requests, we still need to make sure we don't attempt to acquire an
     * invalid lock.
     */
    smp_rmb();
    if ( unlikely(ref >= nr_grant_entries(rgt)) )
    {
        gdprintk(XENLOG_WARNING, "Unstable d%d handle %#x\n",
                 rgt->domain->domain_id, op->handle);
        rc = GNTST_bad_handle;
        flags = 0;
        goto unlock_out;
    }

    /* Make sure the above bound check cannot be bypassed speculatively */
    block_speculation();

    act = active_entry_acquire(rgt, ref);

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
         unlikely(map->ref != ref) )
    {
        gdprintk(XENLOG_WARNING, "Unstable handle %#x\n", op->handle);
        rc = GNTST_bad_handle;
        goto act_release_out;
    }

    op->mfn = act->mfn;

    if ( op->dev_bus_addr &&
         unlikely(op->dev_bus_addr != mfn_to_maddr(act->mfn)) )
        PIN_FAIL(act_release_out, GNTST_general_error,
                 "Bus address doesn't match gntref (%"PRIx64" != %"PRIpaddr")\n",
                 op->dev_bus_addr, mfn_to_maddr(act->mfn));

    if ( op->host_addr && (flags & GNTMAP_host_map) )
    {
        if ( (rc = replace_grant_host_mapping(op->host_addr,
                                              op->mfn, op->new_addr,
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

        kind = mapkind(lgt, rd, op->mfn);
        if ( !kind )
            err = iommu_legacy_unmap(ld, _dfn(mfn_x(op->mfn)), 0);
        else if ( !(kind & MAPKIND_WRITE) )
            err = iommu_legacy_map(ld, _dfn(mfn_x(op->mfn)), op->mfn, 0,
                                   IOMMUF_readable);

        double_gt_unlock(lgt, rgt);

        if ( err )
            rc = GNTST_general_error;
    }

    /* If just unmapped a writable mapping, mark as dirtied */
    if ( rc == GNTST_okay && !(flags & GNTMAP_readonly) )
         gnttab_mark_dirty(rd, op->mfn);

    op->status = rc;
    rcu_unlock_domain(rd);
}

static void
unmap_common_complete(struct gnttab_unmap_common *op)
{
    struct domain *ld, *rd = op->rd;
    struct grant_table *rgt;
    struct active_grant_entry *act;
    grant_entry_header_t *sha;
    struct page_info *pg;
    uint16_t *status;
    unsigned int clear_flags = 0;

    if ( evaluate_nospec(!op->done) )
    {
        /* unmap_common() didn't do anything - nothing to complete. */
        return;
    }

    ld = current->domain;

    rcu_lock_domain(rd);
    rgt = rd->grant_table;

    grant_read_lock(rgt);

    act = active_entry_acquire(rgt, op->ref);
    sha = shared_entry_header(rgt, op->ref);

    if ( evaluate_nospec(rgt->gt_version == 1) )
        status = &sha->flags;
    else
        status = &status_entry(rgt, op->ref);

    pg = mfn_to_page(op->mfn);

    if ( op->done & GNTMAP_device_map )
    {
        if ( !is_iomem_page(act->mfn) )
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
        if ( !is_iomem_page(op->mfn) )
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
        clear_flags |= GTF_writing;

    if ( act->pin == 0 )
        clear_flags |= GTF_reading;

    if ( clear_flags )
        gnttab_clear_flags(rd, clear_flags, status);

    active_entry_release(act);
    grant_read_unlock(rgt);

    rcu_unlock_domain(rd);
}

static void
unmap_grant_ref(
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
    common->mfn = INVALID_MFN;

    unmap_common(common);
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
            unmap_grant_ref(&op, &common[i]);
            ++partial_done;
            if ( unlikely(__copy_field_to_guest(uop, &op, status)) )
                goto fault;
            guest_handle_add_offset(uop, 1);
        }

        gnttab_flush_tlb(current->domain);

        for ( i = 0; i < partial_done; i++ )
            unmap_common_complete(&common[i]);

        count -= c;
        done += c;

        if ( count && hypercall_preempt_check() )
            return done;
    }

    return 0;

fault:
    gnttab_flush_tlb(current->domain);

    for ( i = 0; i < partial_done; i++ )
        unmap_common_complete(&common[i]);
    return -EFAULT;
}

static void
unmap_and_replace(
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
    common->mfn = INVALID_MFN;

    unmap_common(common);
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
            unmap_and_replace(&op, &common[i]);
            ++partial_done;
            if ( unlikely(__copy_field_to_guest(uop, &op, status)) )
                goto fault;
            guest_handle_add_offset(uop, 1);
        }

        gnttab_flush_tlb(current->domain);

        for ( i = 0; i < partial_done; i++ )
            unmap_common_complete(&common[i]);

        count -= c;
        done += c;

        if ( count && hypercall_preempt_check() )
            return done;
    }

    return 0;

fault:
    gnttab_flush_tlb(current->domain);

    for ( i = 0; i < partial_done; i++ )
        unmap_common_complete(&common[i]);
    return -EFAULT;
}

static int
gnttab_populate_status_frames(struct domain *d, struct grant_table *gt,
                              unsigned int req_nr_frames)
{
    unsigned i;
    unsigned req_status_frames;

    req_status_frames = grant_to_status_frames(req_nr_frames);

    /* Make sure, prior version checks are architectural visible */
    block_speculation();

    for ( i = nr_status_frames(gt); i < req_status_frames; i++ )
    {
        if ( (gt->status[i] = alloc_xenheap_page()) == NULL )
            goto status_alloc_failed;
        clear_page(gt->status[i]);
    }
    /* Share the new status frames with the recipient domain */
    for ( i = nr_status_frames(gt); i < req_status_frames; i++ )
        share_xen_page_with_guest(virt_to_page(gt->status[i]), d, SHARE_rw);

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

static int
gnttab_unpopulate_status_frames(struct domain *d, struct grant_table *gt)
{
    unsigned int i;

    /* Make sure, prior version checks are architectural visible */
    block_speculation();

    for ( i = 0; i < nr_status_frames(gt); i++ )
    {
        struct page_info *pg = virt_to_page(gt->status[i]);
        gfn_t gfn = gnttab_get_frame_gfn(gt, true, i);

        /*
         * For translated domains, recovering from failure after partial
         * changes were made is more complicated than it seems worth
         * implementing at this time. Hence respective error paths below
         * crash the domain in such a case.
         */
        if ( paging_mode_translate(d) )
        {
            int rc = gfn_eq(gfn, INVALID_GFN)
                     ? 0
                     : guest_physmap_remove_page(d, gfn,
                                                 page_to_mfn(pg), 0);

            if ( rc )
            {
                gprintk(XENLOG_ERR,
                        "Could not remove status frame %u (GFN %#lx) from P2M\n",
                        i, gfn_x(gfn));
                domain_crash(d);
                return rc;
            }
            gnttab_set_frame_gfn(gt, true, i, INVALID_GFN);
        }

        BUG_ON(page_get_owner(pg) != d);
        put_page_alloc_ref(pg);

        if ( pg->count_info & ~PGC_xen_heap )
        {
            if ( paging_mode_translate(d) )
            {
                gprintk(XENLOG_ERR,
                        "Wrong page state %#lx of status frame %u (GFN %#lx)\n",
                        pg->count_info, i, gfn_x(gfn));
                domain_crash(d);
            }
            else
            {
                if ( get_page(pg, d) )
                    set_bit(_PGC_allocated, &pg->count_info);
                while ( i-- )
                    share_xen_page_with_guest(virt_to_page(gt->status[i]),
                                              d, SHARE_rw);
            }
            return -EBUSY;
        }

        page_set_owner(pg, NULL);
    }

    for ( i = 0; i < nr_status_frames(gt); i++ )
    {
        free_xenheap_page(gt->status[i]);
        gt->status[i] = NULL;
    }
    gt->nr_status_frames = 0;

    return 0;
}

/*
 * Grow the grant table. The caller must hold the grant table's
 * write lock before calling this function.
 */
static int
gnttab_grow_table(struct domain *d, unsigned int req_nr_frames)
{
    struct grant_table *gt = d->grant_table;
    unsigned int i, j;

    if ( req_nr_frames < INITIAL_NR_GRANT_FRAMES )
        req_nr_frames = INITIAL_NR_GRANT_FRAMES;
    ASSERT(req_nr_frames <= gt->max_grant_frames);

    if ( req_nr_frames > INITIAL_NR_GRANT_FRAMES )
        gdprintk(XENLOG_INFO,
                 "Expanding d%d grant table from %u to %u frames\n",
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
    if ( evaluate_nospec(gt->gt_version > 1) )
    {
        if ( gnttab_populate_status_frames(d, gt, req_nr_frames) )
            goto shared_alloc_failed;
    }

    /* Share the new shared frames with the recipient domain */
    for ( i = nr_grant_frames(gt); i < req_nr_frames; i++ )
        share_xen_page_with_guest(virt_to_page(gt->shared_raw[i]), d, SHARE_rw);
    gt->nr_grant_frames = req_nr_frames;

    return 0;

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
    gdprintk(XENLOG_INFO, "Allocation failure when expanding d%d grant table\n",
             d->domain_id);

    return -ENOMEM;
}

int grant_table_init(struct domain *d, int max_grant_frames,
                     int max_maptrack_frames)
{
    struct grant_table *gt;
    int ret = -ENOMEM;

    /* Default to maximum value if no value was specified */
    if ( max_grant_frames < 0 )
        max_grant_frames = opt_max_grant_frames;
    if ( max_maptrack_frames < 0 )
        max_maptrack_frames = opt_max_maptrack_frames;

    if ( max_grant_frames < INITIAL_NR_GRANT_FRAMES ||
         max_grant_frames > opt_max_grant_frames ||
         max_maptrack_frames > opt_max_maptrack_frames )
        return -EINVAL;

    if ( (gt = xzalloc(struct grant_table)) == NULL )
        return -ENOMEM;

    /* Simple stuff. */
    percpu_rwlock_resource_init(&gt->lock, grant_rwlock);
    spin_lock_init(&gt->maptrack_lock);

    gt->gt_version = 1;
    gt->max_grant_frames = max_grant_frames;
    gt->max_maptrack_frames = max_maptrack_frames;

    /* Install the structure early to simplify the error path. */
    gt->domain = d;
    d->grant_table = gt;

    /* Active grant table. */
    gt->active = xzalloc_array(struct active_grant_entry *,
                               max_nr_active_grant_frames(gt));
    if ( gt->active == NULL )
        goto out;

    /* Tracking of mapped foreign frames table */
    if ( gt->max_maptrack_frames )
    {
        gt->maptrack = vzalloc(gt->max_maptrack_frames * sizeof(*gt->maptrack));
        if ( gt->maptrack == NULL )
            goto out;
    }

    /* Shared grant table. */
    gt->shared_raw = xzalloc_array(void *, gt->max_grant_frames);
    if ( gt->shared_raw == NULL )
        goto out;

    /* Status pages for grant table - for version 2 */
    gt->status = xzalloc_array(grant_status_t *,
                               grant_to_status_frames(gt->max_grant_frames));
    if ( gt->status == NULL )
        goto out;

    grant_write_lock(gt);

    ret = gnttab_init_arch(gt);
    if ( ret )
        goto unlock;

    /* gnttab_grow_table() allocates a min number of frames, so 0 is okay. */
    ret = gnttab_grow_table(d, 0);

 unlock:
    grant_write_unlock(gt);

 out:
    if ( ret )
        grant_table_destroy(d);

    return ret;
}

static long
gnttab_setup_table(
    XEN_GUEST_HANDLE_PARAM(gnttab_setup_table_t) uop, unsigned int count,
    unsigned int limit_max)
{
    struct vcpu *curr = current;
    struct gnttab_setup_table op;
    struct domain *d = NULL;
    struct grant_table *gt;
    unsigned int i;

    if ( count != 1 )
        return -EINVAL;

    if ( unlikely(copy_from_guest(&op, uop, 1)) )
        return -EFAULT;

    if ( !guest_handle_okay(op.frame_list, op.nr_frames) )
        return -EFAULT;

    d = rcu_lock_domain_by_any_id(op.dom);
    if ( d == NULL )
    {
        op.status = GNTST_bad_domain;
        goto out;
    }

    if ( xsm_grant_setup(XSM_TARGET, curr->domain, d) )
    {
        op.status = GNTST_permission_denied;
        goto out;
    }

    gt = d->grant_table;
    grant_write_lock(gt);

    if ( unlikely(op.nr_frames > gt->max_grant_frames) )
    {
        gdprintk(XENLOG_INFO, "d%d is limited to %u grant-table frames\n",
                d->domain_id, gt->max_grant_frames);
        op.status = GNTST_general_error;
        goto unlock;
    }
    if ( unlikely(limit_max < op.nr_frames) )
    {
        gdprintk(XENLOG_WARNING, "nr_frames for d%d is too large (%u,%u)\n",
                 d->domain_id, op.nr_frames, limit_max);
        op.status = GNTST_general_error;
        goto unlock;
    }

    if ( (op.nr_frames > nr_grant_frames(gt) ||
          ((gt->gt_version > 1) &&
           (grant_to_status_frames(op.nr_frames) > nr_status_frames(gt)))) &&
         gnttab_grow_table(d, op.nr_frames) )
    {
        gdprintk(XENLOG_INFO,
                 "Expand grant table of d%d to %u failed. Current: %u Max: %u\n",
                 d->domain_id, op.nr_frames, nr_grant_frames(gt),
                 gt->max_grant_frames);
        op.status = GNTST_general_error;
        goto unlock;
    }

    op.status = GNTST_okay;
    for ( i = 0; i < op.nr_frames; i++ )
    {
        xen_pfn_t gmfn = gfn_x(gnttab_shared_gfn(d, gt, i));

        /* Grant tables cannot be shared */
        BUG_ON(SHARED_M2P(gmfn));

        if ( __copy_to_guest_offset(op.frame_list, i, &gmfn, 1) )
            op.status = GNTST_bad_virt_addr;
    }

 unlock:
    grant_write_unlock(gt);
 out:
    if ( d )
        rcu_unlock_domain(d);

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
    struct grant_table *gt;

    if ( count != 1 )
        return -EINVAL;

    if ( unlikely(copy_from_guest(&op, uop, 1)) )
        return -EFAULT;

    d = rcu_lock_domain_by_any_id(op.dom);
    if ( d == NULL )
    {
        op.status = GNTST_bad_domain;
        goto out;
    }

    if ( xsm_grant_query_size(XSM_TARGET, current->domain, d) )
    {
        op.status = GNTST_permission_denied;
        goto out;
    }

    gt = d->grant_table;

    grant_read_lock(gt);

    op.nr_frames     = nr_grant_frames(gt);
    op.max_nr_frames = gt->max_grant_frames;
    op.status        = GNTST_okay;

    grant_read_unlock(gt);

 out:
    if ( d )
        rcu_unlock_domain(d);

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
    uint32_t *raw_shah;
    union grant_combo scombo;
    int                 retries = 0;

    grant_read_lock(rgt);

    if ( unlikely(ref >= nr_grant_entries(rgt)) )
    {
        gdprintk(XENLOG_INFO,
                "Bad grant reference %#x for transfer to d%d\n",
                ref, rd->domain_id);
        goto fail;
    }

    /* This call also ensures the above check cannot be passed speculatively */
    raw_shah = (uint32_t *)shared_entry_header(rgt, ref);
    scombo.raw = ACCESS_ONCE(*raw_shah);

    for ( ; ; )
    {
        union grant_combo prev, new;

        if ( unlikely(scombo.flags != GTF_accept_transfer) ||
             unlikely(scombo.domid != ld->domain_id) )
        {
            gdprintk(XENLOG_INFO,
                     "Bad flags (%x) or dom (%d); expected d%d\n",
                     scombo.flags, scombo.domid, ld->domain_id);
            goto fail;
        }

        new = scombo;
        new.flags |= GTF_transfer_committed;

        prev.raw = guest_cmpxchg(rd, raw_shah, scombo.raw, new.raw);
        if ( likely(prev.raw == scombo.raw) )
            break;

        if ( retries++ == 4 )
        {
            gdprintk(XENLOG_WARNING, "Shared grant entry is unstable\n");
            goto fail;
        }

        scombo = prev;
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
    mfn_t mfn;
    unsigned int max_bitsize;
    struct active_grant_entry *act;

    for ( i = 0; i < count; i++ )
    {
        bool_t okay;
        int rc;

        if ( i && hypercall_preempt_check() )
            return i;

        /* Read from caller address space. */
        if ( unlikely(__copy_from_guest(&gop, uop, 1)) )
        {
            gdprintk(XENLOG_INFO, "error reading req %d/%u\n",
                    i, count);
            return -EFAULT;
        }

#ifdef CONFIG_X86
        {
            p2m_type_t p2mt;

            mfn = get_gfn_unshare(d, gop.mfn, &p2mt);
            if ( p2m_is_shared(p2mt) || !p2m_is_valid(p2mt) )
                mfn = INVALID_MFN;
        }
#else
        mfn = gfn_to_mfn(d, _gfn(gop.mfn));
#endif

        /* Check the passed page frame for basic validity. */
        if ( unlikely(!mfn_valid(mfn)) )
        {
#ifdef CONFIG_X86
            put_gfn(d, gop.mfn);
#endif
            gdprintk(XENLOG_INFO, "out-of-range %lx\n", (unsigned long)gop.mfn);
            gop.status = GNTST_bad_page;
            goto copyback;
        }

        page = mfn_to_page(mfn);
        if ( (rc = steal_page(d, page, 0)) < 0 )
        {
#ifdef CONFIG_X86
            put_gfn(d, gop.mfn);
#endif
            gop.status = rc == -EINVAL ? GNTST_bad_page : GNTST_general_error;
            goto copyback;
        }

        rc = guest_physmap_remove_page(d, _gfn(gop.mfn), mfn, 0);
        gnttab_flush_tlb(d);
        if ( rc )
        {
            gdprintk(XENLOG_INFO,
                     "can't remove GFN %"PRI_xen_pfn" (MFN %#"PRI_mfn")\n",
                     gop.mfn, mfn_x(mfn));
            gop.status = GNTST_general_error;
            goto put_gfn_and_copyback;
        }

        /* Find the target domain. */
        if ( unlikely((e = rcu_lock_domain_by_id(gop.domid)) == NULL) )
        {
            gdprintk(XENLOG_INFO, "can't find d%d\n", gop.domid);
            gop.status = GNTST_bad_domain;
            goto put_gfn_and_copyback;
        }

        if ( xsm_grant_transfer(XSM_HOOK, d, e) )
        {
            gop.status = GNTST_permission_denied;
        unlock_and_copyback:
            rcu_unlock_domain(e);
        put_gfn_and_copyback:
#ifdef CONFIG_X86
            put_gfn(d, gop.mfn);
#endif
            /* The count_info has already been cleaned */
            free_domheap_page(page);
            goto copyback;
        }

        max_bitsize = domain_clamp_alloc_bitsize(
            e, e->grant_table->gt_version > 1 || paging_mode_translate(e)
               ? BITS_PER_LONG + PAGE_SHIFT : 32 + PAGE_SHIFT);
        if ( max_bitsize < BITS_PER_LONG + PAGE_SHIFT &&
             (mfn_x(mfn) >> (max_bitsize - PAGE_SHIFT)) )
        {
            struct page_info *new_page;

            new_page = alloc_domheap_page(e, MEMF_no_owner |
                                             MEMF_bits(max_bitsize));
            if ( new_page == NULL )
            {
                gop.status = GNTST_address_too_big;
                goto unlock_and_copyback;
            }

            copy_domain_page(page_to_mfn(new_page), mfn);

            /* The count_info has already been cleared */
            free_domheap_page(page);
            page = new_page;
            mfn = page_to_mfn(page);
        }

        spin_lock(&e->page_alloc_lock);

        /*
         * Check that 'e' will accept the page and has reservation
         * headroom.  Also, a domain mustn't have PGC_allocated
         * pages when it is dying.
         */
        if ( unlikely(e->is_dying) ||
             unlikely(domain_tot_pages(e) >= e->max_pages) )
        {
            spin_unlock(&e->page_alloc_lock);

            if ( e->is_dying )
                gdprintk(XENLOG_INFO, "Transferee d%d is dying\n",
                         e->domain_id);
            else
                gdprintk(XENLOG_INFO,
                         "Transferee d%d has no headroom (tot %u, max %u)\n",
                         e->domain_id, domain_tot_pages(e), e->max_pages);

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

        /*
         * Make sure the reference bound check in gnttab_prepare_for_transfer
         * is respected and speculative execution is blocked accordingly
         */
        if ( unlikely(!evaluate_nospec(okay)) ||
            unlikely(assign_pages(e, page, 0, MEMF_no_refcount)) )
        {
            bool drop_dom_ref;

            /*
             * Need to grab this again to safely free our "reserved"
             * page in the page total
             */
            spin_lock(&e->page_alloc_lock);
            drop_dom_ref = !domain_adjust_tot_pages(e, -1);
            spin_unlock(&e->page_alloc_lock);

            if ( okay /* i.e. e->is_dying due to the surrounding if() */ )
                gdprintk(XENLOG_INFO, "Transferee d%d is now dying\n",
                         e->domain_id);

            if ( drop_dom_ref )
                put_domain(e);
            gop.status = GNTST_general_error;
            goto unlock_and_copyback;
        }

#ifdef CONFIG_X86
        put_gfn(d, gop.mfn);
#endif

        TRACE_1D(TRC_MEM_PAGE_GRANT_TRANSFER, e->domain_id);

        /* Tell the guest about its new page frame. */
        grant_read_lock(e->grant_table);
        act = active_entry_acquire(e->grant_table, gop.ref);

        if ( evaluate_nospec(e->grant_table->gt_version == 1) )
        {
            grant_entry_v1_t *sha = &shared_entry_v1(e->grant_table, gop.ref);

            guest_physmap_add_page(e, _gfn(sha->frame), mfn, 0);
            if ( !paging_mode_translate(e) )
                sha->frame = mfn_x(mfn);
        }
        else
        {
            grant_entry_v2_t *sha = &shared_entry_v2(e->grant_table, gop.ref);

            guest_physmap_add_page(e, _gfn(sha->full_page.frame), mfn, 0);
            if ( !paging_mode_translate(e) )
                sha->full_page.frame = mfn_x(mfn);
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
            gdprintk(XENLOG_INFO, "error writing resp %d/%u\n", i, count);
            return -EFAULT;
        }
        guest_handle_add_offset(uop, 1);
    }

    return 0;
}

/*
 * Undo acquire_grant_for_copy().  This has no effect on page type and
 * reference counts.
 */
static void
release_grant_for_copy(
    struct domain *rd, grant_ref_t gref, bool readonly)
{
    struct grant_table *rgt = rd->grant_table;
    grant_entry_header_t *sha;
    struct active_grant_entry *act;
    mfn_t mfn;
    uint16_t *status;
    grant_ref_t trans_gref;
    struct domain *td;
    unsigned int clear_flags = 0;

    grant_read_lock(rgt);

    act = active_entry_acquire(rgt, gref);
    sha = shared_entry_header(rgt, gref);
    mfn = act->mfn;

    if ( evaluate_nospec(rgt->gt_version == 1) )
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
        gnttab_mark_dirty(rd, mfn);

        act->pin -= GNTPIN_hstw_inc;
        if ( !(act->pin & (GNTPIN_devw_mask|GNTPIN_hstw_mask)) )
            clear_flags |= GTF_writing;
    }

    if ( !act->pin )
        clear_flags |= GTF_reading;

    if ( clear_flags )
        gnttab_clear_flags(rd, clear_flags, status);

    active_entry_release(act);
    grant_read_unlock(rgt);

    if ( td != rd )
    {
        /*
         * Recursive call, but it is bounded (acquire permits only a single
         * level of transitivity), so it's okay.
         */
        release_grant_for_copy(td, trans_gref, readonly);

        rcu_unlock_domain(td);
    }
}

/* The status for a grant indicates that we're taking more access than
   the pin requires.  Fix up the status to match the pin.  Called
   under the domain's grant table lock. */
/* Only safe on transitive grants.  Even then, note that we don't
   attempt to drop any pin on the referent grant. */
static void fixup_status_for_copy_pin(struct domain *rd,
                                      const struct active_grant_entry *act,
                                      uint16_t *status)
{
    unsigned int clear_flags = 0;

    if ( !(act->pin & (GNTPIN_hstw_mask | GNTPIN_devw_mask)) )
        clear_flags |= GTF_writing;

    if ( !act->pin )
        clear_flags |= GTF_reading;

    if ( clear_flags )
        gnttab_clear_flags(rd, clear_flags, status);
}

/*
 * Grab a machine frame number from a grant entry and update the flags
 * and pin count as appropriate. If rc == GNTST_okay, note that this *does*
 * take one ref count on the target page, stored in *page.
 * If there is any error, *page = NULL, no ref taken.
 */
static int
acquire_grant_for_copy(
    struct domain *rd, grant_ref_t gref, domid_t ldom, bool readonly,
    mfn_t *mfn, struct page_info **page, uint16_t *page_off,
    uint16_t *length, bool allow_transitive)
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
    mfn_t grant_mfn;
    uint16_t trans_page_off;
    uint16_t trans_length;
    bool is_sub_page;
    s16 rc = GNTST_okay;
    unsigned int clear_flags = 0;

    *page = NULL;

    grant_read_lock(rgt);

    if ( unlikely(gref >= nr_grant_entries(rgt)) )
        PIN_FAIL(gt_unlock_out, GNTST_bad_gntref,
                 "Bad grant reference %#x\n", gref);

    /* This call also ensures the above check cannot be passed speculatively */
    shah = shared_entry_header(rgt, gref);
    act = active_entry_acquire(rgt, gref);

    if ( evaluate_nospec(rgt->gt_version == 1) )
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
             (rc = _set_status_v2(shah, status, rd, act, readonly, 0,
                                  ldom)) != GNTST_okay )
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
         * acquire_grant_for_copy() could take the lock on the
         * remote table (if rd == td), so we have to drop the lock
         * here and reacquire.
         */
        active_entry_release(act);
        grant_read_unlock(rgt);

        rc = acquire_grant_for_copy(td, trans_gref, rd->domain_id,
                                    readonly, &grant_mfn, page,
                                    &trans_page_off, &trans_length,
                                    false);

        grant_read_lock(rgt);
        act = active_entry_acquire(rgt, gref);

        if ( rc != GNTST_okay )
        {
            fixup_status_for_copy_pin(rd, act, status);
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
             (old_pin && (act->domid != ldom ||
                          !mfn_eq(act->mfn, grant_mfn) ||
                          act->start != trans_page_off ||
                          act->length != trans_length ||
                          act->trans_domain != td ||
                          act->trans_gref != trans_gref ||
                          !act->is_sub_page)) )
        {
            release_grant_for_copy(td, trans_gref, readonly);
            fixup_status_for_copy_pin(rd, act, status);
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
            act->mfn = grant_mfn;
            act_set_gfn(act, INVALID_GFN);
            /*
             * The actual remote remote grant may or may not be a sub-page,
             * but we always treat it as one because that blocks mappings of
             * transitive grants.
             */
            act->is_sub_page = true;
        }
    }
    else if ( !old_pin ||
              (!readonly && !(old_pin & (GNTPIN_devw_mask|GNTPIN_hstw_mask))) )
    {
        if ( (rc = _set_status(shah, status, rd, rgt->gt_version, act,
                               readonly, 0, ldom)) != GNTST_okay )
             goto unlock_out;

        td = rd;
        trans_gref = gref;
        if ( !sha2 )
        {
            unsigned long gfn = shared_entry_v1(rgt, gref).frame;

            rc = get_paged_frame(gfn, &grant_mfn, page, readonly, rd);
            if ( rc != GNTST_okay )
                goto unlock_out_clear;
            act_set_gfn(act, _gfn(gfn));
            is_sub_page = false;
            trans_page_off = 0;
            trans_length = PAGE_SIZE;
        }
        else if ( !(sha2->hdr.flags & GTF_sub_page) )
        {
            rc = get_paged_frame(sha2->full_page.frame, &grant_mfn, page,
                                 readonly, rd);
            if ( rc != GNTST_okay )
                goto unlock_out_clear;
            act_set_gfn(act, _gfn(sha2->full_page.frame));
            is_sub_page = false;
            trans_page_off = 0;
            trans_length = PAGE_SIZE;
        }
        else
        {
            rc = get_paged_frame(sha2->sub_page.frame, &grant_mfn, page,
                                 readonly, rd);
            if ( rc != GNTST_okay )
                goto unlock_out_clear;
            act_set_gfn(act, _gfn(sha2->sub_page.frame));
            is_sub_page = true;
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
            act->mfn = grant_mfn;
        }
    }
    else
    {
        ASSERT(mfn_valid(act->mfn));
        *page = mfn_to_page(act->mfn);
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
    *mfn = act->mfn;

    active_entry_release(act);
    grant_read_unlock(rgt);
    return rc;

 unlock_out_clear:
    if ( !(readonly) &&
         !(act->pin & (GNTPIN_hstw_mask | GNTPIN_devw_mask)) )
        clear_flags |= GTF_writing;

    if ( !act->pin )
        clear_flags |= GTF_reading;

    if ( clear_flags )
        gnttab_clear_flags(rd, clear_flags, status);

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
    mfn_t mfn;
    struct page_info *page;
    void *virt;
    bool_t read_only;
    bool_t have_grant;
    bool_t have_type;
};

static int gnttab_copy_lock_domain(domid_t domid, bool is_gref,
                                   struct gnttab_copy_buf *buf)
{
    /* Only DOMID_SELF may reference via frame. */
    if ( domid != DOMID_SELF && !is_gref )
        return GNTST_permission_denied;

    buf->domain = rcu_lock_domain_by_any_id(domid);

    if ( !buf->domain )
        return GNTST_bad_domain;

    buf->ptr.domid = domid;

    return GNTST_okay;
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
        release_grant_for_copy(buf->domain, buf->ptr.u.ref, buf->read_only);
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
        rc = acquire_grant_for_copy(buf->domain, ptr->u.ref,
                                    current->domain->domain_id,
                                    buf->read_only,
                                    &buf->mfn, &buf->page,
                                    &buf->ptr.offset, &buf->len,
                                    opt_transitive_grants);
        if ( rc != GNTST_okay )
            goto out;
        buf->ptr.u.ref = ptr->u.ref;
        buf->have_grant = 1;
    }
    else
    {
        rc = get_paged_frame(ptr->u.gmfn, &buf->mfn, &buf->page,
                             buf->read_only, buf->domain);
        if ( rc != GNTST_okay )
            PIN_FAIL(out, rc,
                     "source frame %"PRI_xen_pfn" invalid\n", ptr->u.gmfn);

        buf->ptr.u.gmfn = ptr->u.gmfn;
        buf->ptr.offset = 0;
        buf->len = PAGE_SIZE;
    }

    if ( !buf->read_only )
    {
        if ( !get_page_type(buf->page, PGT_writable_page) )
        {
            if ( !buf->domain->is_dying )
                gdprintk(XENLOG_WARNING,
                         "Could not get writable frame %#"PRI_mfn"\n",
                         mfn_x(buf->mfn));
            rc = GNTST_general_error;
            goto out;
        }
        buf->have_type = 1;
    }

    buf->virt = map_domain_page(buf->mfn);
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
        PIN_FAIL(out, GNTST_bad_copy_arg, "copy beyond page area\n");

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

    /* Make sure the above checks are not bypassed speculatively */
    block_speculation();

    memcpy(dest->virt + op->dest.offset, src->virt + op->source.offset,
           op->len);
    gnttab_mark_dirty(dest->domain, dest->mfn);
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
    unsigned int i, nr_ents;

    if ( copy_from_guest(&op, uop, 1) )
        return -EFAULT;

    res = -EINVAL;
    if ( op.version != 1 && op.version != 2 )
        goto out;

    res = -ENOSYS;
    if ( op.version == 2 && opt_gnttab_max_version == 1 )
        goto out; /* Behave as before set_version was introduced. */

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
    nr_ents = nr_grant_entries(gt);
    for ( i = GNTTAB_NR_RESERVED_ENTRIES; i < nr_ents; i++ )
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
    case 1:
        /* XXX: We could maybe shrink the active grant table here. */
        res = gnttab_populate_status_frames(currd, gt, nr_grant_frames(gt));
        if ( res < 0)
            goto out_unlock;
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
                         "bad flags %#x in grant %#x when switching version\n",
                         flags, i);
                /* fall through */
            case GTF_invalid:
                memset(&reserved_entries[i], 0, sizeof(reserved_entries[i]));
                break;
            }
        }
        break;
    }

    if ( op.version < 2 && gt->gt_version == 2 &&
         (res = gnttab_unpopulate_status_frames(currd, gt)) != 0 )
        goto out_unlock;

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
                         unsigned int count, unsigned int limit_max)
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
                 "Fault while reading gnttab_get_status_frames_t\n");
        return -EFAULT;
    }

    d = rcu_lock_domain_by_any_id(op.dom);
    if ( d == NULL )
    {
        op.status = GNTST_bad_domain;
        goto out1;
    }
    rc = xsm_grant_setup(XSM_TARGET, current->domain, d);
    if ( rc )
    {
        op.status = GNTST_permission_denied;
        goto out2;
    }

    gt = d->grant_table;

    op.status = GNTST_okay;

    grant_read_lock(gt);

    if ( unlikely(op.nr_frames > nr_status_frames(gt)) )
    {
        gdprintk(XENLOG_INFO, "Requested addresses of d%d for %u grant "
                 "status frames, but has only %u\n",
                 d->domain_id, op.nr_frames, nr_status_frames(gt));
        op.status = GNTST_general_error;
        goto unlock;
    }

    if ( unlikely(limit_max < grant_to_status_frames(op.nr_frames)) )
    {
        gdprintk(XENLOG_WARNING,
                 "grant_to_status_frames(%u) for d%d is too large (%u,%u)\n",
                 op.nr_frames, d->domain_id,
                 grant_to_status_frames(op.nr_frames), limit_max);
        op.status = GNTST_general_error;
        goto unlock;
    }

    for ( i = 0; i < op.nr_frames; i++ )
    {
        gmfn = gfn_x(gnttab_status_gfn(d, gt, i));
        if ( copy_to_guest_offset(op.frame_list, i, &gmfn, 1) )
            op.status = GNTST_bad_virt_addr;
    }

 unlock:
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
swap_grant_ref(grant_ref_t ref_a, grant_ref_t ref_b)
{
    struct domain *d = rcu_lock_current_domain();
    struct grant_table *gt = d->grant_table;
    struct active_grant_entry *act_a = NULL;
    struct active_grant_entry *act_b = NULL;
    s16 rc = GNTST_okay;

    grant_write_lock(gt);

    /* Bounds check on the grant refs */
    if ( unlikely(ref_a >= nr_grant_entries(d->grant_table)))
        PIN_FAIL(out, GNTST_bad_gntref, "Bad ref-a %#x\n", ref_a);
    if ( unlikely(ref_b >= nr_grant_entries(d->grant_table)))
        PIN_FAIL(out, GNTST_bad_gntref, "Bad ref-b %#x\n", ref_b);

    /* Make sure the above checks are not bypassed speculatively */
    block_speculation();

    /* Swapping the same ref is a no-op. */
    if ( ref_a == ref_b )
        goto out;

    act_a = active_entry_acquire(gt, ref_a);
    if ( act_a->pin )
        PIN_FAIL(out, GNTST_eagain, "ref a %#x busy\n", ref_a);

    act_b = active_entry_acquire(gt, ref_b);
    if ( act_b->pin )
        PIN_FAIL(out, GNTST_eagain, "ref b %#x busy\n", ref_b);

    if ( evaluate_nospec(gt->gt_version == 1) )
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
        op.status = swap_grant_ref(op.ref_a, op.ref_b);
        if ( unlikely(__copy_field_to_guest(uop, &op, status)) )
            return -EFAULT;
        guest_handle_add_offset(uop, 1);
    }
    return 0;
}

static int cache_flush(const gnttab_cache_flush_t *cflush, grant_ref_t *cur_ref)
{
    struct domain *d, *owner;
    struct page_info *page;
    mfn_t mfn;
    struct active_grant_entry *act = NULL;
    void *v;
    int ret;

    if ( (cflush->offset >= PAGE_SIZE) ||
         (cflush->length > PAGE_SIZE) ||
         (cflush->offset + cflush->length > PAGE_SIZE) ||
         (cflush->op & ~(GNTTAB_CACHE_INVAL | GNTTAB_CACHE_CLEAN)) )
        return -EINVAL;

    if ( cflush->length == 0 || cflush->op == 0 )
        return !*cur_ref ? 0 : -EILSEQ;

    /* currently unimplemented */
    if ( cflush->op & GNTTAB_CACHE_SOURCE_GREF )
        return -EOPNOTSUPP;

    d = rcu_lock_current_domain();
    mfn = maddr_to_mfn(cflush->a.dev_bus_addr);

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

        act = grant_map_exists(d, owner->grant_table, mfn, cur_ref);
        if ( IS_ERR_OR_NULL(act) )
        {
            grant_read_unlock(owner->grant_table);
            rcu_unlock_domain(d);
            put_page(page);
            return act ? PTR_ERR(act) : 1;
        }
    }

    v = map_domain_page(mfn);
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
    {
        active_entry_release(act);
        grant_read_unlock(owner->grant_table);
    }

    unmap_domain_page(v);
    put_page(page);
    rcu_unlock_domain(d);

    return ret;
}

static long
gnttab_cache_flush(XEN_GUEST_HANDLE_PARAM(gnttab_cache_flush_t) uop,
                      grant_ref_t *cur_ref,
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
            int ret = cache_flush(&op, cur_ref);

            if ( ret < 0 )
                return ret;
            if ( ret == 0 )
                break;
            if ( hypercall_preempt_check() )
                return i;
        }
        *cur_ref = 0;
        guest_handle_add_offset(uop, 1);
    }

    *cur_ref = 0;

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
        rc = gnttab_unmap_and_replace(unmap, count);
        if ( rc > 0 )
        {
            guest_handle_add_offset(unmap, rc);
            uop = guest_handle_cast(unmap, void);
        }
        break;
    }

    case GNTTABOP_setup_table:
        rc = gnttab_setup_table(
            guest_handle_cast(uop, gnttab_setup_table_t), count, UINT_MAX);
        ASSERT(rc <= 0);
        break;

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
        rc = gnttab_query_size(
            guest_handle_cast(uop, gnttab_query_size_t), count);
        ASSERT(rc <= 0);
        break;

    case GNTTABOP_set_version:
        rc = gnttab_set_version(guest_handle_cast(uop, gnttab_set_version_t));
        break;

    case GNTTABOP_get_status_frames:
        rc = gnttab_get_status_frames(
            guest_handle_cast(uop, gnttab_get_status_frames_t), count,
                              UINT_MAX);
        break;

    case GNTTABOP_get_version:
        rc = gnttab_get_version(guest_handle_cast(uop, gnttab_get_version_t));
        break;

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
        unsigned int clear_flags = 0;

        map = &maptrack_entry(gt, handle);
        if ( !(map->flags & (GNTMAP_device_map|GNTMAP_host_map)) )
            continue;

        ref = map->ref;

        gdprintk(XENLOG_INFO, "Grant release %#x ref %#x flags %#x d%d\n",
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
        if ( rgt->gt_version == 1 )
            status = &sha->flags;
        else
            status = &status_entry(rgt, ref);

        pg = mfn_to_page(act->mfn);

        if ( map->flags & GNTMAP_readonly )
        {
            if ( map->flags & GNTMAP_device_map )
            {
                BUG_ON(!(act->pin & GNTPIN_devr_mask));
                act->pin -= GNTPIN_devr_inc;
                if ( !is_iomem_page(act->mfn) )
                    put_page(pg);
            }

            if ( map->flags & GNTMAP_host_map )
            {
                BUG_ON(!(act->pin & GNTPIN_hstr_mask));
                act->pin -= GNTPIN_hstr_inc;
                if ( gnttab_release_host_mappings(d) &&
                     !is_iomem_page(act->mfn) )
                    put_page(pg);
            }
        }
        else
        {
            if ( map->flags & GNTMAP_device_map )
            {
                BUG_ON(!(act->pin & GNTPIN_devw_mask));
                act->pin -= GNTPIN_devw_inc;
                if ( !is_iomem_page(act->mfn) )
                    put_page_and_type(pg);
            }

            if ( map->flags & GNTMAP_host_map )
            {
                BUG_ON(!(act->pin & GNTPIN_hstw_mask));
                act->pin -= GNTPIN_hstw_inc;
                if ( gnttab_release_host_mappings(d) &&
                     !is_iomem_page(act->mfn) )
                {
                    if ( gnttab_host_mapping_get_page_type((map->flags &
                                                            GNTMAP_readonly),
                                                           d, rd) )
                        put_page_type(pg);
                    put_page(pg);
                }
            }

            if ( (act->pin & (GNTPIN_devw_mask|GNTPIN_hstw_mask)) == 0 )
                clear_flags |= GTF_writing;
        }

        if ( act->pin == 0 )
            clear_flags |= GTF_reading;

        if ( clear_flags )
            gnttab_clear_flags(rd, clear_flags, status);

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
    unsigned int nr_active = 0, nr_ents;

#define WARN_GRANT_MAX 10

    grant_read_lock(gt);

    nr_ents = nr_grant_entries(gt);
    for ( ref = 0; ref != nr_ents; ref++ )
    {
        act = active_entry_acquire(gt, ref);
        if ( !act->pin )
        {
            active_entry_release(act);
            continue;
        }

        nr_active++;
        if ( nr_active <= WARN_GRANT_MAX )
            printk(XENLOG_G_DEBUG "d%d has active grant %x ("
#ifndef NDEBUG
                   "GFN %lx, "
#endif
                   "MFN: %#"PRI_mfn")\n",
                   d->domain_id, ref,
#ifndef NDEBUG
                   gfn_x(act->gfn),
#endif
                   mfn_x(act->mfn));
        active_entry_release(act);
    }

    if ( nr_active > WARN_GRANT_MAX )
        printk(XENLOG_G_DEBUG "d%d has too many (%d) active grants to report\n",
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

    gnttab_destroy_arch(t);

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

#ifdef CONFIG_MEM_SHARING
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
    else if ( evaluate_nospec(gt->gt_version == 1) )
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
        if ( evaluate_nospec(gt->gt_version == 1) )
            *status = flags;
        else
            *status = status_entry(gt, ref);
    }

    grant_read_unlock(gt);

    return rc;
}
#endif

/* caller must hold write lock */
static int gnttab_get_status_frame_mfn(struct domain *d,
                                       unsigned long idx, mfn_t *mfn)
{
    const struct grant_table *gt = d->grant_table;

    ASSERT(gt->gt_version == 2);

    /* Make sure we have version equal to 2 even under speculation */
    block_speculation();

    if ( idx >= nr_status_frames(gt) )
    {
        unsigned long nr_status;
        unsigned long nr_grant;

        nr_status = idx + 1; /* sufficient frames to make idx valid */

        if ( nr_status == 0 ) /* overflow? */
            return -EINVAL;

        nr_grant = status_to_grant_frames(nr_status);

        if ( grant_to_status_frames(nr_grant) != nr_status ) /* overflow? */
            return -EINVAL;

        if ( nr_grant <= gt->max_grant_frames )
            gnttab_grow_table(d, nr_grant);

        /* check whether gnttab_grow_table() succeeded */
        if ( idx >= nr_status_frames(gt) )
            return -EINVAL;
    }

    /* Make sure idx is bounded wrt nr_status_frames */
    *mfn = _mfn(virt_to_mfn(
                gt->status[array_index_nospec(idx, nr_status_frames(gt))]));
    return 0;
}

/* caller must hold write lock */
static int gnttab_get_shared_frame_mfn(struct domain *d,
                                       unsigned long idx, mfn_t *mfn)
{
    const struct grant_table *gt = d->grant_table;

    ASSERT(gt->gt_version != 0);

    if ( idx >= nr_grant_frames(gt) )
    {
        unsigned long nr_grant;

        nr_grant = idx + 1; /* sufficient frames to make idx valid */

        if ( nr_grant == 0 ) /* overflow? */
            return -EINVAL;

        if ( nr_grant <= gt->max_grant_frames )
            gnttab_grow_table(d, nr_grant);

        /* check whether gnttab_grow_table() succeeded */
        if ( idx >= nr_grant_frames(gt) )
            return -EINVAL;
    }

    /* Make sure idx is bounded wrt nr_status_frames */
    *mfn = _mfn(virt_to_mfn(
                gt->shared_raw[array_index_nospec(idx, nr_grant_frames(gt))]));
    return 0;
}

int gnttab_map_frame(struct domain *d, unsigned long idx, gfn_t gfn, mfn_t *mfn)
{
    int rc = 0;
    struct grant_table *gt = d->grant_table;
    bool status = false;

    grant_write_lock(gt);

    if ( evaluate_nospec(gt->gt_version == 2) && (idx & XENMAPIDX_grant_table_status) )
    {
        idx &= ~XENMAPIDX_grant_table_status;
        status = true;

        rc = gnttab_get_status_frame_mfn(d, idx, mfn);
    }
    else
        rc = gnttab_get_shared_frame_mfn(d, idx, mfn);

    if ( !rc && paging_mode_translate(d) )
    {
        gfn_t gfn = gnttab_get_frame_gfn(gt, status, idx);

        if ( !gfn_eq(gfn, INVALID_GFN) )
            rc = guest_physmap_remove_page(d, gfn, *mfn, 0);
    }

    if ( !rc )
        gnttab_set_frame_gfn(gt, status, idx, gfn);

    grant_write_unlock(gt);

    return rc;
}

int gnttab_get_shared_frame(struct domain *d, unsigned long idx,
                            mfn_t *mfn)
{
    struct grant_table *gt = d->grant_table;
    int rc;

    grant_write_lock(gt);
    rc = gnttab_get_shared_frame_mfn(d, idx, mfn);
    grant_write_unlock(gt);

    return rc;
}

int gnttab_get_status_frame(struct domain *d, unsigned long idx,
                            mfn_t *mfn)
{
    struct grant_table *gt = d->grant_table;
    int rc;

    grant_write_lock(gt);
    rc = (gt->gt_version == 2) ?
        gnttab_get_status_frame_mfn(d, idx, mfn) : -EINVAL;
    grant_write_unlock(gt);

    return rc;
}

static void gnttab_usage_print(struct domain *rd)
{
    int first = 1;
    grant_ref_t ref;
    struct grant_table *gt = rd->grant_table;
    unsigned int nr_ents;

    printk("      -------- active --------       -------- shared --------\n");
    printk("[ref] localdom mfn      pin          localdom gmfn     flags\n");

    grant_read_lock(gt);

    printk("grant-table for remote d%d (v%u)\n"
           "  %u frames (%u max), %u maptrack frames (%u max)\n",
           rd->domain_id, gt->gt_version,
           nr_grant_frames(gt), gt->max_grant_frames,
           nr_maptrack_frames(gt), gt->max_maptrack_frames);

    nr_ents = nr_grant_entries(gt);
    for ( ref = 0; ref != nr_ents; ref++ )
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

        first = 0;

        /*      [0xXXX]  ddddd 0xXXXXX 0xXXXXXXXX      ddddd 0xXXXXXX 0xXX */
        printk("[0x%03x]  %5d 0x%"PRI_mfn" 0x%08x      %5d 0x%06"PRIx64" 0x%02x\n",
               ref, act->domid, mfn_x(act->mfn), act->pin,
               sha->domid, frame, status);
        active_entry_release(act);
    }

    grant_read_unlock(gt);

    if ( first )
        printk("no active grant table entries\n");
}

static void gnttab_usage_print_all(unsigned char key)
{
    struct domain *d;

    printk("%s [ key '%c' pressed\n", __func__, key);

    rcu_read_lock(&domlist_read_lock);

    for_each_domain ( d )
        gnttab_usage_print(d);

    rcu_read_unlock(&domlist_read_lock);

    printk("%s ] done\n", __func__);
}

static int __init gnttab_usage_init(void)
{
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
