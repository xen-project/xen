/******************************************************************************
 * arch/x86/mm/mem_sharing.c
 *
 * Memory sharing support.
 *
 * Copyright (c) 2011 GridCentric, Inc. (Adin Scannell & Andres Lagar-Cavilla)
 * Copyright (c) 2009 Citrix Systems, Inc. (Grzegorz Milos)
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

#include <xen/types.h>
#include <xen/domain_page.h>
#include <xen/event.h>
#include <xen/spinlock.h>
#include <xen/rwlock.h>
#include <xen/mm.h>
#include <xen/grant_table.h>
#include <xen/sched.h>
#include <xen/rcupdate.h>
#include <xen/guest_access.h>
#include <xen/vm_event.h>
#include <asm/page.h>
#include <asm/string.h>
#include <asm/p2m.h>
#include <asm/altp2m.h>
#include <asm/atomic.h>
#include <asm/event.h>
#include <asm/hap.h>
#include <asm/hvm/hvm.h>
#include <xsm/xsm.h>

#include <public/hvm/params.h>

#include "mm-locks.h"

static shr_handle_t next_handle = 1;

typedef struct pg_lock_data {
    int mm_unlock_level;
    unsigned short recurse_count;
} pg_lock_data_t;

static DEFINE_PER_CPU(pg_lock_data_t, __pld);

/* Reverse map defines */
#define RMAP_HASHTAB_ORDER  0
#define RMAP_HASHTAB_SIZE   \
        ((PAGE_SIZE << RMAP_HASHTAB_ORDER) / sizeof(struct list_head))
#define RMAP_USES_HASHTAB(page) \
        ((page)->sharing->hash_table.flag == NULL)
#define RMAP_HEAVY_SHARED_PAGE   RMAP_HASHTAB_SIZE
/*
 * A bit of hysteresis. We don't want to be mutating between list and hash
 * table constantly.
 */
#define RMAP_LIGHT_SHARED_PAGE   (RMAP_HEAVY_SHARED_PAGE >> 2)

#if MEM_SHARING_AUDIT

static LIST_HEAD(shr_audit_list);
static DEFINE_SPINLOCK(shr_audit_lock);
static DEFINE_RCU_READ_LOCK(shr_audit_read_lock);

/* RCU delayed free of audit list entry */
static void _free_pg_shared_info(struct rcu_head *head)
{
    xfree(container_of(head, struct page_sharing_info, rcu_head));
}

static void audit_add_list(struct page_info *page)
{
    INIT_LIST_HEAD(&page->sharing->entry);
    spin_lock(&shr_audit_lock);
    list_add_rcu(&page->sharing->entry, &shr_audit_list);
    spin_unlock(&shr_audit_lock);
}

/* Removes from the audit list and cleans up the page sharing metadata. */
static void page_sharing_dispose(struct page_info *page)
{
    /* Unlikely given our thresholds, but we should be careful. */
    if ( unlikely(RMAP_USES_HASHTAB(page)) )
        free_xenheap_pages(page->sharing->hash_table.bucket,
                           RMAP_HASHTAB_ORDER);

    spin_lock(&shr_audit_lock);
    list_del_rcu(&page->sharing->entry);
    spin_unlock(&shr_audit_lock);
    INIT_RCU_HEAD(&page->sharing->rcu_head);
    call_rcu(&page->sharing->rcu_head, _free_pg_shared_info);
}

#else

#define audit_add_list(p)  ((void)0)
static void page_sharing_dispose(struct page_info *page)
{
    /* Unlikely given our thresholds, but we should be careful. */
    if ( unlikely(RMAP_USES_HASHTAB(page)) )
        free_xenheap_pages(page->sharing->hash_table.bucket,
                           RMAP_HASHTAB_ORDER);
    xfree(page->sharing);
}

#endif /* MEM_SHARING_AUDIT */

/*
 * Private implementations of page_lock/unlock to bypass PV-only
 * sanity checks not applicable to mem-sharing.
 *
 * _page_lock is used in memory sharing to protect addition (share) and removal
 * (unshare) of (gfn,domain) tupples to a list of gfn's that the shared page is
 * currently backing.
 * Nesting may happen when sharing (and locking) two pages.
 * Deadlock is avoided by locking pages in increasing order.
 * All memory sharing code paths take the p2m lock of the affected gfn before
 * taking the lock for the underlying page. We enforce ordering between
 * page_lock and p2m_lock using an mm-locks.h construct.
 *
 * TODO: Investigate if PGT_validated is necessary.
 */
static bool _page_lock(struct page_info *page)
{
    unsigned long x, nx;

    do {
        while ( (x = page->u.inuse.type_info) & PGT_locked )
            cpu_relax();
        nx = x + (1 | PGT_locked);
        if ( !(x & PGT_validated) ||
             !(x & PGT_count_mask) ||
             !(nx & PGT_count_mask) )
            return false;
    } while ( cmpxchg(&page->u.inuse.type_info, x, nx) != x );

    return true;
}

static void _page_unlock(struct page_info *page)
{
    unsigned long x, nx, y = page->u.inuse.type_info;

    do {
        x = y;
        ASSERT((x & PGT_count_mask) && (x & PGT_locked));

        nx = x - (1 | PGT_locked);
        /* We must not drop the last reference here. */
        ASSERT(nx & PGT_count_mask);
    } while ( (y = cmpxchg(&page->u.inuse.type_info, x, nx)) != x );
}

static bool mem_sharing_page_lock(struct page_info *pg)
{
    bool rc;
    pg_lock_data_t *pld = &(this_cpu(__pld));

    page_sharing_mm_pre_lock();
    rc = _page_lock(pg);
    if ( rc )
    {
        preempt_disable();
        page_sharing_mm_post_lock(&pld->mm_unlock_level,
                                  &pld->recurse_count);
    }
    return rc;
}

static void mem_sharing_page_unlock(struct page_info *pg)
{
    pg_lock_data_t *pld = &(this_cpu(__pld));

    page_sharing_mm_unlock(pld->mm_unlock_level,
                           &pld->recurse_count);
    preempt_enable();
    _page_unlock(pg);
}

static shr_handle_t get_next_handle(void)
{
    /* Get the next handle get_page style */
    uint64_t x, y = next_handle;
    do {
        x = y;
    }
    while ( (y = cmpxchg(&next_handle, x, x + 1)) != x );
    return x + 1;
}

static atomic_t nr_saved_mfns   = ATOMIC_INIT(0);
static atomic_t nr_shared_mfns  = ATOMIC_INIT(0);

/*
 * Reverse map
 *
 * Every shared frame keeps a reverse map (rmap) of <domain, gfn> tuples that
 * this shared frame backs. For pages with a low degree of sharing, a O(n)
 * search linked list is good enough. For pages with higher degree of sharing,
 * we use a hash table instead.
 */

typedef struct gfn_info
{
    unsigned long gfn;
    domid_t domain;
    struct list_head list;
} gfn_info_t;

static void rmap_init(struct page_info *page)
{
    /* We always start off as a doubly linked list. */
    INIT_LIST_HEAD(&page->sharing->gfns);
}

/* Exceedingly simple "hash function" */
#define HASH(domain, gfn)       \
    (((gfn) + (domain)) % RMAP_HASHTAB_SIZE)

/*
 * Conversions. Tuned by the thresholds. Should only happen twice
 * (once each) during the lifetime of a shared page.
 */
static inline int rmap_list_to_hash_table(struct page_info *page)
{
    unsigned int i;
    struct list_head *pos, *tmp, *b =
        alloc_xenheap_pages(RMAP_HASHTAB_ORDER, 0);

    if ( b == NULL )
        return -ENOMEM;

    for ( i = 0; i < RMAP_HASHTAB_SIZE; i++ )
        INIT_LIST_HEAD(b + i);

    list_for_each_safe ( pos, tmp, &page->sharing->gfns )
    {
        gfn_info_t *gfn_info = list_entry(pos, gfn_info_t, list);
        struct list_head *bucket = b + HASH(gfn_info->domain, gfn_info->gfn);

        list_del(pos);
        list_add(pos, bucket);
    }

    page->sharing->hash_table.bucket = b;
    page->sharing->hash_table.flag   = NULL;

    return 0;
}

static void rmap_hash_table_to_list(struct page_info *page)
{
    unsigned int i;
    struct list_head *bucket = page->sharing->hash_table.bucket;

    INIT_LIST_HEAD(&page->sharing->gfns);

    for ( i = 0; i < RMAP_HASHTAB_SIZE; i++ )
    {
        struct list_head *pos, *tmp, *head = bucket + i;

        list_for_each_safe ( pos, tmp, head )
        {
            list_del(pos);
            list_add(pos, &page->sharing->gfns);
        }
    }

    free_xenheap_pages(bucket, RMAP_HASHTAB_ORDER);
}

/* Generic accessors to the rmap */
static unsigned long rmap_count(const struct page_info *pg)
{
    unsigned long count;
    unsigned long t = read_atomic(&pg->u.inuse.type_info);

    count = t & PGT_count_mask;
    if ( t & PGT_locked )
        count--;
    return count;
}

/*
 * The page type count is always decreased after removing from the rmap.
 * Use a convert flag to avoid mutating the rmap if in the middle of an
 * iterator, or if the page will be soon destroyed anyways.
 */
static void rmap_del(gfn_info_t *gfn_info, struct page_info *page, int convert)
{
    if ( RMAP_USES_HASHTAB(page) && convert &&
         (rmap_count(page) <= RMAP_LIGHT_SHARED_PAGE) )
        rmap_hash_table_to_list(page);

    /* Regardless of rmap type, same removal operation */
    list_del(&gfn_info->list);
}

/* The page type count is always increased before adding to the rmap. */
static void rmap_add(gfn_info_t *gfn_info, struct page_info *page)
{
    struct list_head *head;

    if ( !RMAP_USES_HASHTAB(page) &&
         (rmap_count(page) >= RMAP_HEAVY_SHARED_PAGE) )
        /*
         * The conversion may fail with ENOMEM. We'll be less efficient,
         * but no reason to panic.
         */
        (void)rmap_list_to_hash_table(page);

    head = (RMAP_USES_HASHTAB(page)
            ? page->sharing->hash_table.bucket + HASH(gfn_info->domain,
                                                      gfn_info->gfn)
            : &page->sharing->gfns);

    INIT_LIST_HEAD(&gfn_info->list);
    list_add(&gfn_info->list, head);
}

static gfn_info_t *rmap_retrieve(uint16_t domain_id, unsigned long gfn,
                                 struct page_info *page)
{
    gfn_info_t *gfn_info;
    struct list_head *le, *head;

    head = (RMAP_USES_HASHTAB(page)
            ? page->sharing->hash_table.bucket + HASH(domain_id, gfn)
            : &page->sharing->gfns);

    list_for_each ( le, head )
    {
        gfn_info = list_entry(le, gfn_info_t, list);
        if ( (gfn_info->gfn == gfn) && (gfn_info->domain == domain_id) )
            return gfn_info;
    }

    /* Nothing was found */
    return NULL;
}

/*
 * The iterator hides the details of how the rmap is implemented. This
 * involves splitting the list_for_each_safe macro into two steps.
 */
struct rmap_iterator {
    struct list_head *curr;
    struct list_head *next;
    unsigned int bucket;
};

static void rmap_seed_iterator(struct page_info *page, struct rmap_iterator *ri)
{
    ri->curr = (RMAP_USES_HASHTAB(page)
                ? page->sharing->hash_table.bucket
                : &page->sharing->gfns);
    ri->next = ri->curr->next;
    ri->bucket = 0;
}

static gfn_info_t *rmap_iterate(struct page_info *page,
                                struct rmap_iterator *ri)
{
    struct list_head *head = (RMAP_USES_HASHTAB(page)
                              ? page->sharing->hash_table.bucket + ri->bucket
                              : &page->sharing->gfns);

 retry:
    if ( ri->next == head)
    {
        if ( RMAP_USES_HASHTAB(page) )
        {
            ri->bucket++;
            if ( ri->bucket >= RMAP_HASHTAB_SIZE )
                /* No more hash table buckets */
                return NULL;
            head = page->sharing->hash_table.bucket + ri->bucket;
            ri->curr = head;
            ri->next = ri->curr->next;
            goto retry;
        }
        else
            /* List exhausted */
            return NULL;
    }

    ri->curr = ri->next;
    ri->next = ri->curr->next;

    return list_entry(ri->curr, gfn_info_t, list);
}

static gfn_info_t *mem_sharing_gfn_alloc(struct page_info *page,
                                         struct domain *d, unsigned long gfn)
{
    gfn_info_t *gfn_info = xmalloc(gfn_info_t);

    if ( gfn_info == NULL )
        return NULL;

    gfn_info->gfn = gfn;
    gfn_info->domain = d->domain_id;

    rmap_add(gfn_info, page);

    /* Increment our number of shared pges. */
    atomic_inc(&d->shr_pages);

    return gfn_info;
}

static void mem_sharing_gfn_destroy(struct page_info *page, struct domain *d,
                                    gfn_info_t *gfn_info)
{
    /* Decrement the number of pages. */
    atomic_dec(&d->shr_pages);

    /* Free the gfn_info structure. */
    rmap_del(gfn_info, page, 1);
    xfree(gfn_info);
}

static struct page_info *mem_sharing_lookup(unsigned long mfn)
{
    struct page_info *page;
    unsigned long t;

    if ( !mfn_valid(_mfn(mfn)) )
        return NULL;

    page = mfn_to_page(_mfn(mfn));
    if ( page_get_owner(page) != dom_cow )
        return NULL;

    /*
     * Count has to be at least two, because we're called
     * with the mfn locked (1) and this is supposed to be
     * a shared page (1).
     */
    t = read_atomic(&page->u.inuse.type_info);
    ASSERT((t & PGT_type_mask) == PGT_shared_page);
    ASSERT((t & PGT_count_mask) >= 2);
    ASSERT(SHARED_M2P(get_gpfn_from_mfn(mfn)));

    return page;
}

static int audit(void)
{
#if MEM_SHARING_AUDIT
    int errors = 0;
    unsigned long count_expected;
    unsigned long count_found = 0;
    struct list_head *ae;

    count_expected = atomic_read(&nr_shared_mfns);

    rcu_read_lock(&shr_audit_read_lock);

    list_for_each_rcu ( ae, &shr_audit_list )
    {
        struct page_sharing_info *pg_shared_info;
        unsigned long nr_gfns = 0;
        struct page_info *pg;
        mfn_t mfn;
        gfn_info_t *g;
        struct rmap_iterator ri;

        pg_shared_info = list_entry(ae, struct page_sharing_info, entry);
        pg = pg_shared_info->pg;
        mfn = page_to_mfn(pg);

        /* If we can't lock it, it's definitely not a shared page */
        if ( !mem_sharing_page_lock(pg) )
        {
            gdprintk(XENLOG_ERR,
                     "mfn %lx in audit list, but cannot be locked (%lx)!\n",
                     mfn_x(mfn), pg->u.inuse.type_info);
            errors++;
            continue;
        }

        /* Check if the MFN has correct type, owner and handle. */
        if ( (pg->u.inuse.type_info & PGT_type_mask) != PGT_shared_page )
        {
            gdprintk(XENLOG_ERR,
                     "mfn %lx in audit list, but not PGT_shared_page (%lx)!\n",
                     mfn_x(mfn), pg->u.inuse.type_info & PGT_type_mask);
            errors++;
            continue;
        }

        /* Check the page owner. */
        if ( page_get_owner(pg) != dom_cow )
        {
            gdprintk(XENLOG_ERR, "mfn %lx shared, but wrong owner (%pd)!\n",
                     mfn_x(mfn), page_get_owner(pg));
            errors++;
        }

        /* Check the m2p entry */
        if ( !SHARED_M2P(get_gpfn_from_mfn(mfn_x(mfn))) )
        {
            gdprintk(XENLOG_ERR, "mfn %lx shared, but wrong m2p entry (%lx)!\n",
                     mfn_x(mfn), get_gpfn_from_mfn(mfn_x(mfn)));
            errors++;
        }

        /* Check we have a list */
        if ( (!pg->sharing) || rmap_count(pg) == 0 )
        {
            gdprintk(XENLOG_ERR, "mfn %lx shared, but empty gfn list!\n",
                     mfn_x(mfn));
            errors++;
            continue;
        }

        /* We've found a page that is shared */
        count_found++;

        /* Check if all GFNs map to the MFN, and the p2m types */
        rmap_seed_iterator(pg, &ri);
        while ( (g = rmap_iterate(pg, &ri)) != NULL )
        {
            struct domain *d;
            p2m_type_t t;
            mfn_t o_mfn;

            d = get_domain_by_id(g->domain);
            if ( d == NULL )
            {
                gdprintk(XENLOG_ERR,
                         "Unknown dom: %d, for PFN=%lx, MFN=%lx\n",
                         g->domain, g->gfn, mfn_x(mfn));
                errors++;
                continue;
            }
            o_mfn = get_gfn_query_unlocked(d, g->gfn, &t);
            if ( !mfn_eq(o_mfn, mfn) )
            {
                gdprintk(XENLOG_ERR, "Incorrect P2M for %pd, PFN=%lx."
                         "Expecting MFN=%lx, got %lx\n",
                         d, g->gfn, mfn_x(mfn), mfn_x(o_mfn));
                errors++;
            }
            if ( t != p2m_ram_shared )
            {
                gdprintk(XENLOG_ERR,
                         "Incorrect P2M type for %pd, PFN=%lx MFN=%lx."
                         "Expecting t=%d, got %d\n",
                         d, g->gfn, mfn_x(mfn), p2m_ram_shared, t);
                errors++;
            }
            put_domain(d);
            nr_gfns++;
        }
        /* The type count has an extra ref because we have locked the page */
        if ( (nr_gfns + 1) != (pg->u.inuse.type_info & PGT_count_mask) )
        {
            gdprintk(XENLOG_ERR, "Mismatched counts for MFN=%lx."
                     "nr_gfns in list %lu, in type_info %lx\n",
                     mfn_x(mfn), nr_gfns,
                     (pg->u.inuse.type_info & PGT_count_mask));
            errors++;
        }

        mem_sharing_page_unlock(pg);
    }

    rcu_read_unlock(&shr_audit_read_lock);

    if ( count_found != count_expected )
    {
        gdprintk(XENLOG_ERR, "Expected %ld shared mfns, found %ld.",
                 count_expected, count_found);
        errors++;
    }

    return errors;
#else
    return -EOPNOTSUPP;
#endif
}

int mem_sharing_notify_enomem(struct domain *d, unsigned long gfn,
                              bool allow_sleep)
{
    struct vcpu *v = current;
    int rc;
    vm_event_request_t req = {
        .reason = VM_EVENT_REASON_MEM_SHARING,
        .vcpu_id = v->vcpu_id,
        .u.mem_sharing.gfn = gfn,
        .u.mem_sharing.p2mt = p2m_ram_shared,
    };

    if ( (rc = __vm_event_claim_slot(
              d, d->vm_event_share, allow_sleep)) < 0 )
        return rc;

    if ( v->domain == d )
    {
        req.flags = VM_EVENT_FLAG_VCPU_PAUSED;
        vm_event_vcpu_pause(v);
    }

    vm_event_put_request(d, d->vm_event_share, &req);

    return 0;
}

unsigned int mem_sharing_get_nr_saved_mfns(void)
{
    return atomic_read(&nr_saved_mfns);
}

unsigned int mem_sharing_get_nr_shared_mfns(void)
{
    return atomic_read(&nr_shared_mfns);
}

/* Functions that change a page's type and ownership */
static int page_make_sharable(struct domain *d,
                              struct page_info *page,
                              unsigned int expected_refcnt,
                              bool validate_only)
{
    int rc = 0;
    bool drop_dom_ref = false;

    spin_lock_recursive(&d->page_alloc_lock);

    if ( d->is_dying )
    {
        rc = -EBUSY;
        goto out;
    }

    /* Change page type and count atomically */
    if ( !get_page_and_type(page, d, PGT_shared_page) )
    {
        rc = -EINVAL;
        goto out;
    }

    /* Check it wasn't already sharable and undo if it was */
    if ( (page->u.inuse.type_info & PGT_count_mask) != 1 )
    {
        put_page_and_type(page);
        rc = -EEXIST;
        goto out;
    }

    /*
     * Check if the ref count is 2. The first from PGC_allocated, and
     * the second from get_page_and_type at the top of this function.
     */
    if ( page->count_info != (PGC_allocated | (2 + expected_refcnt)) )
    {
        /* Return type count back to zero */
        put_page_and_type(page);
        rc = -E2BIG;
        goto out;
    }

    if ( !validate_only )
    {
        page_set_owner(page, dom_cow);
        drop_dom_ref = !domain_adjust_tot_pages(d, -1);
        page_list_del(page, &d->page_list);
    }

out:
    spin_unlock_recursive(&d->page_alloc_lock);

    if ( drop_dom_ref )
        put_domain(d);

    return rc;
}

static int page_make_private(struct domain *d, struct page_info *page)
{
    unsigned long expected_type;

    if ( !get_page(page, dom_cow) )
        return -EINVAL;

    spin_lock(&d->page_alloc_lock);

    if ( d->is_dying )
    {
        spin_unlock(&d->page_alloc_lock);
        put_page(page);
        return -EBUSY;
    }

    expected_type = (PGT_shared_page | PGT_validated | PGT_locked | 2);
    if ( page->u.inuse.type_info != expected_type )
    {
        spin_unlock(&d->page_alloc_lock);
        put_page(page);
        return -EEXIST;
    }

    mem_sharing_page_unlock(page);

    /* Drop the final typecount */
    put_page_and_type(page);

    /* Change the owner */
    ASSERT(page_get_owner(page) == dom_cow);
    page_set_owner(page, d);

    if ( domain_adjust_tot_pages(d, 1) == 1 )
        get_knownalive_domain(d);
    page_list_add_tail(page, &d->page_list);
    spin_unlock(&d->page_alloc_lock);

    put_page(page);

    return 0;
}

static struct page_info *__grab_shared_page(mfn_t mfn)
{
    struct page_info *pg = NULL;

    if ( !mfn_valid(mfn) )
        return NULL;

    pg = mfn_to_page(mfn);

    /*
     * If the page is not validated we can't lock it, and if it's
     * not validated it's obviously not shared.
     */
    if ( !mem_sharing_page_lock(pg) )
        return NULL;

    if ( mem_sharing_lookup(mfn_x(mfn)) == NULL )
    {
        mem_sharing_page_unlock(pg);
        return NULL;
    }

    return pg;
}

static int debug_mfn(mfn_t mfn)
{
    struct page_info *page;
    int num_refs;

    if ( (page = __grab_shared_page(mfn)) == NULL)
    {
        gdprintk(XENLOG_ERR, "Invalid MFN=%lx\n", mfn_x(mfn));
        return -EINVAL;
    }

    gdprintk(XENLOG_ERR,
             "Debug page: MFN=%lx is ci=%lx, ti=%lx, owner_id=%pd\n",
             mfn_x(page_to_mfn(page)), page->count_info,
             page->u.inuse.type_info, page_get_owner(page));

    /* -1 because the page is locked and that's an additional type ref */
    num_refs = ((int) (page->u.inuse.type_info & PGT_count_mask)) - 1;
    mem_sharing_page_unlock(page);
    return num_refs;
}

static int debug_gfn(struct domain *d, gfn_t gfn)
{
    p2m_type_t p2mt;
    mfn_t mfn;
    int num_refs;

    mfn = get_gfn_query(d, gfn_x(gfn), &p2mt);

    gdprintk(XENLOG_ERR, "Debug for %pd, gfn=%" PRI_gfn "\n",
             d, gfn_x(gfn));

    num_refs = debug_mfn(mfn);
    put_gfn(d, gfn_x(gfn));

    return num_refs;
}

static int debug_gref(struct domain *d, grant_ref_t ref)
{
    int rc;
    uint16_t status;
    gfn_t gfn;

    rc = mem_sharing_gref_to_gfn(d->grant_table, ref, &gfn, &status);
    if ( rc )
    {
        gdprintk(XENLOG_ERR, "Asked to debug [%pd,gref=%u]: error %d.\n",
                 d, ref, rc);
        return rc;
    }

    gdprintk(XENLOG_ERR, "==> Grant [%pd,ref=%d], status=%x. ",
             d, ref, status);

    return debug_gfn(d, gfn);
}

static int nominate_page(struct domain *d, gfn_t gfn,
                         unsigned int expected_refcnt, bool validate_only,
                         shr_handle_t *phandle)
{
    struct p2m_domain *hp2m = p2m_get_hostp2m(d);
    p2m_type_t p2mt;
    p2m_access_t p2ma;
    mfn_t mfn;
    struct page_info *page = NULL; /* gcc... */
    int ret;

    *phandle = 0UL;

    mfn = get_gfn_type_access(hp2m, gfn_x(gfn), &p2mt, &p2ma, 0, NULL);

    /* Check if mfn is valid */
    ret = -EINVAL;
    if ( !mfn_valid(mfn) )
        goto out;

    /* Return the handle if the page is already shared */
    if ( p2m_is_shared(p2mt) )
    {
        struct page_info *pg = __grab_shared_page(mfn);
        if ( !pg )
            BUG();

        *phandle = pg->sharing->handle;
        ret = 0;
        mem_sharing_page_unlock(pg);
        goto out;
    }

    /* Check p2m type */
    if ( !p2m_is_sharable(p2mt) )
        goto out;

    page = mfn_to_page(mfn);
    if ( !page || is_special_page(page) )
        goto out;

    /* Check if there are mem_access/remapped altp2m entries for this page */
    if ( altp2m_active(d) )
    {
        unsigned int i;
        struct p2m_domain *ap2m;
        mfn_t amfn;
        p2m_type_t ap2mt;
        p2m_access_t ap2ma;

        altp2m_list_lock(d);

        for ( i = 0; i < MAX_ALTP2M; i++ )
        {
            ap2m = d->arch.altp2m_p2m[i];
            if ( !ap2m )
                continue;

            amfn = __get_gfn_type_access(ap2m, gfn_x(gfn), &ap2mt, &ap2ma,
                                         0, NULL, false);
            if ( mfn_valid(amfn) && (!mfn_eq(amfn, mfn) || ap2ma != p2ma) )
            {
                altp2m_list_unlock(d);
                goto out;
            }
        }

        altp2m_list_unlock(d);
    }

    /* Try to convert the mfn to the sharable type */
    ret = page_make_sharable(d, page, expected_refcnt, validate_only);
    if ( ret || validate_only )
        goto out;

    /*
     * Now that the page is validated, we can lock it. There is no
     * race because we're holding the p2m entry, so no one else
     * could be nominating this gfn.
     */
    ret = -ENOENT;
    if ( !mem_sharing_page_lock(page) )
        goto out;

    /* Initialize the shared state */
    ret = -ENOMEM;
    if ( !(page->sharing = xmalloc(struct page_sharing_info)) )
    {
        /* Making a page private atomically unlocks it */
        BUG_ON(page_make_private(d, page));
        goto out;
    }
    page->sharing->pg = page;
    rmap_init(page);

    /* Create the handle */
    page->sharing->handle = get_next_handle();

    /* Create the local gfn info */
    if ( !mem_sharing_gfn_alloc(page, d, gfn_x(gfn)) )
    {
        xfree(page->sharing);
        page->sharing = NULL;
        BUG_ON(page_make_private(d, page));
        goto out;
    }

    /* Change the p2m type, should never fail with p2m locked. */
    BUG_ON(p2m_change_type_one(d, gfn_x(gfn), p2mt, p2m_ram_shared));

    /* Account for this page. */
    atomic_inc(&nr_shared_mfns);

    /* Update m2p entry to SHARED_M2P_ENTRY */
    set_gpfn_from_mfn(mfn_x(mfn), SHARED_M2P_ENTRY);

    *phandle = page->sharing->handle;
    audit_add_list(page);
    mem_sharing_page_unlock(page);
    ret = 0;

out:
    put_gfn(d, gfn_x(gfn));
    return ret;
}

static int share_pages(struct domain *sd, gfn_t sgfn, shr_handle_t sh,
                       struct domain *cd, gfn_t cgfn, shr_handle_t ch)
{
    struct page_info *spage, *cpage, *firstpg, *secondpg;
    gfn_info_t *gfn;
    struct domain *d;
    int ret = -EINVAL;
    mfn_t smfn, cmfn;
    p2m_type_t smfn_type, cmfn_type;
    struct two_gfns tg;
    struct rmap_iterator ri;
    unsigned long put_count = 0;

    get_two_gfns(sd, sgfn, &smfn_type, NULL, &smfn,
                 cd, cgfn, &cmfn_type, NULL, &cmfn, 0, &tg, true);

    /*
     * This tricky business is to avoid two callers deadlocking if
     * grabbing pages in opposite client/source order.
     */
    if ( mfn_eq(smfn, cmfn) )
    {
        /*
         * The pages are already the same.  We could return some
         * kind of error here, but no matter how you look at it,
         * the pages are already 'shared'.  It possibly represents
         * a big problem somewhere else, but as far as sharing is
         * concerned: great success!
         */
        ret = 0;
        goto err_out;
    }

    if ( mfn_x(smfn) < mfn_x(cmfn) )
    {
        ret = XENMEM_SHARING_OP_S_HANDLE_INVALID;
        spage = firstpg = __grab_shared_page(smfn);
        if ( spage == NULL )
            goto err_out;

        ret = XENMEM_SHARING_OP_C_HANDLE_INVALID;
        cpage = secondpg = __grab_shared_page(cmfn);
        if ( cpage == NULL )
        {
            mem_sharing_page_unlock(spage);
            goto err_out;
        }
    }
    else
    {
        ret = XENMEM_SHARING_OP_C_HANDLE_INVALID;
        cpage = firstpg = __grab_shared_page(cmfn);
        if ( cpage == NULL )
            goto err_out;

        ret = XENMEM_SHARING_OP_S_HANDLE_INVALID;
        spage = secondpg = __grab_shared_page(smfn);
        if ( spage == NULL )
        {
            mem_sharing_page_unlock(cpage);
            goto err_out;
        }
    }

    ASSERT(smfn_type == p2m_ram_shared);
    ASSERT(cmfn_type == p2m_ram_shared);

    /* Check that the handles match */
    if ( spage->sharing->handle != sh )
    {
        ret = XENMEM_SHARING_OP_S_HANDLE_INVALID;
        mem_sharing_page_unlock(secondpg);
        mem_sharing_page_unlock(firstpg);
        goto err_out;
    }

    if ( cpage->sharing->handle != ch )
    {
        ret = XENMEM_SHARING_OP_C_HANDLE_INVALID;
        mem_sharing_page_unlock(secondpg);
        mem_sharing_page_unlock(firstpg);
        goto err_out;
    }

    /* Merge the lists together */
    rmap_seed_iterator(cpage, &ri);
    while ( (gfn = rmap_iterate(cpage, &ri)) != NULL)
    {
        /*
         * Get the source page and type, this should never fail:
         * we are under shr lock, and got a successful lookup.
         */
        BUG_ON(!get_page_and_type(spage, dom_cow, PGT_shared_page));
        /*
         * Move the gfn_info from client list to source list.
         * Don't change the type of rmap for the client page.
         */
        rmap_del(gfn, cpage, 0);
        rmap_add(gfn, spage);
        put_count++;
        d = get_domain_by_id(gfn->domain);
        BUG_ON(!d);
        BUG_ON(set_shared_p2m_entry(d, gfn->gfn, smfn));
        put_domain(d);
    }
    ASSERT(list_empty(&cpage->sharing->gfns));
    BUG_ON(!put_count);

    /* Clear the rest of the shared state */
    page_sharing_dispose(cpage);
    cpage->sharing = NULL;

    mem_sharing_page_unlock(secondpg);
    mem_sharing_page_unlock(firstpg);

    /* Free the client page */
    put_page_alloc_ref(cpage);

    while ( put_count-- )
        put_page_and_type(cpage);

    /* We managed to free a domain page. */
    atomic_dec(&nr_shared_mfns);
    atomic_inc(&nr_saved_mfns);
    ret = 0;

err_out:
    put_two_gfns(&tg);
    return ret;
}

/*
 * This function is intended to be used for plugging a "hole" in the client's
 * physmap with a shared memory entry. Unfortunately the definition of a "hole"
 * is currently ambigious. There are two cases one can run into a "hole":
 *  1) there is no pagetable entry at all
 *  2) there is a pagetable entry with a type that passes p2m_is_hole
 *
 * The intended use-case for this function is case 1.
 *
 * During 1) the mem_access being returned is p2m_access_n and that is
 * incorrect to be applied to the new entry being added the client physmap,
 * thus we make use of the p2m->default_access instead.
 * When 2) is true it is possible that the existing pagetable entry also has
 * a mem_access permission set, which could be p2m_access_n. Since we can't
 * differentiate whether we are in case 1) or 2), we default to using the
 * access permission defined as default for the p2m, thus in
 * case 2) overwriting any custom mem_access permission the user may have set
 * on a hole page. Custom mem_access permissions being set on a hole are
 * unheard of but technically possible.
 *
 * TODO: to properly resolve this issue implement differentiation between the
 * two "hole" types.
 */
static
int add_to_physmap(struct domain *sd, unsigned long sgfn, shr_handle_t sh,
                   struct domain *cd, unsigned long cgfn, bool lock)
{
    struct page_info *spage;
    int ret = -EINVAL;
    mfn_t smfn, cmfn;
    p2m_type_t smfn_type, cmfn_type;
    struct gfn_info *gfn_info;
    struct p2m_domain *p2m = p2m_get_hostp2m(cd);
    struct two_gfns tg;

    get_two_gfns(sd, _gfn(sgfn), &smfn_type, NULL, &smfn,
                 cd, _gfn(cgfn), &cmfn_type, NULL, &cmfn, 0, &tg, lock);

    /* Get the source shared page, check and lock */
    ret = XENMEM_SHARING_OP_S_HANDLE_INVALID;
    spage = __grab_shared_page(smfn);
    if ( spage == NULL )
        goto err_out;

    ASSERT(smfn_type == p2m_ram_shared);

    /* Check that the handles match */
    if ( spage->sharing->handle != sh )
        goto err_unlock;

    /*
     * Make sure the target page is a hole in the physmap. These are typically
     * p2m_mmio_dm, but also accept p2m_invalid and paged out pages. See the
     * definition of p2m_is_hole in p2m.h.
     */
    if ( !p2m_is_hole(cmfn_type) )
    {
        ret = XENMEM_SHARING_OP_C_HANDLE_INVALID;
        goto err_unlock;
    }

    /* This is simpler than regular sharing */
    BUG_ON(!get_page_and_type(spage, dom_cow, PGT_shared_page));
    if ( !(gfn_info = mem_sharing_gfn_alloc(spage, cd, cgfn)) )
    {
        put_page_and_type(spage);
        ret = -ENOMEM;
        goto err_unlock;
    }

    ret = p2m_set_entry(p2m, _gfn(cgfn), smfn, PAGE_ORDER_4K,
                        p2m_ram_shared, p2m->default_access);

    /* Tempted to turn this into an assert */
    if ( ret )
    {
        mem_sharing_gfn_destroy(spage, cd, gfn_info);
        put_page_and_type(spage);
    }
    else
    {
        /*
         * There is a chance we're plugging a hole where a paged out
         * page was.
         */
        if ( p2m_is_paging(cmfn_type) && (cmfn_type != p2m_ram_paging_out) )
        {
            atomic_dec(&cd->paged_pages);
            /*
             * Further, there is a chance this was a valid page.
             * Don't leak it.
             */
            if ( mfn_valid(cmfn) )
            {
                struct page_info *cpage = mfn_to_page(cmfn);

                if ( !get_page(cpage, cd) )
                {
                    domain_crash(cd);
                    ret = -EOVERFLOW;
                    goto err_unlock;
                }
                put_page_alloc_ref(cpage);
                put_page(cpage);
            }
        }
    }

    atomic_inc(&nr_saved_mfns);

err_unlock:
    mem_sharing_page_unlock(spage);
err_out:
    if ( lock )
        put_two_gfns(&tg);
    return ret;
}


/*
 * A note on the rationale for unshare error handling:
 *  1. Unshare can only fail with ENOMEM. Any other error conditions BUG_ON()'s
 *  2. We notify a potential dom0 helper through a vm_event ring. But we
 *     allow the notification to not go to sleep. If the event ring is full
 *     of ENOMEM warnings, then it's on the ball.
 *  3. We cannot go to sleep until the unshare is resolved, because we might
 *     be buried deep into locks (e.g. something -> copy_to_user -> __hvm_copy)
 *  4. So, we make sure we:
 *     4.1. return an error
 *     4.2. do not corrupt shared memory
 *     4.3. do not corrupt guest memory
 *     4.4. let the guest deal with it if the error propagation will reach it
 */
int __mem_sharing_unshare_page(struct domain *d,
                               unsigned long gfn,
                               bool destroy)
{
    p2m_type_t p2mt;
    mfn_t mfn;
    struct page_info *page, *old_page;
    int last_gfn;
    gfn_info_t *gfn_info = NULL;

    mfn = get_gfn(d, gfn, &p2mt);

    /* Has someone already unshared it? */
    if ( !p2m_is_shared(p2mt) )
    {
        put_gfn(d, gfn);
        return 0;
    }

    page = __grab_shared_page(mfn);
    if ( page == NULL )
    {
        gdprintk(XENLOG_ERR, "Domain p2m is shared, but page is not: %lx\n",
                 gfn);
        BUG();
    }

    gfn_info = rmap_retrieve(d->domain_id, gfn, page);
    if ( unlikely(gfn_info == NULL) )
    {
        gdprintk(XENLOG_ERR, "Could not find gfn_info for shared gfn: %lx\n",
                 gfn);
        BUG();
    }

    /*
     * Do the accounting first. If anything fails below, we have bigger
     * bigger fish to fry. First, remove the gfn from the list.
     */
    last_gfn = rmap_count(page) == 1;
    if ( last_gfn )
    {
        /*
         * Clean up shared state. Get rid of the <domid, gfn> tuple
         * before destroying the rmap.
         */
        mem_sharing_gfn_destroy(page, d, gfn_info);
        page_sharing_dispose(page);
        page->sharing = NULL;
        atomic_dec(&nr_shared_mfns);
    }
    else
        atomic_dec(&nr_saved_mfns);

    /*
     * If the GFN is getting destroyed drop the references to MFN
     * (possibly freeing the page), and exit early.
     */
    if ( destroy )
    {
        if ( !last_gfn )
            mem_sharing_gfn_destroy(page, d, gfn_info);

        mem_sharing_page_unlock(page);

        if ( last_gfn )
            put_page_alloc_ref(page);

        put_page_and_type(page);
        put_gfn(d, gfn);

        return 0;
    }

    if ( last_gfn )
    {
        /* Making a page private atomically unlocks it */
        BUG_ON(page_make_private(d, page) != 0);
        goto private_page_found;
    }

    old_page = page;
    page = alloc_domheap_page(d, 0);
    if ( !page )
    {
        /* Undo dec of nr_saved_mfns, as the retry will decrease again. */
        atomic_inc(&nr_saved_mfns);
        mem_sharing_page_unlock(old_page);
        put_gfn(d, gfn);
        /*
         * Caller is responsible for placing an event
         * in the ring.
         */
        return -ENOMEM;
    }

    copy_domain_page(page_to_mfn(page), page_to_mfn(old_page));

    BUG_ON(set_shared_p2m_entry(d, gfn, page_to_mfn(page)));
    mem_sharing_gfn_destroy(old_page, d, gfn_info);
    mem_sharing_page_unlock(old_page);
    put_page_and_type(old_page);

 private_page_found:
    if ( p2m_change_type_one(d, gfn, p2m_ram_shared, p2m_ram_rw) )
    {
        gdprintk(XENLOG_ERR, "Could not change p2m type d %pd gfn %lx.\n",
                 d, gfn);
        BUG();
    }

    /* Update m2p entry */
    set_gpfn_from_mfn(mfn_x(page_to_mfn(page)), gfn);

    /*
     * Now that the gfn<->mfn map is properly established,
     * marking dirty is feasible
     */
    paging_mark_dirty(d, page_to_mfn(page));
    /* We do not need to unlock a private page */
    put_gfn(d, gfn);
    return 0;
}

int relinquish_shared_pages(struct domain *d)
{
    int rc = 0;
    struct mem_sharing_domain *msd = &d->arch.hvm.mem_sharing;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    unsigned long gfn, count = 0;

    if ( p2m == NULL )
        return 0;

    p2m_lock(p2m);
    for ( gfn = msd->next_shared_gfn_to_relinquish;
          gfn <= p2m->max_mapped_pfn; gfn++ )
    {
        p2m_access_t a;
        p2m_type_t t;
        mfn_t mfn;
        int set_rc;

        if ( !atomic_read(&d->shr_pages) )
            break;

        mfn = p2m->get_entry(p2m, _gfn(gfn), &t, &a, 0, NULL, NULL);
        if ( mfn_valid(mfn) && p2m_is_shared(t) )
        {
            /* Does not fail with ENOMEM given "destroy" is set to true */
            BUG_ON(__mem_sharing_unshare_page(d, gfn, true));
            /*
             * Clear out the p2m entry so no one else may try to
             * unshare.  Must succeed: we just read the old entry and
             * we hold the p2m lock.
             */
            set_rc = p2m->set_entry(p2m, _gfn(gfn), INVALID_MFN, PAGE_ORDER_4K,
                                    p2m_invalid, p2m_access_rwx, -1);
            ASSERT(!set_rc);
            count += 0x10;
        }
        else
            ++count;

        /* Preempt every 2MiB (shared) or 32MiB (unshared) - arbitrary. */
        if ( count >= 0x2000 )
        {
            if ( hypercall_preempt_check() )
            {
                msd->next_shared_gfn_to_relinquish = gfn + 1;
                rc = -ERESTART;
                break;
            }
            count = 0;
        }
    }

    p2m_unlock(p2m);
    return rc;
}

static int range_share(struct domain *d, struct domain *cd,
                       struct mem_sharing_op_range *range)
{
    int rc = 0;
    shr_handle_t sh, ch;
    unsigned long start = range->opaque ?: range->first_gfn;

    while ( range->last_gfn >= start )
    {
        /*
         * We only break out if we run out of memory as individual pages may
         * legitimately be unsharable and we just want to skip over those.
         */
        rc = nominate_page(d, _gfn(start), 0, false, &sh);
        if ( rc == -ENOMEM )
            break;

        if ( !rc )
        {
            rc = nominate_page(cd, _gfn(start), 0, false, &ch);
            if ( rc == -ENOMEM )
                break;

            if ( !rc )
            {
                /* If we get here this should be guaranteed to succeed. */
                rc = share_pages(d, _gfn(start), sh, cd, _gfn(start), ch);
                ASSERT(!rc);
            }
        }

        /* Check for continuation if it's not the last iteration. */
        if ( range->last_gfn >= ++start && hypercall_preempt_check() )
        {
            rc = 1;
            break;
        }
    }

    range->opaque = start;

    /*
     * The last page may fail with -EINVAL, and for range sharing we don't
     * care about that.
     */
    if ( range->last_gfn < start && rc == -EINVAL )
        rc = 0;

    return rc;
}

static inline int mem_sharing_control(struct domain *d, bool enable,
                                      uint16_t flags)
{
    if ( enable )
    {
        if ( unlikely(!is_hvm_domain(d) || !cpu_has_vmx) )
            return -EOPNOTSUPP;

        if ( unlikely(!hap_enabled(d)) )
            return -ENODEV;

        if ( unlikely(is_iommu_enabled(d) &&
                      !(flags & XENMEM_FORK_WITH_IOMMU_ALLOWED)) )
            return -EXDEV;
    }

    d->arch.hvm.mem_sharing.enabled = enable;
    return 0;
}

/*
 * Forking a page only gets called when the VM faults due to no entry being
 * in the EPT for the access. Depending on the type of access we either
 * populate the physmap with a shared entry for read-only access or
 * fork the page if its a write access.
 *
 * The client p2m is already locked so we only need to lock
 * the parent's here.
 */
int mem_sharing_fork_page(struct domain *d, gfn_t gfn, bool unsharing)
{
    int rc = -ENOENT;
    shr_handle_t handle;
    struct domain *parent = d->parent;
    struct p2m_domain *p2m;
    unsigned long gfn_l = gfn_x(gfn);
    mfn_t mfn, new_mfn;
    p2m_type_t p2mt;
    struct page_info *page;

    if ( !mem_sharing_is_fork(d) )
        return -ENOENT;

    if ( !unsharing )
    {
        /* For read-only accesses we just add a shared entry to the physmap */
        while ( parent )
        {
            if ( !(rc = nominate_page(parent, gfn, 0, false, &handle)) )
                break;

            parent = parent->parent;
        }

        if ( !rc )
        {
            /* The client's p2m is already locked */
            p2m = p2m_get_hostp2m(parent);

            p2m_lock(p2m);
            rc = add_to_physmap(parent, gfn_l, handle, d, gfn_l, false);
            p2m_unlock(p2m);

            if ( !rc )
                return 0;
        }
    }

    /*
     * If it's a write access (ie. unsharing) or if adding a shared entry to
     * the physmap failed we'll fork the page directly.
     */
    p2m = p2m_get_hostp2m(d);
    parent = d->parent;

    while ( parent )
    {
        mfn = get_gfn_query(parent, gfn_l, &p2mt);

        /* We can't fork grant memory from the parent, only regular ram */
        if ( mfn_valid(mfn) && p2m_is_ram(p2mt) )
            break;

        put_gfn(parent, gfn_l);
        parent = parent->parent;
    }

    if ( !parent )
        return -ENOENT;

    if ( !(page = alloc_domheap_page(d, 0)) )
    {
        put_gfn(parent, gfn_l);
        return -ENOMEM;
    }

    new_mfn = page_to_mfn(page);
    copy_domain_page(new_mfn, mfn);
    set_gpfn_from_mfn(mfn_x(new_mfn), gfn_l);

    put_gfn(parent, gfn_l);

    return p2m->set_entry(p2m, gfn, new_mfn, PAGE_ORDER_4K, p2m_ram_rw,
                          p2m->default_access, -1);
}

static int bring_up_vcpus(struct domain *cd, struct domain *d)
{
    unsigned int i;
    int ret = -EINVAL;

    if ( d->max_vcpus != cd->max_vcpus ||
        (ret = cpupool_move_domain(cd, d->cpupool)) )
        return ret;

    for ( i = 0; i < cd->max_vcpus; i++ )
    {
        if ( !d->vcpu[i] || cd->vcpu[i] )
            continue;

        if ( !vcpu_create(cd, i) )
            return -EINVAL;
    }

    domain_update_node_affinity(cd);
    return 0;
}

static int copy_vcpu_settings(struct domain *cd, const struct domain *d)
{
    unsigned int i;
    struct p2m_domain *p2m = p2m_get_hostp2m(cd);
    int ret = -EINVAL;

    for ( i = 0; i < cd->max_vcpus; i++ )
    {
        const struct vcpu *d_vcpu = d->vcpu[i];
        struct vcpu *cd_vcpu = cd->vcpu[i];
        mfn_t vcpu_info_mfn;

        if ( !d_vcpu || !cd_vcpu )
            continue;

        /* Copy & map in the vcpu_info page if the guest uses one */
        vcpu_info_mfn = d_vcpu->vcpu_info_mfn;
        if ( !mfn_eq(vcpu_info_mfn, INVALID_MFN) )
        {
            mfn_t new_vcpu_info_mfn = cd_vcpu->vcpu_info_mfn;

            /* Allocate & map the page for it if it hasn't been already */
            if ( mfn_eq(new_vcpu_info_mfn, INVALID_MFN) )
            {
                gfn_t gfn = mfn_to_gfn(d, vcpu_info_mfn);
                unsigned long gfn_l = gfn_x(gfn);
                struct page_info *page;

                if ( !(page = alloc_domheap_page(cd, 0)) )
                    return -ENOMEM;

                new_vcpu_info_mfn = page_to_mfn(page);
                set_gpfn_from_mfn(mfn_x(new_vcpu_info_mfn), gfn_l);

                ret = p2m->set_entry(p2m, gfn, new_vcpu_info_mfn,
                                     PAGE_ORDER_4K, p2m_ram_rw,
                                     p2m->default_access, -1);
                if ( ret )
                    return ret;

                ret = map_vcpu_info(cd_vcpu, gfn_l,
                                    PAGE_OFFSET(d_vcpu->vcpu_info));
                if ( ret )
                    return ret;
            }

            copy_domain_page(new_vcpu_info_mfn, vcpu_info_mfn);
        }

        /*
         * TODO: to support VMs with PV interfaces copy additional
         * settings here, such as PV timers.
         */
    }

    return 0;
}

static int fork_hap_allocation(struct domain *cd, struct domain *d)
{
    int rc;
    bool preempted;
    unsigned long mb = hap_get_allocation(d);

    if ( mb == hap_get_allocation(cd) )
        return 0;

    paging_lock(cd);
    rc = hap_set_allocation(cd, mb << (20 - PAGE_SHIFT), &preempted);
    paging_unlock(cd);

    return preempted ? -ERESTART : rc;
}

static void copy_tsc(struct domain *cd, struct domain *d)
{
    uint32_t tsc_mode;
    uint32_t gtsc_khz;
    uint32_t incarnation;
    uint64_t elapsed_nsec;

    tsc_get_info(d, &tsc_mode, &elapsed_nsec, &gtsc_khz, &incarnation);
    /* Don't bump incarnation on set */
    tsc_set_info(cd, tsc_mode, elapsed_nsec, gtsc_khz, incarnation - 1);
}

static int copy_special_pages(struct domain *cd, struct domain *d)
{
    mfn_t new_mfn, old_mfn;
    gfn_t new_gfn, old_gfn;
    struct p2m_domain *p2m = p2m_get_hostp2m(cd);
    static const unsigned int params[] =
    {
        HVM_PARAM_STORE_PFN,
        HVM_PARAM_IOREQ_PFN,
        HVM_PARAM_BUFIOREQ_PFN,
        HVM_PARAM_CONSOLE_PFN
    };
    unsigned int i;
    int rc;

    for ( i = 0; i < ARRAY_SIZE(params); i++ )
    {
        p2m_type_t t;
        uint64_t value = 0;
        struct page_info *page;

        if ( hvm_get_param(d, params[i], &value) || !value )
            continue;

        old_mfn = get_gfn_query_unlocked(d, value, &t);
        new_mfn = get_gfn_query_unlocked(cd, value, &t);

        /* Allocate the page and map it in if it's not present */
        if ( mfn_eq(new_mfn, INVALID_MFN) )
        {
            if ( !(page = alloc_domheap_page(cd, 0)) )
                return -ENOMEM;

            new_mfn = page_to_mfn(page);
            set_gpfn_from_mfn(mfn_x(new_mfn), value);

            rc = p2m->set_entry(p2m, _gfn(value), new_mfn, PAGE_ORDER_4K,
                                p2m_ram_rw, p2m->default_access, -1);
            if ( rc )
                return rc;
        }

        copy_domain_page(new_mfn, old_mfn);
    }

    old_mfn = _mfn(virt_to_mfn(d->shared_info));
    new_mfn = _mfn(virt_to_mfn(cd->shared_info));
    copy_domain_page(new_mfn, old_mfn);

    old_gfn = _gfn(get_gpfn_from_mfn(mfn_x(old_mfn)));
    new_gfn = _gfn(get_gpfn_from_mfn(mfn_x(new_mfn)));

    if ( !gfn_eq(old_gfn, new_gfn) )
    {
        if ( !gfn_eq(new_gfn, INVALID_GFN) )
        {
            /* if shared_info is mapped to a different gfn just remove it */
            rc = p2m->set_entry(p2m, new_gfn, INVALID_MFN, PAGE_ORDER_4K,
                                p2m_invalid, p2m->default_access, -1);
            if ( rc )
                return rc;
        }

        if ( !gfn_eq(old_gfn, INVALID_GFN) )
        {
            /* now map it to the same gfn as the parent */
            rc = p2m->set_entry(p2m, old_gfn, new_mfn, PAGE_ORDER_4K,
                                p2m_ram_rw, p2m->default_access, -1);
            if ( rc )
                return rc;
        }
    }

    return 0;
}

static int copy_settings(struct domain *cd, struct domain *d)
{
    int rc;

    if ( (rc = copy_vcpu_settings(cd, d)) )
        return rc;

    if ( (rc = hvm_copy_context_and_params(cd, d)) )
        return rc;

    if ( (rc = copy_special_pages(cd, d)) )
        return rc;

    copy_tsc(cd, d);

    return rc;
}

static int fork(struct domain *cd, struct domain *d)
{
    int rc = -EBUSY;

    if ( !cd->controller_pause_count )
        return rc;

    if ( !cd->parent )
    {
        if ( !get_domain(d) )
        {
            ASSERT_UNREACHABLE();
            return -EBUSY;
        }

        domain_pause(d);
        cd->max_pages = d->max_pages;
        cd->parent = d;
    }

    /* This is preemptible so it's the first to get done */
    if ( (rc = fork_hap_allocation(cd, d)) )
        goto done;

    if ( (rc = bring_up_vcpus(cd, d)) )
        goto done;

    rc = copy_settings(cd, d);

 done:
    if ( rc && rc != -ERESTART )
    {
        domain_unpause(d);
        put_domain(d);
        cd->parent = NULL;
    }

    return rc;
}

/*
 * The fork reset operation is intended to be used on short-lived forks only.
 * There is no hypercall continuation operation implemented for this reason.
 * For forks that obtain a larger memory footprint it is likely going to be
 * more performant to create a new fork instead of resetting an existing one.
 *
 * TODO: In case this hypercall would become useful on forks with larger memory
 * footprints the hypercall continuation should be implemented (or if this
 * feature needs to be become "stable").
 */
static int mem_sharing_fork_reset(struct domain *d, struct domain *pd)
{
    int rc;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    struct page_info *page, *tmp;

    domain_pause(d);

    /* need recursive lock because we will free pages */
    spin_lock_recursive(&d->page_alloc_lock);
    page_list_for_each_safe(page, tmp, &d->page_list)
    {
        shr_handle_t sh;
        mfn_t mfn = page_to_mfn(page);
        gfn_t gfn = mfn_to_gfn(d, mfn);

        /*
         * We only want to remove pages from the fork here that were copied
         * from the parent but could be potentially re-populated using memory
         * sharing after the reset. These pages all must be regular pages with
         * no extra reference held to them, thus should be possible to make
         * them sharable. Unfortunately p2m_is_sharable check is not sufficient
         * to test this as it doesn't check the page's reference count. We thus
         * check whether the page is convertable to the shared type using
         * nominate_page. In case the page is already shared (ie. a share
         * handle is returned) then we don't remove it.
         */
        if ( (rc = nominate_page(d, gfn, 0, true, &sh)) || sh )
            continue;

        /* forked memory is 4k, not splitting large pages so this must work */
        rc = p2m->set_entry(p2m, gfn, INVALID_MFN, PAGE_ORDER_4K,
                            p2m_invalid, p2m_access_rwx, -1);
        ASSERT(!rc);

        put_page_alloc_ref(page);
        put_page_and_type(page);
    }
    spin_unlock_recursive(&d->page_alloc_lock);

    rc = copy_settings(d, pd);

    domain_unpause(d);

    return rc;
}

int mem_sharing_memop(XEN_GUEST_HANDLE_PARAM(xen_mem_sharing_op_t) arg)
{
    int rc;
    xen_mem_sharing_op_t mso;
    struct domain *d;

    rc = -EFAULT;
    if ( copy_from_guest(&mso, arg, 1) )
        return rc;

    if ( mso.op == XENMEM_sharing_op_audit )
        return audit();

    rc = rcu_lock_live_remote_domain_by_id(mso.domain, &d);
    if ( rc )
        return rc;

    rc = xsm_mem_sharing(XSM_DM_PRIV, d);
    if ( rc )
        goto out;

    if ( !mem_sharing_enabled(d) &&
         (rc = mem_sharing_control(d, true, 0)) )
        return rc;

    switch ( mso.op )
    {
    case XENMEM_sharing_op_nominate_gfn:
    {
        shr_handle_t handle;

        rc = nominate_page(d, _gfn(mso.u.nominate.u.gfn), 0, false, &handle);
        mso.u.nominate.handle = handle;
    }
    break;

    case XENMEM_sharing_op_nominate_gref:
    {
        grant_ref_t gref = mso.u.nominate.u.grant_ref;
        gfn_t gfn;
        shr_handle_t handle;

        rc = mem_sharing_gref_to_gfn(d->grant_table, gref, &gfn, NULL);
        if ( rc < 0 )
            goto out;

        rc = nominate_page(d, gfn, 3, false, &handle);
        mso.u.nominate.handle = handle;
    }
    break;

    case XENMEM_sharing_op_share:
    {
        gfn_t sgfn, cgfn;
        struct domain *cd;
        shr_handle_t sh, ch;

        rc = rcu_lock_live_remote_domain_by_id(mso.u.share.client_domain,
                                               &cd);
        if ( rc )
            goto out;

        rc = xsm_mem_sharing_op(XSM_DM_PRIV, d, cd, mso.op);
        if ( rc )
        {
            rcu_unlock_domain(cd);
            goto out;
        }

        if ( !mem_sharing_enabled(cd) )
        {
            rcu_unlock_domain(cd);
            rc = -EINVAL;
            goto out;
        }

        if ( XENMEM_SHARING_OP_FIELD_IS_GREF(mso.u.share.source_gfn) )
        {
            grant_ref_t gref =
                XENMEM_SHARING_OP_FIELD_GET_GREF(mso.u.share.source_gfn);

            rc = mem_sharing_gref_to_gfn(d->grant_table, gref, &sgfn,
                                         NULL);
            if ( rc < 0 )
            {
                rcu_unlock_domain(cd);
                goto out;
            }
        }
        else
            sgfn = _gfn(mso.u.share.source_gfn);

        if ( XENMEM_SHARING_OP_FIELD_IS_GREF(mso.u.share.client_gfn) )
        {
            grant_ref_t gref =
                XENMEM_SHARING_OP_FIELD_GET_GREF(mso.u.share.client_gfn);

            rc = mem_sharing_gref_to_gfn(cd->grant_table, gref, &cgfn,
                                         NULL);
            if ( rc < 0 )
            {
                rcu_unlock_domain(cd);
                goto out;
            }
        }
        else
            cgfn = _gfn(mso.u.share.client_gfn);

        sh = mso.u.share.source_handle;
        ch = mso.u.share.client_handle;

        rc = share_pages(d, sgfn, sh, cd, cgfn, ch);

        rcu_unlock_domain(cd);
    }
    break;

    case XENMEM_sharing_op_add_physmap:
    {
        unsigned long sgfn, cgfn;
        struct domain *cd;
        shr_handle_t sh;

        rc = rcu_lock_live_remote_domain_by_id(mso.u.share.client_domain,
                                               &cd);
        if ( rc )
            goto out;

        rc = xsm_mem_sharing_op(XSM_DM_PRIV, d, cd, mso.op);
        if ( rc )
        {
            rcu_unlock_domain(cd);
            goto out;
        }

        if ( !mem_sharing_enabled(cd) )
        {
            rcu_unlock_domain(cd);
            rc = -EINVAL;
            goto out;
        }

        if ( XENMEM_SHARING_OP_FIELD_IS_GREF(mso.u.share.source_gfn) )
        {
            /* Cannot add a gref to the physmap */
            rcu_unlock_domain(cd);
            rc = -EINVAL;
            goto out;
        }

        sgfn    = mso.u.share.source_gfn;
        sh      = mso.u.share.source_handle;
        cgfn    = mso.u.share.client_gfn;

        rc = add_to_physmap(d, sgfn, sh, cd, cgfn, true);

        rcu_unlock_domain(cd);
    }
    break;

    case XENMEM_sharing_op_range_share:
    {
        unsigned long max_sgfn, max_cgfn;
        struct domain *cd;

        rc = -EINVAL;
        if ( mso.u.range._pad[0] || mso.u.range._pad[1] ||
             mso.u.range._pad[2] )
            goto out;

        /*
         * We use opaque for the hypercall continuation value.
         * Ideally the user sets this to 0 in the beginning but
         * there is no good way of enforcing that here, so we just check
         * that it's at least in range.
         */
        if ( mso.u.range.opaque &&
             (mso.u.range.opaque < mso.u.range.first_gfn ||
              mso.u.range.opaque > mso.u.range.last_gfn) )
            goto out;

        rc = rcu_lock_live_remote_domain_by_id(mso.u.range.client_domain,
                                               &cd);
        if ( rc )
            goto out;

        /*
         * We reuse XENMEM_sharing_op_share XSM check here as this is
         * essentially the same concept repeated over multiple pages.
         */
        rc = xsm_mem_sharing_op(XSM_DM_PRIV, d, cd,
                                XENMEM_sharing_op_share);
        if ( rc )
        {
            rcu_unlock_domain(cd);
            goto out;
        }

        if ( !mem_sharing_enabled(cd) )
        {
            rcu_unlock_domain(cd);
            rc = -EINVAL;
            goto out;
        }

        /*
         * Sanity check only, the client should keep the domains paused for
         * the duration of this op.
         */
        if ( !atomic_read(&d->pause_count) ||
             !atomic_read(&cd->pause_count) )
        {
            rcu_unlock_domain(cd);
            rc = -EINVAL;
            goto out;
        }

        max_sgfn = domain_get_maximum_gpfn(d);
        max_cgfn = domain_get_maximum_gpfn(cd);

        if ( max_sgfn < mso.u.range.first_gfn ||
             max_sgfn < mso.u.range.last_gfn ||
             max_cgfn < mso.u.range.first_gfn ||
             max_cgfn < mso.u.range.last_gfn )
        {
            rcu_unlock_domain(cd);
            rc = -EINVAL;
            goto out;
        }

        rc = range_share(d, cd, &mso.u.range);
        rcu_unlock_domain(cd);

        if ( rc > 0 )
        {
            if ( __copy_to_guest(arg, &mso, 1) )
                rc = -EFAULT;
            else
                rc = hypercall_create_continuation(__HYPERVISOR_memory_op,
                                                   "lh", XENMEM_sharing_op,
                                                   arg);
        }
        else
            mso.u.range.opaque = 0;
    }
    break;

    case XENMEM_sharing_op_debug_gfn:
        rc = debug_gfn(d, _gfn(mso.u.debug.u.gfn));
        break;

    case XENMEM_sharing_op_debug_gref:
        rc = debug_gref(d, mso.u.debug.u.gref);
        break;

    case XENMEM_sharing_op_fork:
    {
        struct domain *pd;

        rc = -EINVAL;
        if ( mso.u.fork.pad )
            goto out;
        if ( mso.u.fork.flags & ~XENMEM_FORK_WITH_IOMMU_ALLOWED )
            goto out;

        rc = rcu_lock_live_remote_domain_by_id(mso.u.fork.parent_domain,
                                               &pd);
        if ( rc )
            goto out;

        rc = -EINVAL;
        if ( pd->max_vcpus != d->max_vcpus )
        {
            rcu_unlock_domain(pd);
            goto out;
        }

        if ( !mem_sharing_enabled(pd) &&
             (rc = mem_sharing_control(pd, true, mso.u.fork.flags)) )
        {
            rcu_unlock_domain(pd);
            goto out;
        }

        rc = fork(d, pd);

        if ( rc == -ERESTART )
            rc = hypercall_create_continuation(__HYPERVISOR_memory_op,
                                               "lh", XENMEM_sharing_op,
                                               arg);
        rcu_unlock_domain(pd);
        break;
    }

    case XENMEM_sharing_op_fork_reset:
    {
        struct domain *pd;

        rc = -EINVAL;
        if ( mso.u.fork.pad || mso.u.fork.flags )
            goto out;

        rc = -ENOSYS;
        if ( !d->parent )
            goto out;

        rc = rcu_lock_live_remote_domain_by_id(d->parent->domain_id, &pd);
        if ( rc )
            goto out;

        rc = mem_sharing_fork_reset(d, pd);

        rcu_unlock_domain(pd);
        break;
    }

    default:
        rc = -ENOSYS;
        break;
    }

    if ( !rc && __copy_to_guest(arg, &mso, 1) )
        rc = -EFAULT;

out:
    rcu_unlock_domain(d);
    return rc;
}

int mem_sharing_domctl(struct domain *d, struct xen_domctl_mem_sharing_op *mec)
{
    int rc;

    switch ( mec->op )
    {
    case XEN_DOMCTL_MEM_SHARING_CONTROL:
        rc = mem_sharing_control(d, mec->u.enable, 0);
        break;

    default:
        rc = -ENOSYS;
        break;
    }

    return rc;
}
