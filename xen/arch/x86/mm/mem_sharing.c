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
#include <xsm/xsm.h>

#include "mm-locks.h"

static shr_handle_t next_handle = 1;

typedef struct pg_lock_data {
    int mm_unlock_level;
    unsigned short recurse_count;
} pg_lock_data_t;

static DEFINE_PER_CPU(pg_lock_data_t, __pld);

#define MEM_SHARING_DEBUG(_f, _a...)                                  \
    debugtrace_printk("mem_sharing_debug: %s(): " _f, __func__, ##_a)

/* Reverse map defines */
#define RMAP_HASHTAB_ORDER  0
#define RMAP_HASHTAB_SIZE   \
        ((PAGE_SIZE << RMAP_HASHTAB_ORDER) / sizeof(struct list_head))
#define RMAP_USES_HASHTAB(page) \
        ((page)->sharing->hash_table.flag == NULL)
#define RMAP_HEAVY_SHARED_PAGE   RMAP_HASHTAB_SIZE
/* A bit of hysteresis. We don't want to be mutating between list and hash
 * table constantly. */
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

static inline void audit_add_list(struct page_info *page)
{
    INIT_LIST_HEAD(&page->sharing->entry);
    spin_lock(&shr_audit_lock);
    list_add_rcu(&page->sharing->entry, &shr_audit_list);
    spin_unlock(&shr_audit_lock);
}

/* Removes from the audit list and cleans up the page sharing metadata. */
static inline void page_sharing_dispose(struct page_info *page)
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
static inline void page_sharing_dispose(struct page_info *page)
{
    /* Unlikely given our thresholds, but we should be careful. */
    if ( unlikely(RMAP_USES_HASHTAB(page)) )
        free_xenheap_pages(page->sharing->hash_table.bucket, 
                            RMAP_HASHTAB_ORDER);
    xfree(page->sharing);
}

#endif /* MEM_SHARING_AUDIT */

static inline int mem_sharing_page_lock(struct page_info *pg)
{
    int rc;
    pg_lock_data_t *pld = &(this_cpu(__pld));

    page_sharing_mm_pre_lock();
    rc = page_lock(pg);
    if ( rc )
    {
        preempt_disable();
        page_sharing_mm_post_lock(&pld->mm_unlock_level, 
                                  &pld->recurse_count);
    }
    return rc;
}

static inline void mem_sharing_page_unlock(struct page_info *pg)
{
    pg_lock_data_t *pld = &(this_cpu(__pld));

    page_sharing_mm_unlock(pld->mm_unlock_level, 
                           &pld->recurse_count);
    preempt_enable();
    page_unlock(pg);
}

static inline shr_handle_t get_next_handle(void)
{
    /* Get the next handle get_page style */ 
    uint64_t x, y = next_handle;
    do {
        x = y;
    }
    while ( (y = cmpxchg(&next_handle, x, x + 1)) != x );
    return x + 1;
}

#define mem_sharing_enabled(d) \
    (is_hvm_domain(d) && (d)->arch.hvm.mem_sharing_enabled)

static atomic_t nr_saved_mfns   = ATOMIC_INIT(0); 
static atomic_t nr_shared_mfns  = ATOMIC_INIT(0);

/** Reverse map **/
/* Every shared frame keeps a reverse map (rmap) of <domain, gfn> tuples that
 * this shared frame backs. For pages with a low degree of sharing, a O(n)
 * search linked list is good enough. For pages with higher degree of sharing,
 * we use a hash table instead. */

typedef struct gfn_info
{
    unsigned long gfn;
    domid_t domain; 
    struct list_head list;
} gfn_info_t;

static inline void
rmap_init(struct page_info *page)
{
    /* We always start off as a doubly linked list. */
    INIT_LIST_HEAD(&page->sharing->gfns);
}

/* Exceedingly simple "hash function" */
#define HASH(domain, gfn)       \
    (((gfn) + (domain)) % RMAP_HASHTAB_SIZE)

/* Conversions. Tuned by the thresholds. Should only happen twice 
 * (once each) during the lifetime of a shared page */
static inline int
rmap_list_to_hash_table(struct page_info *page)
{
    unsigned int i;
    struct list_head *pos, *tmp, *b =
        alloc_xenheap_pages(RMAP_HASHTAB_ORDER, 0);

    if ( b == NULL )
        return -ENOMEM;

    for ( i = 0; i < RMAP_HASHTAB_SIZE; i++ )
        INIT_LIST_HEAD(b + i);

    list_for_each_safe(pos, tmp, &page->sharing->gfns)
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

static inline void
rmap_hash_table_to_list(struct page_info *page)
{
    unsigned int i;
    struct list_head *bucket = page->sharing->hash_table.bucket;

    INIT_LIST_HEAD(&page->sharing->gfns);

    for ( i = 0; i < RMAP_HASHTAB_SIZE; i++ )
    {
        struct list_head *pos, *tmp, *head = bucket + i;
        list_for_each_safe(pos, tmp, head)
        {
            list_del(pos);
            list_add(pos, &page->sharing->gfns);
        }
    }

    free_xenheap_pages(bucket, RMAP_HASHTAB_ORDER);
}

/* Generic accessors to the rmap */
static inline unsigned long
rmap_count(struct page_info *pg)
{
    unsigned long count;
    unsigned long t = read_atomic(&pg->u.inuse.type_info);
    count = t & PGT_count_mask;
    if ( t & PGT_locked )
        count--;
    return count;
}

/* The page type count is always decreased after removing from the rmap.
 * Use a convert flag to avoid mutating the rmap if in the middle of an 
 * iterator, or if the page will be soon destroyed anyways. */
static inline void
rmap_del(gfn_info_t *gfn_info, struct page_info *page, int convert)
{
    if ( RMAP_USES_HASHTAB(page) && convert &&
         (rmap_count(page) <= RMAP_LIGHT_SHARED_PAGE) )
        rmap_hash_table_to_list(page);

    /* Regardless of rmap type, same removal operation */
    list_del(&gfn_info->list);
}

/* The page type count is always increased before adding to the rmap. */
static inline void
rmap_add(gfn_info_t *gfn_info, struct page_info *page)
{
    struct list_head *head;

    if ( !RMAP_USES_HASHTAB(page) &&
         (rmap_count(page) >= RMAP_HEAVY_SHARED_PAGE) )
        /* The conversion may fail with ENOMEM. We'll be less efficient,
         * but no reason to panic. */
        (void)rmap_list_to_hash_table(page);

    head = (RMAP_USES_HASHTAB(page)) ?
        page->sharing->hash_table.bucket + 
                            HASH(gfn_info->domain, gfn_info->gfn) :
        &page->sharing->gfns;

    INIT_LIST_HEAD(&gfn_info->list);
    list_add(&gfn_info->list, head);
}

static inline gfn_info_t *
rmap_retrieve(uint16_t domain_id, unsigned long gfn, 
                            struct page_info *page)
{
    gfn_info_t *gfn_info;
    struct list_head *le, *head;

    head = (RMAP_USES_HASHTAB(page)) ?
        page->sharing->hash_table.bucket + HASH(domain_id, gfn) :
        &page->sharing->gfns;

    list_for_each(le, head)
    {
        gfn_info = list_entry(le, gfn_info_t, list);
        if ( (gfn_info->gfn == gfn) && (gfn_info->domain == domain_id) )
            return gfn_info;
    }

    /* Nothing was found */
    return NULL;
}

/* Returns true if the rmap has only one entry. O(1) complexity. */
static inline int rmap_has_one_entry(struct page_info *page)
{
    return (rmap_count(page) == 1);
}

/* Returns true if the rmap has any entries. O(1) complexity. */
static inline int rmap_has_entries(struct page_info *page)
{
    return (rmap_count(page) != 0);
}

/* The iterator hides the details of how the rmap is implemented. This
 * involves splitting the list_for_each_safe macro into two steps. */
struct rmap_iterator {
    struct list_head *curr;
    struct list_head *next;
    unsigned int bucket;
};

static inline void
rmap_seed_iterator(struct page_info *page, struct rmap_iterator *ri)
{
    ri->curr = (RMAP_USES_HASHTAB(page)) ?
                page->sharing->hash_table.bucket :
                &page->sharing->gfns;
    ri->next = ri->curr->next; 
    ri->bucket = 0;
}

static inline gfn_info_t *
rmap_iterate(struct page_info *page, struct rmap_iterator *ri)
{
    struct list_head *head = (RMAP_USES_HASHTAB(page)) ?
                page->sharing->hash_table.bucket + ri->bucket :
                &page->sharing->gfns;

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
        } else
            /* List exhausted */
            return NULL;
    }

    ri->curr = ri->next;
    ri->next = ri->curr->next;

    return list_entry(ri->curr, gfn_info_t, list);
}

static inline gfn_info_t *mem_sharing_gfn_alloc(struct page_info *page,
                                                struct domain *d,
                                                unsigned long gfn)
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

static inline void mem_sharing_gfn_destroy(struct page_info *page,
                                           struct domain *d,
                                           gfn_info_t *gfn_info)
{
    /* Decrement the number of pages. */
    atomic_dec(&d->shr_pages);

    /* Free the gfn_info structure. */
    rmap_del(gfn_info, page, 1);
    xfree(gfn_info);
}

static struct page_info* mem_sharing_lookup(unsigned long mfn)
{
    if ( mfn_valid(_mfn(mfn)) )
    {
        struct page_info* page = mfn_to_page(_mfn(mfn));
        if ( page_get_owner(page) == dom_cow )
        {
            /* Count has to be at least two, because we're called
             * with the mfn locked (1) and this is supposed to be 
             * a shared page (1). */
            unsigned long t = read_atomic(&page->u.inuse.type_info);
            ASSERT((t & PGT_type_mask) == PGT_shared_page);
            ASSERT((t & PGT_count_mask) >= 2);
            ASSERT(SHARED_M2P(get_gpfn_from_mfn(mfn)));
            return page;
        }
    }

    return NULL;
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

    list_for_each_rcu(ae, &shr_audit_list)
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
           MEM_SHARING_DEBUG("mfn %lx in audit list, but cannot be locked (%lx)!\n",
                              mfn_x(mfn), pg->u.inuse.type_info);
           errors++;
           continue;
        }

        /* Check if the MFN has correct type, owner and handle. */ 
        if ( (pg->u.inuse.type_info & PGT_type_mask) != PGT_shared_page )
        {
           MEM_SHARING_DEBUG("mfn %lx in audit list, but not PGT_shared_page (%lx)!\n",
                              mfn_x(mfn), pg->u.inuse.type_info & PGT_type_mask);
           errors++;
           continue;
        }

        /* Check the page owner. */
        if ( page_get_owner(pg) != dom_cow )
        {
           MEM_SHARING_DEBUG("mfn %lx shared, but wrong owner (%hu)!\n",
                             mfn_x(mfn), page_get_owner(pg)->domain_id);
           errors++;
        }

        /* Check the m2p entry */
        if ( !SHARED_M2P(get_gpfn_from_mfn(mfn_x(mfn))) )
        {
           MEM_SHARING_DEBUG("mfn %lx shared, but wrong m2p entry (%lx)!\n",
                             mfn_x(mfn), get_gpfn_from_mfn(mfn_x(mfn)));
           errors++;
        }

        /* Check we have a list */
        if ( (!pg->sharing) || !rmap_has_entries(pg) )
        {
           MEM_SHARING_DEBUG("mfn %lx shared, but empty gfn list!\n",
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
                MEM_SHARING_DEBUG("Unknown dom: %hu, for PFN=%lx, MFN=%lx\n",
                                  g->domain, g->gfn, mfn_x(mfn));
                errors++;
                continue;
            }
            o_mfn = get_gfn_query_unlocked(d, g->gfn, &t); 
            if ( !mfn_eq(o_mfn, mfn) )
            {
                MEM_SHARING_DEBUG("Incorrect P2M for d=%hu, PFN=%lx."
                                  "Expecting MFN=%lx, got %lx\n",
                                  g->domain, g->gfn, mfn_x(mfn), mfn_x(o_mfn));
                errors++;
            }
            if ( t != p2m_ram_shared )
            {
                MEM_SHARING_DEBUG("Incorrect P2M type for d=%hu, PFN=%lx MFN=%lx."
                                  "Expecting t=%d, got %d\n",
                                  g->domain, g->gfn, mfn_x(mfn), p2m_ram_shared, t);
                errors++;
            }
            put_domain(d);
            nr_gfns++;
        }
        /* The type count has an extra ref because we have locked the page */
        if ( (nr_gfns + 1) != (pg->u.inuse.type_info & PGT_count_mask) )
        {
            MEM_SHARING_DEBUG("Mismatched counts for MFN=%lx."
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
        MEM_SHARING_DEBUG("Expected %ld shared mfns, found %ld.",
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
        .u.mem_sharing.p2mt = p2m_ram_shared
    };

    if ( (rc = __vm_event_claim_slot(d, 
                        d->vm_event_share, allow_sleep)) < 0 )
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
    return ((unsigned int)atomic_read(&nr_saved_mfns));
}

unsigned int mem_sharing_get_nr_shared_mfns(void)
{
    return (unsigned int)atomic_read(&nr_shared_mfns);
}

/* Functions that change a page's type and ownership */
static int page_make_sharable(struct domain *d, 
                       struct page_info *page, 
                       int expected_refcnt)
{
    bool_t drop_dom_ref;

    spin_lock(&d->page_alloc_lock);

    if ( d->is_dying )
    {
        spin_unlock(&d->page_alloc_lock);
        return -EBUSY;
    }

    /* Change page type and count atomically */
    if ( !get_page_and_type(page, d, PGT_shared_page) )
    {
        spin_unlock(&d->page_alloc_lock);
        return -EINVAL;
    }

    /* Check it wasn't already sharable and undo if it was */
    if ( (page->u.inuse.type_info & PGT_count_mask) != 1 )
    {
        spin_unlock(&d->page_alloc_lock);
        put_page_and_type(page);
        return -EEXIST;
    }

    /* Check if the ref count is 2. The first from PGC_allocated, and
     * the second from get_page_and_type at the top of this function */
    if ( page->count_info != (PGC_allocated | (2 + expected_refcnt)) )
    {
        spin_unlock(&d->page_alloc_lock);
        /* Return type count back to zero */
        put_page_and_type(page);
        return -E2BIG;
    }

    page_set_owner(page, dom_cow);
    drop_dom_ref = !domain_adjust_tot_pages(d, -1);
    page_list_del(page, &d->page_list);
    spin_unlock(&d->page_alloc_lock);

    if ( drop_dom_ref )
        put_domain(d);
    return 0;
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

    /* We can only change the type if count is one */
    /* Because we are locking pages individually, we need to drop
     * the lock here, while the page is typed. We cannot risk the 
     * race of page_unlock and then put_page_type. */
    expected_type = (PGT_shared_page | PGT_validated | PGT_locked | 2);
    if ( page->u.inuse.type_info != expected_type )
    {
        spin_unlock(&d->page_alloc_lock);
        put_page(page);
        return -EEXIST;
    }

    /* Drop the final typecount */
    put_page_and_type(page);

    /* Now that we've dropped the type, we can unlock */
    mem_sharing_page_unlock(page);

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

static inline struct page_info *__grab_shared_page(mfn_t mfn)
{
    struct page_info *pg = NULL;

    if ( !mfn_valid(mfn) )
        return NULL;
    pg = mfn_to_page(mfn);

    /* If the page is not validated we can't lock it, and if it's  
     * not validated it's obviously not shared. */
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

    MEM_SHARING_DEBUG( 
            "Debug page: MFN=%lx is ci=%lx, ti=%lx, owner_id=%d\n",
            mfn_x(page_to_mfn(page)), 
            page->count_info, 
            page->u.inuse.type_info,
            page_get_owner(page)->domain_id);

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

    MEM_SHARING_DEBUG("Debug for dom%d, gfn=%" PRI_gfn "\n", 
                      d->domain_id, gfn_x(gfn));
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
        MEM_SHARING_DEBUG("Asked to debug [dom=%d,gref=%u]: error %d.\n",
                          d->domain_id, ref, rc);
        return rc;
    }
    
    MEM_SHARING_DEBUG(
            "==> Grant [dom=%d,ref=%d], status=%x. ", 
            d->domain_id, ref, status);

    return debug_gfn(d, gfn);
}

static int nominate_page(struct domain *d, gfn_t gfn,
                         int expected_refcnt, shr_handle_t *phandle)
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
    if ( p2m_is_shared(p2mt) ) {
        struct page_info *pg = __grab_shared_page(mfn);
        if ( !pg )
        {
            gprintk(XENLOG_ERR,
                    "Shared p2m entry gfn %" PRI_gfn ", but could not grab mfn %" PRI_mfn " dom%d\n",
                    gfn_x(gfn), mfn_x(mfn), d->domain_id);
            BUG();
        }
        *phandle = pg->sharing->handle;
        ret = 0;
        mem_sharing_page_unlock(pg);
        goto out;
    }

    /* Check p2m type */
    if ( !p2m_is_sharable(p2mt) )
        goto out;

#ifdef CONFIG_HVM
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
#endif

    /* Try to convert the mfn to the sharable type */
    page = mfn_to_page(mfn);
    ret = page_make_sharable(d, page, expected_refcnt); 
    if ( ret ) 
        goto out;

    /* Now that the page is validated, we can lock it. There is no 
     * race because we're holding the p2m entry, so no one else 
     * could be nominating this gfn */
    ret = -ENOENT;
    if ( !mem_sharing_page_lock(page) )
        goto out;

    /* Initialize the shared state */
    ret = -ENOMEM;
    if ( (page->sharing = 
            xmalloc(struct page_sharing_info)) == NULL )
    {
        /* Making a page private atomically unlocks it */
        BUG_ON(page_make_private(d, page) != 0);
        goto out;
    }
    page->sharing->pg = page;
    rmap_init(page);

    /* Create the handle */
    page->sharing->handle = get_next_handle();  

    /* Create the local gfn info */
    if ( mem_sharing_gfn_alloc(page, d, gfn_x(gfn)) == NULL )
    {
        xfree(page->sharing);
        page->sharing = NULL;
        BUG_ON(page_make_private(d, page) != 0);
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

    get_two_gfns(sd, sgfn, &smfn_type, NULL, &smfn,
                 cd, cgfn, &cmfn_type, NULL, &cmfn, 0, &tg);

    /* This tricky business is to avoid two callers deadlocking if 
     * grabbing pages in opposite client/source order */
    if ( mfn_eq(smfn, cmfn) )
    {
        /* The pages are already the same.  We could return some
         * kind of error here, but no matter how you look at it,
         * the pages are already 'shared'.  It possibly represents
         * a big problem somewhere else, but as far as sharing is
         * concerned: great success! */
        ret = 0;
        goto err_out;
    }
    else if ( mfn_x(smfn) < mfn_x(cmfn) )
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
    } else {
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

    /* Acquire an extra reference, for the freeing below to be safe. */
    if ( !get_page(cpage, dom_cow) )
    {
        ret = -EOVERFLOW;
        mem_sharing_page_unlock(secondpg);
        mem_sharing_page_unlock(firstpg);
        goto err_out;
    }

    /* Merge the lists together */
    rmap_seed_iterator(cpage, &ri);
    while ( (gfn = rmap_iterate(cpage, &ri)) != NULL)
    {
        /* Get the source page and type, this should never fail: 
         * we are under shr lock, and got a successful lookup */
        BUG_ON(!get_page_and_type(spage, dom_cow, PGT_shared_page));
        /* Move the gfn_info from client list to source list.
         * Don't change the type of rmap for the client page. */
        rmap_del(gfn, cpage, 0);
        rmap_add(gfn, spage);
        put_page_and_type(cpage);
        d = get_domain_by_id(gfn->domain);
        BUG_ON(!d);
        BUG_ON(set_shared_p2m_entry(d, gfn->gfn, smfn));
        put_domain(d);
    }
    ASSERT(list_empty(&cpage->sharing->gfns));

    /* Clear the rest of the shared state */
    page_sharing_dispose(cpage);
    cpage->sharing = NULL;

    mem_sharing_page_unlock(secondpg);
    mem_sharing_page_unlock(firstpg);

    /* Free the client page */
    put_page_alloc_ref(cpage);
    put_page(cpage);

    /* We managed to free a domain page. */
    atomic_dec(&nr_shared_mfns);
    atomic_inc(&nr_saved_mfns);
    ret = 0;
    
err_out:
    put_two_gfns(&tg);
    return ret;
}

int mem_sharing_add_to_physmap(struct domain *sd, unsigned long sgfn, shr_handle_t sh,
                            struct domain *cd, unsigned long cgfn) 
{
    struct page_info *spage;
    int ret = -EINVAL;
    mfn_t smfn, cmfn;
    p2m_type_t smfn_type, cmfn_type;
    struct gfn_info *gfn_info;
    struct p2m_domain *p2m = p2m_get_hostp2m(cd);
    p2m_access_t a;
    struct two_gfns tg;

    get_two_gfns(sd, _gfn(sgfn), &smfn_type, NULL, &smfn,
                 cd, _gfn(cgfn), &cmfn_type, &a, &cmfn, 0, &tg);

    /* Get the source shared page, check and lock */
    ret = XENMEM_SHARING_OP_S_HANDLE_INVALID;
    spage = __grab_shared_page(smfn);
    if ( spage == NULL )
        goto err_out;
    ASSERT(smfn_type == p2m_ram_shared);

    /* Check that the handles match */
    if ( spage->sharing->handle != sh )
        goto err_unlock;

    /* Make sure the target page is a hole in the physmap. These are typically
     * p2m_mmio_dm, but also accept p2m_invalid and paged out pages. See the
     * definition of p2m_is_hole in p2m.h. */
    if ( !p2m_is_hole(cmfn_type) )
    {
        ret = XENMEM_SHARING_OP_C_HANDLE_INVALID;
        goto err_unlock;
    }

    /* This is simpler than regular sharing */
    BUG_ON(!get_page_and_type(spage, dom_cow, PGT_shared_page));
    if ( (gfn_info = mem_sharing_gfn_alloc(spage, cd, cgfn)) == NULL )
    {
        put_page_and_type(spage);
        ret = -ENOMEM;
        goto err_unlock;
    }

    ret = p2m_set_entry(p2m, _gfn(cgfn), smfn, PAGE_ORDER_4K,
                        p2m_ram_shared, a);

    /* Tempted to turn this into an assert */
    if ( ret )
    {
        mem_sharing_gfn_destroy(spage, cd, gfn_info);
        put_page_and_type(spage);
    } else {
        /* There is a chance we're plugging a hole where a paged out page was */
        if ( p2m_is_paging(cmfn_type) && (cmfn_type != p2m_ram_paging_out) )
        {
            atomic_dec(&cd->paged_pages);
            /* Further, there is a chance this was a valid page. Don't leak it. */
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
    put_two_gfns(&tg);
    return ret;
}


/* A note on the rationale for unshare error handling:
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
                             uint16_t flags)
{
    p2m_type_t p2mt;
    mfn_t mfn;
    struct page_info *page, *old_page;
    int last_gfn;
    gfn_info_t *gfn_info = NULL;
   
    mfn = get_gfn(d, gfn, &p2mt);
    
    /* Has someone already unshared it? */
    if ( !p2m_is_shared(p2mt) ) {
        put_gfn(d, gfn);
        return 0;
    }

    page = __grab_shared_page(mfn);
    if ( page == NULL )
    {
        gdprintk(XENLOG_ERR, "Domain p2m is shared, but page is not: "
                                "%lx\n", gfn);
        BUG();
    }

    gfn_info = rmap_retrieve(d->domain_id, gfn, page);
    if ( unlikely(gfn_info == NULL) )
    {
        gdprintk(XENLOG_ERR, "Could not find gfn_info for shared gfn: "
                                "%lx\n", gfn);
        BUG();
    }

    /* Do the accounting first. If anything fails below, we have bigger
     * bigger fish to fry. First, remove the gfn from the list. */ 
    last_gfn = rmap_has_one_entry(page);
    if ( last_gfn )
    {
        /* Clean up shared state. Get rid of the <domid, gfn> tuple
         * before destroying the rmap. */
        mem_sharing_gfn_destroy(page, d, gfn_info);
        page_sharing_dispose(page);
        page->sharing = NULL;
        atomic_dec(&nr_shared_mfns);
    }
    else
        atomic_dec(&nr_saved_mfns);

    /* If the GFN is getting destroyed drop the references to MFN 
     * (possibly freeing the page), and exit early */
    if ( flags & MEM_SHARING_DESTROY_GFN )
    {
        if ( !last_gfn )
            mem_sharing_gfn_destroy(page, d, gfn_info);
        put_page_and_type(page);
        mem_sharing_page_unlock(page);
        if ( last_gfn )
        {
            if ( !get_page(page, dom_cow) )
            {
                put_gfn(d, gfn);
                domain_crash(d);
                return -EOVERFLOW;
            }
            put_page_alloc_ref(page);
            put_page(page);
        }
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
        /* Caller is responsible for placing an event
         * in the ring */
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
        gdprintk(XENLOG_ERR, "Could not change p2m type d %hu gfn %lx.\n", 
                                d->domain_id, gfn);
        BUG();
    }

    /* Update m2p entry */
    set_gpfn_from_mfn(mfn_x(page_to_mfn(page)), gfn);

    /* Now that the gfn<->mfn map is properly established,
     * marking dirty is feasible */
    paging_mark_dirty(d, page_to_mfn(page));
    /* We do not need to unlock a private page */
    put_gfn(d, gfn);
    return 0;
}

int relinquish_shared_pages(struct domain *d)
{
    int rc = 0;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    unsigned long gfn, count = 0;

    if ( p2m == NULL )
        return 0;

    p2m_lock(p2m);
    for ( gfn = p2m->next_shared_gfn_to_relinquish;
          gfn <= p2m->max_mapped_pfn; gfn++ )
    {
        p2m_access_t a;
        p2m_type_t t;
        mfn_t mfn;
        int set_rc;

        if ( atomic_read(&d->shr_pages) == 0 )
            break;
        mfn = p2m->get_entry(p2m, _gfn(gfn), &t, &a, 0, NULL, NULL);
        if ( mfn_valid(mfn) && (t == p2m_ram_shared) )
        {
            /* Does not fail with ENOMEM given the DESTROY flag */
            BUG_ON(__mem_sharing_unshare_page(d, gfn, 
                    MEM_SHARING_DESTROY_GFN));
            /* Clear out the p2m entry so no one else may try to
             * unshare.  Must succeed: we just read the old entry and
             * we hold the p2m lock. */
            set_rc = p2m->set_entry(p2m, _gfn(gfn), _mfn(0), PAGE_ORDER_4K,
                                    p2m_invalid, p2m_access_rwx, -1);
            ASSERT(set_rc == 0);
            count += 0x10;
        }
        else
            ++count;

        /* Preempt every 2MiB (shared) or 32MiB (unshared) - arbitrary. */
        if ( count >= 0x2000 )
        {
            if ( hypercall_preempt_check() )
            {
                p2m->next_shared_gfn_to_relinquish = gfn + 1;
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
        rc = nominate_page(d, _gfn(start), 0, &sh);
        if ( rc == -ENOMEM )
            break;

        if ( !rc )
        {
            rc = nominate_page(cd, _gfn(start), 0, &ch);
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

    /* Only HAP is supported */
    rc = -ENODEV;
    if ( !hap_enabled(d) || !d->arch.hvm.mem_sharing_enabled )
        goto out;

    switch ( mso.op )
    {
        case XENMEM_sharing_op_nominate_gfn:
        {
            shr_handle_t handle;

            rc = -EINVAL;
            if ( !mem_sharing_enabled(d) )
                goto out;

            rc = nominate_page(d, _gfn(mso.u.nominate.u.gfn), 0, &handle);
            mso.u.nominate.handle = handle;
        }
        break;

        case XENMEM_sharing_op_nominate_gref:
        {
            grant_ref_t gref = mso.u.nominate.u.grant_ref;
            gfn_t gfn;
            shr_handle_t handle;

            rc = -EINVAL;
            if ( !mem_sharing_enabled(d) )
                goto out;
            rc = mem_sharing_gref_to_gfn(d->grant_table, gref, &gfn, NULL);
            if ( rc < 0 )
                goto out;

            rc = nominate_page(d, gfn, 3, &handle);
            mso.u.nominate.handle = handle;
        }
        break;

        case XENMEM_sharing_op_share:
        {
            gfn_t sgfn, cgfn;
            struct domain *cd;
            shr_handle_t sh, ch;

            rc = -EINVAL;
            if ( !mem_sharing_enabled(d) )
                goto out;

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
                grant_ref_t gref = (grant_ref_t) 
                                    (XENMEM_SHARING_OP_FIELD_GET_GREF(
                                        mso.u.share.source_gfn));
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
                grant_ref_t gref = (grant_ref_t) 
                                    (XENMEM_SHARING_OP_FIELD_GET_GREF(
                                        mso.u.share.client_gfn));
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

            rc = -EINVAL;
            if ( !mem_sharing_enabled(d) )
                goto out;

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

            rc = mem_sharing_add_to_physmap(d, sgfn, sh, cd, cgfn); 

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

            if ( !mem_sharing_enabled(d) )
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

    /* Only HAP is supported */
    if ( !hap_enabled(d) )
         return -ENODEV;

    switch(mec->op)
    {
        case XEN_DOMCTL_MEM_SHARING_CONTROL:
        {
            rc = 0;
            if ( unlikely(has_iommu_pt(d) && mec->u.enable) )
                rc = -EXDEV;
            else
                d->arch.hvm.mem_sharing_enabled = mec->u.enable;
        }
        break;

        default:
            rc = -ENOSYS;
    }

    return rc;
}
