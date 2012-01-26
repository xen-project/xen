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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <xen/types.h>
#include <xen/domain_page.h>
#include <xen/spinlock.h>
#include <xen/mm.h>
#include <xen/grant_table.h>
#include <xen/sched.h>
#include <asm/page.h>
#include <asm/string.h>
#include <asm/p2m.h>
#include <asm/mem_event.h>
#include <asm/atomic.h>

#include "mm-locks.h"

static shr_handle_t next_handle = 1;

typedef struct pg_lock_data {
    int mm_unlock_level;
    unsigned short recurse_count;
} pg_lock_data_t;

DEFINE_PER_CPU(pg_lock_data_t, __pld);

#if MEM_SHARING_AUDIT

static mm_lock_t shr_lock;

#define shr_lock()          _shr_lock()
#define shr_unlock()        _shr_unlock()
#define shr_locked_by_me()  _shr_locked_by_me()

static void mem_sharing_audit(void);

#define MEM_SHARING_DEBUG(_f, _a...)                                  \
    debugtrace_printk("mem_sharing_debug: %s(): " _f, __func__, ##_a)

static struct list_head shr_audit_list;

static inline void audit_add_list(struct page_info *page)
{
    INIT_LIST_HEAD(&page->shared_info->entry);
    list_add(&page->shared_info->entry, &shr_audit_list);
}

static inline void audit_del_list(struct page_info *page)
{
    list_del(&page->shared_info->entry);
}

static inline int mem_sharing_page_lock(struct page_info *p)
{
    return 1;
}
#define mem_sharing_page_unlock(p)   ((void)0)

#define get_next_handle()   next_handle++;
#else

#define shr_lock()          ((void)0)
#define shr_unlock()        ((void)0)
/* Only used inside audit code */
//#define shr_locked_by_me()  ((void)0)

#define mem_sharing_audit() ((void)0)

#define audit_add_list(p)  ((void)0)
#define audit_del_list(p)  ((void)0)

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
#endif /* MEM_SHARING_AUDIT */

#define mem_sharing_enabled(d) \
    (is_hvm_domain(d) && (d)->arch.hvm_domain.mem_sharing_enabled)

#undef mfn_to_page
#define mfn_to_page(_m) __mfn_to_page(mfn_x(_m))
#undef mfn_valid
#define mfn_valid(_mfn) __mfn_valid(mfn_x(_mfn))
#undef page_to_mfn
#define page_to_mfn(_pg) _mfn(__page_to_mfn(_pg))

static atomic_t nr_saved_mfns   = ATOMIC_INIT(0); 
static atomic_t nr_shared_mfns  = ATOMIC_INIT(0);

typedef struct gfn_info
{
    unsigned long gfn;
    domid_t domain; 
    struct list_head list;
} gfn_info_t;

/* Returns true if list has only one entry. O(1) complexity. */
static inline int list_has_one_entry(struct list_head *head)
{
    return (head->next != head) && (head->next->next == head);
}

static inline gfn_info_t *gfn_get_info(struct list_head *list)
{
    return list_entry(list->next, gfn_info_t, list);
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
    INIT_LIST_HEAD(&gfn_info->list);
    list_add(&gfn_info->list, &page->shared_info->gfns);

    /* Increment our number of shared pges. */
    atomic_inc(&d->shr_pages);

    return gfn_info;
}

static inline void mem_sharing_gfn_destroy(struct domain *d,
                                           gfn_info_t *gfn_info)
{
    /* Decrement the number of pages. */
    atomic_dec(&d->shr_pages);

    /* Free the gfn_info structure. */
    list_del(&gfn_info->list);
    xfree(gfn_info);
}

static struct page_info* mem_sharing_lookup(unsigned long mfn)
{
    if ( mfn_valid(_mfn(mfn)) )
    {
        struct page_info* page = mfn_to_page(_mfn(mfn));
        if ( page_get_owner(page) == dom_cow )
        {
            ASSERT(page->u.inuse.type_info & PGT_type_mask); 
            ASSERT(get_gpfn_from_mfn(mfn) == SHARED_M2P_ENTRY); 
            return page;
        }
    }

    return NULL;
}

#if MEM_SHARING_AUDIT
static void mem_sharing_audit(void)
{
    int errors = 0;
    unsigned long count_expected;
    unsigned long count_found = 0;
    struct list_head *ae;

    ASSERT(shr_locked_by_me());
    count_expected = atomic_read(&nr_shared_mfns);

    list_for_each(ae, &shr_audit_list)
    {
        struct page_sharing_info *shared_info;
        unsigned long nr_gfns = 0;
        struct page_info *pg;
        struct list_head *le;
        mfn_t mfn;

        shared_info = list_entry(ae, struct page_sharing_info, entry);
        pg = shared_info->pg;
        mfn = page_to_mfn(pg);

        /* Check if the MFN has correct type, owner and handle. */ 
        if ( !(pg->u.inuse.type_info & PGT_shared_page) )
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
        if ( get_gpfn_from_mfn(mfn_x(mfn)) != SHARED_M2P_ENTRY )
        {
           MEM_SHARING_DEBUG("mfn %lx shared, but wrong m2p entry (%lx)!\n",
                             mfn_x(mfn), get_gpfn_from_mfn(mfn_x(mfn)));
           errors++;
        }

        /* Check we have a list */
        if ( (!pg->shared_info) || (list_empty(&pg->shared_info->gfns)) )
        {
           MEM_SHARING_DEBUG("mfn %lx shared, but empty gfn list!\n",
                             mfn_x(mfn));
           errors++;
           continue;
        }

        /* We've found a page that is shared */
        count_found++;

        /* Check if all GFNs map to the MFN, and the p2m types */
        list_for_each(le, &pg->shared_info->gfns)
        {
            struct domain *d;
            p2m_type_t t;
            mfn_t o_mfn;
            gfn_info_t *g;

            g = list_entry(le, gfn_info_t, list);
            d = get_domain_by_id(g->domain);
            if ( d == NULL )
            {
                MEM_SHARING_DEBUG("Unknown dom: %hu, for PFN=%lx, MFN=%lx\n",
                                  g->domain, g->gfn, mfn_x(mfn));
                errors++;
                continue;
            }
            o_mfn = get_gfn_query_unlocked(d, g->gfn, &t); 
            if ( mfn_x(o_mfn) != mfn_x(mfn) )
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
        if ( nr_gfns != (pg->u.inuse.type_info & PGT_count_mask) )
        {
            MEM_SHARING_DEBUG("Mismatched counts for MFN=%lx."
                              "nr_gfns in list %lu, in type_info %lx\n",
                              mfn_x(mfn), nr_gfns, 
                              (pg->u.inuse.type_info & PGT_count_mask));
            errors++;
        }
    }

    if ( count_found != count_expected )
    {
        MEM_SHARING_DEBUG("Expected %ld shared mfns, found %ld.",
                          count_expected, count_found);
        errors++;
    }

}
#endif


static void mem_sharing_notify_helper(struct domain *d, unsigned long gfn)
{
    struct vcpu *v = current;
    mem_event_request_t req = { .type = MEM_EVENT_TYPE_SHARED };

    if ( v->domain != d )
    {
        /* XXX This path needs some attention.  For now, just fail foreign 
         * XXX requests to unshare if there's no memory.  This replaces 
         * XXX old code that BUG()ed here; the callers now BUG()
         * XXX elewhere. */
        gdprintk(XENLOG_ERR, 
                 "Failed alloc on unshare path for foreign (%d) lookup\n",
                 d->domain_id);
        return;
    }

    if (mem_event_claim_slot(d, &d->mem_event->share) < 0)
    {
        return;
    }

    req.flags = MEM_EVENT_FLAG_VCPU_PAUSED;
    vcpu_pause_nosync(v);

    req.gfn = gfn;
    req.p2mt = p2m_ram_shared;
    req.vcpu_id = v->vcpu_id;
    mem_event_put_request(d, &d->mem_event->share, &req);
}

unsigned int mem_sharing_get_nr_saved_mfns(void)
{
    return ((unsigned int)atomic_read(&nr_saved_mfns));
}

unsigned int mem_sharing_get_nr_shared_mfns(void)
{
    return (unsigned int)atomic_read(&nr_shared_mfns);
}

int mem_sharing_sharing_resume(struct domain *d)
{
    mem_event_response_t rsp;

    /* Get all requests off the ring */
    while ( mem_event_get_response(d, &d->mem_event->share, &rsp) )
    {
        if ( rsp.flags & MEM_EVENT_FLAG_DUMMY )
            continue;
        /* Unpause domain/vcpu */
        if ( rsp.flags & MEM_EVENT_FLAG_VCPU_PAUSED )
            vcpu_unpause(d->vcpu[rsp.vcpu_id]);
    }

    return 0;
}

int mem_sharing_debug_mfn(unsigned long mfn)
{
    struct page_info *page;

    if ( !mfn_valid(_mfn(mfn)) )
    {
        gdprintk(XENLOG_ERR, "Invalid MFN=%lx\n", mfn);
        return -1;
    }
    page = mfn_to_page(_mfn(mfn));

    gdprintk(XENLOG_DEBUG, 
            "Debug page: MFN=%lx is ci=%lx, ti=%lx, owner_id=%d\n",
            mfn_x(page_to_mfn(page)), 
            page->count_info, 
            page->u.inuse.type_info,
            page_get_owner(page)->domain_id);

    return 0;
}

int mem_sharing_debug_gfn(struct domain *d, unsigned long gfn)
{
    p2m_type_t p2mt;
    mfn_t mfn;

    mfn = get_gfn_unlocked(d, gfn, &p2mt);

    gdprintk(XENLOG_DEBUG, "Debug for domain=%d, gfn=%lx, ", 
               d->domain_id, 
               gfn);
    return mem_sharing_debug_mfn(mfn_x(mfn));
}

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
    ASSERT (t->gt_version != 0);
    if ( t->gt_version == 1 )
        return (grant_entry_header_t*)&shared_entry_v1(t, ref);
    else
        return &shared_entry_v2(t, ref).hdr;
}

static int mem_sharing_gref_to_gfn(struct domain *d, 
                                   grant_ref_t ref, 
                                   unsigned long *gfn)
{
    if ( d->grant_table->gt_version < 1 )
        return -1;

    if ( d->grant_table->gt_version == 1 ) 
    {
        grant_entry_v1_t *sha1;
        sha1 = &shared_entry_v1(d->grant_table, ref);
        *gfn = sha1->frame;
    } 
    else 
    {
        grant_entry_v2_t *sha2;
        sha2 = &shared_entry_v2(d->grant_table, ref);
        *gfn = sha2->full_page.frame;
    }
 
    return 0;
}


int mem_sharing_debug_gref(struct domain *d, grant_ref_t ref)
{
    grant_entry_header_t *shah;
    uint16_t status;
    unsigned long gfn;

    if ( d->grant_table->gt_version < 1 )
    {
        gdprintk(XENLOG_ERR, 
                "Asked to debug [dom=%d,gref=%d], but not yet inited.\n",
                d->domain_id, ref);
        return -1;
    }
    (void)mem_sharing_gref_to_gfn(d, ref, &gfn); 
    shah = shared_entry_header(d->grant_table, ref);
    if ( d->grant_table->gt_version == 1 ) 
        status = shah->flags;
    else 
        status = status_entry(d->grant_table, ref);
    
    gdprintk(XENLOG_DEBUG,
            "==> Grant [dom=%d,ref=%d], status=%x. ", 
            d->domain_id, ref, status);

    return mem_sharing_debug_gfn(d, gfn); 
}

/* Functions that change a page's type and ownership */
static int page_make_sharable(struct domain *d, 
                       struct page_info *page, 
                       int expected_refcnt)
{
    spin_lock(&d->page_alloc_lock);

    /* Change page type and count atomically */
    if ( !get_page_and_type(page, d, PGT_shared_page) )
    {
        spin_unlock(&d->page_alloc_lock);
        return -EINVAL;
    }

    /* Check it wasn't already sharable and undo if it was */
    if ( (page->u.inuse.type_info & PGT_count_mask) != 1 )
    {
        put_page_and_type(page);
        spin_unlock(&d->page_alloc_lock);
        return -EEXIST;
    }

    /* Check if the ref count is 2. The first from PGC_allocated, and
     * the second from get_page_and_type at the top of this function */
    if ( page->count_info != (PGC_allocated | (2 + expected_refcnt)) )
    {
        /* Return type count back to zero */
        put_page_and_type(page);
        spin_unlock(&d->page_alloc_lock);
        return -E2BIG;
    }

    page_set_owner(page, dom_cow);
    d->tot_pages--;
    page_list_del(page, &d->page_list);
    spin_unlock(&d->page_alloc_lock);
    return 0;
}

static int page_make_private(struct domain *d, struct page_info *page)
{
    unsigned long expected_type;

    if ( !get_page(page, dom_cow) )
        return -EINVAL;
    
    spin_lock(&d->page_alloc_lock);

    /* We can only change the type if count is one */
    /* If we are locking pages individually, then we need to drop
     * the lock here, while the page is typed. We cannot risk the 
     * race of page_unlock and then put_page_type. */
#if MEM_SHARING_AUDIT
    expected_type = (PGT_shared_page | PGT_validated | 1);
#else
    expected_type = (PGT_shared_page | PGT_validated | PGT_locked | 2);
#endif
    if ( page->u.inuse.type_info != expected_type )
    {
        put_page(page);
        spin_unlock(&d->page_alloc_lock);
        return -EEXIST;
    }

    /* Drop the final typecount */
    put_page_and_type(page);

#ifndef MEM_SHARING_AUDIT
    /* Now that we've dropped the type, we can unlock */
    mem_sharing_page_unlock(page);
#endif

    /* Change the owner */
    ASSERT(page_get_owner(page) == dom_cow);
    page_set_owner(page, d);

    d->tot_pages++;
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

int mem_sharing_nominate_page(struct domain *d,
                              unsigned long gfn,
                              int expected_refcnt,
                              shr_handle_t *phandle)
{
    p2m_type_t p2mt;
    mfn_t mfn;
    struct page_info *page = NULL; /* gcc... */
    int ret;
    struct gfn_info *gfn_info;

    *phandle = 0UL;

    shr_lock(); 
    mfn = get_gfn(d, gfn, &p2mt);

    /* Check if mfn is valid */
    ret = -EINVAL;
    if ( !mfn_valid(mfn) )
        goto out;

    /* Return the handle if the page is already shared */
    if ( p2m_is_shared(p2mt) ) {
        struct page_info *pg = __grab_shared_page(mfn);
        if ( !pg )
        {
            gdprintk(XENLOG_ERR, "Shared p2m entry gfn %lx, but could not "
                        "grab page %lx dom %d\n", gfn, mfn_x(mfn), d->domain_id);
            BUG();
        }
        *phandle = pg->shared_info->handle;
        ret = 0;
        mem_sharing_page_unlock(pg);
        goto out;
    }

    /* Check p2m type */
    if ( !p2m_is_sharable(p2mt) )
        goto out;

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
    if ( (page->shared_info = 
            xmalloc(struct page_sharing_info)) == NULL )
    {
        /* Making a page private atomically unlocks it */
        BUG_ON(page_make_private(d, page) != 0);
        goto out;
    }
    page->shared_info->pg = page;
    INIT_LIST_HEAD(&page->shared_info->gfns);

    /* Create the handle */
    page->shared_info->handle = get_next_handle();  

    /* Create the local gfn info */
    if ( (gfn_info = mem_sharing_gfn_alloc(page, d, gfn)) == NULL )
    {
        xfree(page->shared_info);
        page->shared_info = NULL;
        BUG_ON(page_make_private(d, page) != 0);
        goto out;
    }

    /* Change the p2m type */
    if ( p2m_change_type(d, gfn, p2mt, p2m_ram_shared) != p2mt ) 
    {
        /* This is unlikely, as the type must have changed since we've checked
         * it a few lines above.
         * The mfn needs to revert back to rw type. This should never fail,
         * since no-one knew that the mfn was temporarily sharable */
        mem_sharing_gfn_destroy(d, gfn_info);
        xfree(page->shared_info);
        page->shared_info = NULL;
        /* NOTE: We haven't yet added this to the audit list. */
        BUG_ON(page_make_private(d, page) != 0);
        goto out;
    }

    /* Account for this page. */
    atomic_inc(&nr_shared_mfns);

    /* Update m2p entry to SHARED_M2P_ENTRY */
    set_gpfn_from_mfn(mfn_x(mfn), SHARED_M2P_ENTRY);

    *phandle = page->shared_info->handle;
    audit_add_list(page);
    mem_sharing_page_unlock(page);
    ret = 0;

out:
    put_gfn(d, gfn);
    shr_unlock();
    return ret;
}

int mem_sharing_share_pages(struct domain *sd, unsigned long sgfn, shr_handle_t sh,
                            struct domain *cd, unsigned long cgfn, shr_handle_t ch) 
{
    struct page_info *spage, *cpage, *firstpg, *secondpg;
    struct list_head *le, *te;
    gfn_info_t *gfn;
    struct domain *d;
    int ret = -EINVAL;
    mfn_t smfn, cmfn;
    p2m_type_t smfn_type, cmfn_type;

    shr_lock();

    /* XXX if sd == cd handle potential deadlock by ordering
     * the get_ and put_gfn's */
    smfn = get_gfn(sd, sgfn, &smfn_type);
    cmfn = get_gfn(cd, cgfn, &cmfn_type);

    /* This tricky business is to avoid two callers deadlocking if 
     * grabbing pages in opposite client/source order */
    if( mfn_x(smfn) == mfn_x(cmfn) )
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
        ret = XEN_DOMCTL_MEM_SHARING_S_HANDLE_INVALID;
        spage = firstpg = __grab_shared_page(smfn);
        if ( spage == NULL )
            goto err_out;

        ret = XEN_DOMCTL_MEM_SHARING_C_HANDLE_INVALID;
        cpage = secondpg = __grab_shared_page(cmfn);
        if ( cpage == NULL )
        {
            mem_sharing_page_unlock(spage);
            goto err_out;
        }
    } else {
        ret = XEN_DOMCTL_MEM_SHARING_C_HANDLE_INVALID;
        cpage = firstpg = __grab_shared_page(cmfn);
        if ( cpage == NULL )
            goto err_out;

        ret = XEN_DOMCTL_MEM_SHARING_S_HANDLE_INVALID;
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
    if ( spage->shared_info->handle != sh )
    {
        ret = XEN_DOMCTL_MEM_SHARING_S_HANDLE_INVALID;
        mem_sharing_page_unlock(secondpg);
        mem_sharing_page_unlock(firstpg);
        goto err_out;
    }
    if ( cpage->shared_info->handle != ch )
    {
        ret = XEN_DOMCTL_MEM_SHARING_C_HANDLE_INVALID;
        mem_sharing_page_unlock(secondpg);
        mem_sharing_page_unlock(firstpg);
        goto err_out;
    }

    /* Merge the lists together */
    list_for_each_safe(le, te, &cpage->shared_info->gfns)
    {
        gfn = list_entry(le, gfn_info_t, list);
        /* Get the source page and type, this should never fail: 
         * we are under shr lock, and got a successful lookup */
        BUG_ON(!get_page_and_type(spage, dom_cow, PGT_shared_page));
        /* Move the gfn_info from client list to source list */
        list_del(&gfn->list);
        list_add(&gfn->list, &spage->shared_info->gfns);
        put_page_and_type(cpage);
        d = get_domain_by_id(gfn->domain);
        BUG_ON(!d);
        BUG_ON(set_shared_p2m_entry(d, gfn->gfn, smfn) == 0);
        put_domain(d);
    }
    ASSERT(list_empty(&cpage->shared_info->gfns));

    /* Clear the rest of the shared state */
    audit_del_list(cpage);
    xfree(cpage->shared_info);
    cpage->shared_info = NULL;

    mem_sharing_page_unlock(secondpg);
    mem_sharing_page_unlock(firstpg);

    /* Free the client page */
    if(test_and_clear_bit(_PGC_allocated, &cpage->count_info))
        put_page(cpage);

    /* We managed to free a domain page. */
    atomic_dec(&nr_shared_mfns);
    atomic_inc(&nr_saved_mfns);
    ret = 0;
    
err_out:
    put_gfn(cd, cgfn);
    put_gfn(sd, sgfn);
    shr_unlock();
    return ret;
}

int mem_sharing_unshare_page(struct domain *d,
                             unsigned long gfn, 
                             uint16_t flags)
{
    p2m_type_t p2mt;
    mfn_t mfn;
    struct page_info *page, *old_page;
    void *s, *t;
    int last_gfn;
    gfn_info_t *gfn_info = NULL;
    struct list_head *le;
   
    /* This is one of the reasons why we can't enforce ordering
     * between shr_lock and p2m fine-grained locks in mm-lock. 
     * Callers may walk in here already holding the lock for this gfn */
    shr_lock();
    mem_sharing_audit();
    mfn = get_gfn(d, gfn, &p2mt);
    
    /* Has someone already unshared it? */
    if ( !p2m_is_shared(p2mt) ) {
        put_gfn(d, gfn);
        shr_unlock();
        return 0;
    }

    page = __grab_shared_page(mfn);
    if ( page == NULL )
    {
        gdprintk(XENLOG_ERR, "Domain p2m is shared, but page is not: "
                                "%lx\n", gfn);
        BUG();
    }

    list_for_each(le, &page->shared_info->gfns)
    {
        gfn_info = list_entry(le, gfn_info_t, list);
        if ( (gfn_info->gfn == gfn) && (gfn_info->domain == d->domain_id) )
            goto gfn_found;
    }
    gdprintk(XENLOG_ERR, "Could not find gfn_info for shared gfn: "
                            "%lx\n", gfn);
    BUG();

gfn_found:
    /* Do the accounting first. If anything fails below, we have bigger
     * bigger fish to fry. First, remove the gfn from the list. */ 
    last_gfn = list_has_one_entry(&page->shared_info->gfns);
    mem_sharing_gfn_destroy(d, gfn_info);
    if ( last_gfn )
    {
        /* Clean up shared state */
        audit_del_list(page);
        xfree(page->shared_info);
        page->shared_info = NULL;
        atomic_dec(&nr_shared_mfns);
    }
    else
        atomic_dec(&nr_saved_mfns);
    /* If the GFN is getting destroyed drop the references to MFN 
     * (possibly freeing the page), and exit early */
    if ( flags & MEM_SHARING_DESTROY_GFN )
    {
        put_page_and_type(page);
        mem_sharing_page_unlock(page);
        if ( last_gfn && 
            test_and_clear_bit(_PGC_allocated, &page->count_info) ) 
            put_page(page);
        put_gfn(d, gfn);
        shr_unlock();

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
        mem_sharing_page_unlock(old_page);
        put_gfn(d, gfn);
        mem_sharing_notify_helper(d, gfn);
        shr_unlock();
        return -ENOMEM;
    }

    s = map_domain_page(__page_to_mfn(old_page));
    t = map_domain_page(__page_to_mfn(page));
    memcpy(t, s, PAGE_SIZE);
    unmap_domain_page(s);
    unmap_domain_page(t);

    BUG_ON(set_shared_p2m_entry(d, gfn, page_to_mfn(page)) == 0);
    mem_sharing_page_unlock(old_page);
    put_page_and_type(old_page);

private_page_found:    
    if ( p2m_change_type(d, gfn, p2m_ram_shared, p2m_ram_rw) != 
                                                p2m_ram_shared ) 
    {
        gdprintk(XENLOG_ERR, "Could not change p2m type d %hu gfn %lx.\n", 
                                d->domain_id, gfn);
        BUG();
    }

    /* Update m2p entry */
    set_gpfn_from_mfn(mfn_x(page_to_mfn(page)), gfn);

    /* Now that the gfn<->mfn map is properly established,
     * marking dirty is feasible */
    paging_mark_dirty(d, mfn_x(page_to_mfn(page)));
    /* We do not need to unlock a private page */
    put_gfn(d, gfn);
    shr_unlock();
    return 0;
}

int mem_sharing_domctl(struct domain *d, xen_domctl_mem_sharing_op_t *mec)
{
    int rc;

    /* Only HAP is supported */
    if ( !hap_enabled(d) )
         return -ENODEV;

    switch(mec->op)
    {
        case XEN_DOMCTL_MEM_EVENT_OP_SHARING_CONTROL:
        {
            d->arch.hvm_domain.mem_sharing_enabled = mec->u.enable;
            rc = 0;
        }
        break;

        case XEN_DOMCTL_MEM_EVENT_OP_SHARING_NOMINATE_GFN:
        {
            unsigned long gfn = mec->u.nominate.u.gfn;
            shr_handle_t handle;
            if ( !mem_sharing_enabled(d) )
                return -EINVAL;
            rc = mem_sharing_nominate_page(d, gfn, 0, &handle);
            mec->u.nominate.handle = handle;
        }
        break;

        case XEN_DOMCTL_MEM_EVENT_OP_SHARING_NOMINATE_GREF:
        {
            grant_ref_t gref = mec->u.nominate.u.grant_ref;
            unsigned long gfn;
            shr_handle_t handle;

            if ( !mem_sharing_enabled(d) )
                return -EINVAL;
            if ( mem_sharing_gref_to_gfn(d, gref, &gfn) < 0 )
                return -EINVAL;
            rc = mem_sharing_nominate_page(d, gfn, 3, &handle);
            mec->u.nominate.handle = handle;
        }
        break;

        case XEN_DOMCTL_MEM_EVENT_OP_SHARING_SHARE:
        {
            unsigned long sgfn, cgfn;
            struct domain *cd;
            shr_handle_t sh, ch;

            if ( !mem_sharing_enabled(d) )
                return -EINVAL;

            cd = get_domain_by_id(mec->u.share.client_domain);
            if ( !cd )
                return -ESRCH;

            if ( !mem_sharing_enabled(cd) )
            {
                put_domain(cd);
                return -EINVAL;
            }

            if ( XEN_DOMCTL_MEM_SHARING_FIELD_IS_GREF(mec->u.share.source_gfn) )
            {
                grant_ref_t gref = (grant_ref_t) 
                                    (XEN_DOMCTL_MEM_SHARING_FIELD_GET_GREF(
                                        mec->u.share.source_gfn));
                if ( mem_sharing_gref_to_gfn(d, gref, &sgfn) < 0 )
                {
                    put_domain(cd);
                    return -EINVAL;
                }
            } else {
                sgfn  = mec->u.share.source_gfn;
            }

            if ( XEN_DOMCTL_MEM_SHARING_FIELD_IS_GREF(mec->u.share.client_gfn) )
            {
                grant_ref_t gref = (grant_ref_t) 
                                    (XEN_DOMCTL_MEM_SHARING_FIELD_GET_GREF(
                                        mec->u.share.client_gfn));
                if ( mem_sharing_gref_to_gfn(cd, gref, &cgfn) < 0 )
                {
                    put_domain(cd);
                    return -EINVAL;
                }
            } else {
                cgfn  = mec->u.share.client_gfn;
            }

            sh = mec->u.share.source_handle;
            ch = mec->u.share.client_handle;

            rc = mem_sharing_share_pages(d, sgfn, sh, cd, cgfn, ch); 

            put_domain(cd);
        }
        break;

        case XEN_DOMCTL_MEM_EVENT_OP_SHARING_RESUME:
        {
            if ( !mem_sharing_enabled(d) )
                return -EINVAL;
            rc = mem_sharing_sharing_resume(d);
        }
        break;

        case XEN_DOMCTL_MEM_EVENT_OP_SHARING_DEBUG_GFN:
        {
            unsigned long gfn = mec->u.debug.u.gfn;
            rc = mem_sharing_debug_gfn(d, gfn);
        }
        break;

        case XEN_DOMCTL_MEM_EVENT_OP_SHARING_DEBUG_MFN:
        {
            unsigned long mfn = mec->u.debug.u.mfn;
            rc = mem_sharing_debug_mfn(mfn);
        }
        break;

        case XEN_DOMCTL_MEM_EVENT_OP_SHARING_DEBUG_GREF:
        {
            grant_ref_t gref = mec->u.debug.u.gref;
            rc = mem_sharing_debug_gref(d, gref);
        }
        break;

        default:
            rc = -ENOSYS;
            break;
    }

    shr_lock();
    mem_sharing_audit();
    shr_unlock();

    return rc;
}

void __init mem_sharing_init(void)
{
    printk("Initing memory sharing.\n");
#if MEM_SHARING_AUDIT
    mm_lock_init(&shr_lock);
    INIT_LIST_HEAD(&shr_audit_list);
#endif
}

