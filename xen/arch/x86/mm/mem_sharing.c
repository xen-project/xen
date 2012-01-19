/******************************************************************************
 * arch/x86/mm/mem_sharing.c
 *
 * Memory sharing support.
 *
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

/* Auditing of memory sharing code? */
#define MEM_SHARING_AUDIT 0

#if MEM_SHARING_AUDIT
static void mem_sharing_audit(void);
#define MEM_SHARING_DEBUG(_f, _a...)                                  \
    debugtrace_printk("mem_sharing_debug: %s(): " _f, __func__, ##_a)
#else
#define mem_sharing_audit() do {} while(0)
#endif /* MEM_SHARING_AUDIT */

#define mem_sharing_enabled(d) \
    (is_hvm_domain(d) && (d)->arch.hvm_domain.mem_sharing_enabled)

#undef mfn_to_page
#define mfn_to_page(_m) __mfn_to_page(mfn_x(_m))
#undef mfn_valid
#define mfn_valid(_mfn) __mfn_valid(mfn_x(_mfn))
#undef page_to_mfn
#define page_to_mfn(_pg) _mfn(__page_to_mfn(_pg))

static shr_handle_t next_handle = 1;
static atomic_t nr_saved_mfns   = ATOMIC_INIT(0); 

typedef struct shr_hash_entry 
{
    shr_handle_t handle;
    mfn_t mfn; 
    struct shr_hash_entry *next;
    struct list_head gfns;
} shr_hash_entry_t;

#define SHR_HASH_LENGTH 1000
static shr_hash_entry_t *shr_hash[SHR_HASH_LENGTH];

typedef struct gfn_info
{
    unsigned long gfn;
    domid_t domain; 
    struct list_head list;
} gfn_info_t;

static mm_lock_t shr_lock;

/* Returns true if list has only one entry. O(1) complexity. */
static inline int list_has_one_entry(struct list_head *head)
{
    return (head->next != head) && (head->next->next == head);
}

static inline gfn_info_t *gfn_get_info(struct list_head *list)
{
    return list_entry(list->next, gfn_info_t, list);
}

static void __init mem_sharing_hash_init(void)
{
    int i;

    mm_lock_init(&shr_lock);
    for(i=0; i<SHR_HASH_LENGTH; i++)
        shr_hash[i] = NULL;
}

static shr_hash_entry_t *mem_sharing_hash_alloc(void)
{
    return xmalloc(shr_hash_entry_t); 
}

static void mem_sharing_hash_destroy(shr_hash_entry_t *e)
{
    xfree(e);
}

static gfn_info_t *mem_sharing_gfn_alloc(void)
{
    return xmalloc(gfn_info_t); 
}

static void mem_sharing_gfn_destroy(gfn_info_t *gfn, int was_shared)
{
    /* Decrement the number of pages, if the gfn was shared before */
    if ( was_shared )
    {
        struct domain *d = get_domain_by_id(gfn->domain);
        /* Domain may have been destroyed by now *
         * (if we are called from p2m_teardown)  */
        if ( d )
        {
            atomic_dec(&d->shr_pages);
            put_domain(d);
        }
    }
    xfree(gfn);
}

static shr_hash_entry_t* mem_sharing_hash_lookup(shr_handle_t handle)
{
    shr_hash_entry_t *e;
    
    e = shr_hash[handle % SHR_HASH_LENGTH]; 
    while(e != NULL)
    {
        if(e->handle == handle)
            return e;
        e = e->next;
    }

    return NULL;
}

static shr_hash_entry_t* mem_sharing_hash_insert(shr_handle_t handle, mfn_t mfn)
{
    shr_hash_entry_t *e, **ee;
    
    e = mem_sharing_hash_alloc();
    if(e == NULL) return NULL;
    e->handle = handle;
    e->mfn = mfn;
    ee = &shr_hash[handle % SHR_HASH_LENGTH]; 
    e->next = *ee;
    *ee = e;
    return e;
}

static void mem_sharing_hash_delete(shr_handle_t handle)
{
    shr_hash_entry_t **pprev, *e;  

    pprev = &shr_hash[handle % SHR_HASH_LENGTH];
    e = *pprev;
    while(e != NULL)
    {
        if(e->handle == handle)
        {
            *pprev = e->next;
            mem_sharing_hash_destroy(e);
            return;
        }
        pprev = &e->next;
        e = e->next;
    }
    printk("Could not find shr entry for handle %"PRIx64"\n", handle);
    BUG();
} 

#if MEM_SHARING_AUDIT
static void mem_sharing_audit(void)
{
    shr_hash_entry_t *e;
    struct list_head *le;
    gfn_info_t *g;
    int bucket;
    struct page_info *pg;

    ASSERT(shr_locked_by_me());

    for(bucket=0; bucket < SHR_HASH_LENGTH; bucket++)
    {
        e = shr_hash[bucket];    
        /* Loop over all shr_hash_entries */ 
        while(e != NULL)
        {
            int nr_gfns=0;

            /* Check if the MFN has correct type, owner and handle */ 
            pg = mfn_to_page(e->mfn);
            if((pg->u.inuse.type_info & PGT_type_mask) != PGT_shared_page)
                MEM_SHARING_DEBUG("mfn %lx not shared, but in the hash!\n",
                                   mfn_x(e->mfn));
            if(page_get_owner(pg) != dom_cow)
                MEM_SHARING_DEBUG("mfn %lx shared, but wrong owner (%d)!\n",
                                   mfn_x(e->mfn), 
                                   page_get_owner(pg)->domain_id);
            if(e->handle != pg->shr_handle)
                MEM_SHARING_DEBUG("mfn %lx shared, but wrong handle "
                                  "(%ld != %ld)!\n",
                                   mfn_x(e->mfn), pg->shr_handle, e->handle);
            /* Check if all GFNs map to the MFN, and the p2m types */
            list_for_each(le, &e->gfns)
            {
                struct domain *d;
                p2m_type_t t;
                mfn_t mfn;

                g = list_entry(le, struct gfn_info, list);
                d = get_domain_by_id(g->domain);
                if(d == NULL)
                {
                    MEM_SHARING_DEBUG("Unknow dom: %d, for PFN=%lx, MFN=%lx\n",
                            g->domain, g->gfn, mfn_x(e->mfn));
                    continue;
                }
                mfn = get_gfn_unlocked(d, g->gfn, &t); 
                if(mfn_x(mfn) != mfn_x(e->mfn))
                    MEM_SHARING_DEBUG("Incorrect P2M for d=%d, PFN=%lx."
                                      "Expecting MFN=%ld, got %ld\n",
                                      g->domain, g->gfn, mfn_x(e->mfn),
                                      mfn_x(mfn));
                if(t != p2m_ram_shared)
                    MEM_SHARING_DEBUG("Incorrect P2M type for d=%d, PFN=%lx."
                                      "Expecting t=%d, got %d\n",
                                      g->domain, g->gfn, mfn_x(e->mfn),
                                      p2m_ram_shared, t);
                put_domain(d);
                nr_gfns++;
            } 
            if(nr_gfns != (pg->u.inuse.type_info & PGT_count_mask))
                MEM_SHARING_DEBUG("Mismatched counts for MFN=%lx."
                                  "nr_gfns in hash %d, in type_info %d\n",
                                  mfn_x(e->mfn), nr_gfns, 
                                 (pg->u.inuse.type_info & PGT_count_mask));
            e = e->next;
        }
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

/* Account for a GFN being shared/unshared.
 * When sharing this function needs to be called _before_ gfn lists are merged
 * together, but _after_ gfn is removed from the list when unsharing.
 */
static int mem_sharing_gfn_account(struct gfn_info *gfn, int sharing)
{
    struct domain *d;

    /* A) When sharing:
     * if the gfn being shared is in > 1 long list, its already been 
     * accounted for
     * B) When unsharing:
     * if the list is longer than > 1, we don't have to account yet. 
     */
    if(list_has_one_entry(&gfn->list))
    {
        d = get_domain_by_id(gfn->domain);
        BUG_ON(!d);
        if(sharing) 
            atomic_inc(&d->shr_pages);
        else
            atomic_dec(&d->shr_pages);
        put_domain(d);

        return 1;
    }
    mem_sharing_audit();

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

int mem_sharing_nominate_page(struct domain *d,
                              unsigned long gfn,
                              int expected_refcnt,
                              shr_handle_t *phandle)
{
    p2m_type_t p2mt;
    mfn_t mfn;
    struct page_info *page;
    int ret;
    shr_handle_t handle;
    shr_hash_entry_t *hash_entry;
    struct gfn_info *gfn_info;

    *phandle = 0UL;

    shr_lock(); 
    mfn = get_gfn(d, gfn, &p2mt);

    /* Check if mfn is valid */
    ret = -EINVAL;
    if ( !mfn_valid(mfn) )
        goto out;

    /* Return the handle if the page is already shared */
    page = mfn_to_page(mfn);
    if ( p2m_is_shared(p2mt) ) {
        *phandle = page->shr_handle;
        ret = 0;
        goto out;
    }

    /* Check p2m type */
    if ( !p2m_is_sharable(p2mt) )
        goto out;

    /* Try to convert the mfn to the sharable type */
    ret = page_make_sharable(d, page, expected_refcnt); 
    if ( ret ) 
        goto out;

    /* Create the handle */
    ret = -ENOMEM;
    handle = next_handle++;  
    if((hash_entry = mem_sharing_hash_insert(handle, mfn)) == NULL)
    {
        goto out;
    }
    if((gfn_info = mem_sharing_gfn_alloc()) == NULL)
    {
        mem_sharing_hash_destroy(hash_entry);
        goto out;
    }

    /* Change the p2m type */
    if ( p2m_change_type(d, gfn, p2mt, p2m_ram_shared) != p2mt ) 
    {
        /* This is unlikely, as the type must have changed since we've checked
         * it a few lines above.
         * The mfn needs to revert back to rw type. This should never fail,
         * since no-one knew that the mfn was temporarily sharable */
        BUG_ON(page_make_private(d, page) != 0);
        mem_sharing_hash_destroy(hash_entry);
        mem_sharing_gfn_destroy(gfn_info, 0);
        goto out;
    }

    /* Update m2p entry to SHARED_M2P_ENTRY */
    set_gpfn_from_mfn(mfn_x(mfn), SHARED_M2P_ENTRY);

    INIT_LIST_HEAD(&hash_entry->gfns);
    INIT_LIST_HEAD(&gfn_info->list);
    list_add(&gfn_info->list, &hash_entry->gfns);
    gfn_info->gfn = gfn;
    gfn_info->domain = d->domain_id;
    page->shr_handle = handle;
    *phandle = handle;

    ret = 0;

out:
    put_gfn(d, gfn);
    shr_unlock();
    return ret;
}

int mem_sharing_share_pages(shr_handle_t sh, shr_handle_t ch) 
{
    shr_hash_entry_t *se, *ce;
    struct page_info *spage, *cpage;
    struct list_head *le, *te;
    struct gfn_info *gfn;
    struct domain *d;
    int ret;

    shr_lock();

    ret = XEN_DOMCTL_MEM_SHARING_S_HANDLE_INVALID;
    se = mem_sharing_hash_lookup(sh);
    if(se == NULL) goto err_out;
    ret = XEN_DOMCTL_MEM_SHARING_C_HANDLE_INVALID;
    ce = mem_sharing_hash_lookup(ch);
    if(ce == NULL) goto err_out;
    spage = mfn_to_page(se->mfn); 
    cpage = mfn_to_page(ce->mfn); 
    /* gfn lists always have at least one entry => save to call list_entry */
    mem_sharing_gfn_account(gfn_get_info(&ce->gfns), 1);
    mem_sharing_gfn_account(gfn_get_info(&se->gfns), 1);
    list_for_each_safe(le, te, &ce->gfns)
    {
        gfn = list_entry(le, struct gfn_info, list);
        /* Get the source page and type, this should never fail 
         * because we are under shr lock, and got non-null se */
        BUG_ON(!get_page_and_type(spage, dom_cow, PGT_shared_page));
        /* Move the gfn_info from ce list to se list */
        list_del(&gfn->list);
        d = get_domain_by_id(gfn->domain);
        BUG_ON(!d);
        BUG_ON(set_shared_p2m_entry(d, gfn->gfn, se->mfn) == 0);
        put_domain(d);
        list_add(&gfn->list, &se->gfns);
        put_page_and_type(cpage);
    } 
    ASSERT(list_empty(&ce->gfns));
    mem_sharing_hash_delete(ch);
    atomic_inc(&nr_saved_mfns);
    /* Free the client page */
    if(test_and_clear_bit(_PGC_allocated, &cpage->count_info))
        put_page(cpage);
    ret = 0;
    
err_out:
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
    int ret, last_gfn;
    shr_hash_entry_t *hash_entry;
    struct gfn_info *gfn_info = NULL;
    shr_handle_t handle;
    struct list_head *le;

    /* Remove the gfn_info from the list */
   
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

    page = mfn_to_page(mfn);
    handle = page->shr_handle;
 
    hash_entry = mem_sharing_hash_lookup(handle); 
    list_for_each(le, &hash_entry->gfns)
    {
        gfn_info = list_entry(le, struct gfn_info, list);
        if ( (gfn_info->gfn == gfn) && (gfn_info->domain == d->domain_id) )
            goto gfn_found;
    }
    gdprintk(XENLOG_ERR, "Could not find gfn_info for shared gfn: "
                            "%lx\n", gfn);
    BUG();
gfn_found: 
    /* Delete gfn_info from the list, but hold on to it, until we've allocated
     * memory to make a copy */
    list_del(&gfn_info->list);
    last_gfn = list_empty(&hash_entry->gfns);

    /* If the GFN is getting destroyed drop the references to MFN 
     * (possibly freeing the page), and exit early */
    if ( flags & MEM_SHARING_DESTROY_GFN )
    {
        mem_sharing_gfn_destroy(gfn_info, !last_gfn);
        if(last_gfn) 
            mem_sharing_hash_delete(handle);
        else 
            /* Even though we don't allocate a private page, we have to account
             * for the MFN that originally backed this PFN. */
            atomic_dec(&nr_saved_mfns);
        put_gfn(d, gfn);
        shr_unlock();
        put_page_and_type(page);
        if(last_gfn && 
           test_and_clear_bit(_PGC_allocated, &page->count_info)) 
            put_page(page);
        return 0;
    }
 
    ret = page_make_private(d, page);
    BUG_ON(last_gfn & ret);
    if(ret == 0) goto private_page_found;
        
    old_page = page;
    page = alloc_domheap_page(d, 0);
    if(!page) 
    {
        /* We've failed to obtain memory for private page. Need to re-add the
         * gfn_info to relevant list */
        list_add(&gfn_info->list, &hash_entry->gfns);
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

    /* NOTE: set_shared_p2m_entry will switch the underlying mfn. If
     * we do get_page withing get_gfn, the correct sequence here
     * should be
       get_page(page);
       put_page(old_page);
     * so that the ref to the old page is dropped, and a ref to
     * the new page is obtained to later be dropped in put_gfn */
    BUG_ON(set_shared_p2m_entry(d, gfn, page_to_mfn(page)) == 0);
    put_page_and_type(old_page);

private_page_found:    
    /* We've got a private page, we can commit the gfn destruction */
    mem_sharing_gfn_destroy(gfn_info, !last_gfn);
    if(last_gfn) 
        mem_sharing_hash_delete(handle);
    else
        atomic_dec(&nr_saved_mfns);

    if ( p2m_change_type(d, gfn, p2m_ram_shared, p2m_ram_rw) != 
                                                p2m_ram_shared ) 
    {
        printk("Could not change p2m type.\n");
        BUG();
    }
    /* Update m2p entry */
    set_gpfn_from_mfn(mfn_x(page_to_mfn(page)), gfn);

    /* Now that the gfn<->mfn map is properly established,
     * marking dirty is feasible */
    paging_mark_dirty(d, mfn_x(page_to_mfn(page)));
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
            shr_handle_t sh = mec->u.share.source_handle;
            shr_handle_t ch = mec->u.share.client_handle;
            rc = mem_sharing_share_pages(sh, ch); 
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
    mem_sharing_hash_init();
}

