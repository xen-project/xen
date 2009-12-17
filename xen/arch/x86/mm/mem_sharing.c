/******************************************************************************
 * arch/x86/mm/mem_sharing.c
 *
 * Memory sharing support.
 *
 * Copyright (c) 2009 Citrix (R&D) Ltd. (Grzegorz Milos)
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

#include <asm/page.h>
#include <asm/string.h>
#include <asm/p2m.h>
#include <asm/mem_event.h>
#include <xen/domain_page.h>
#include <xen/types.h>
#include <xen/spinlock.h>
#include <xen/mm.h>
#include <xen/sched.h>
 
#undef mfn_to_page
#define mfn_to_page(_m) __mfn_to_page(mfn_x(_m))
#undef mfn_valid
#define mfn_valid(_mfn) __mfn_valid(mfn_x(_mfn))
#undef page_to_mfn
#define page_to_mfn(_pg) _mfn(__page_to_mfn(_pg))

static shr_handle_t next_handle = 1;

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

typedef struct shr_lock
{
    spinlock_t  lock;            /* mem sharing lock */
    int         locker;          /* processor which holds the lock */
    const char *locker_function; /* func that took it */
} shr_lock_t;
static shr_lock_t shr_lock;

#define shr_lock_init(_i)                      \
    do {                                       \
        spin_lock_init(&shr_lock.lock);        \
        shr_lock.locker = -1;                  \
        shr_lock.locker_function = "nobody";   \
    } while (0)

#define shr_locked_by_me(_i)                   \
    (current->processor == shr_lock.locker)

#define shr_lock(_i)                                           \
    do {                                                       \
        if ( unlikely(shr_lock.locker == current->processor) ) \
        {                                                      \
            printk("Error: shr lock held by %s\n",             \
                   shr_lock.locker_function);                  \
            BUG();                                             \
        }                                                      \
        spin_lock(&shr_lock.lock);                             \
        ASSERT(shr_lock.locker == -1);                         \
        shr_lock.locker = current->processor;                  \
        shr_lock.locker_function = __func__;                   \
    } while (0)

#define shr_unlock(_i)                                    \
    do {                                                  \
        ASSERT(shr_lock.locker == current->processor);    \
        shr_lock.locker = -1;                             \
        shr_lock.locker_function = "nobody";              \
        spin_unlock(&shr_lock.lock);                      \
    } while (0)



static void mem_sharing_hash_init(void)
{
    int i;

    shr_lock_init();
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

static void mem_sharing_gfn_destroy(gfn_info_t *gfn_info)
{
    xfree(gfn_info);
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
    printk("Could not find shr entry for handle %lx\n", handle);
    BUG();
} 


static struct page_info* mem_sharing_alloc_page(struct domain *d, 
                                                unsigned long gfn,
                                                int must_succeed)
{
    struct page_info* page;
    struct vcpu *v = current;
    mem_event_request_t req;

    page = alloc_domheap_page(d, 0); 
    if(page != NULL) return page;

    memset(&req, 0, sizeof(req));
    if(must_succeed) 
    {
        /* We do not support 'must_succeed' any more. External operations such
         * as grant table mappings may fail with OOM condition! 
         */
        BUG();
    }
    else
    {
        /* All foreign attempts to unshare pages should be handled through
         * 'must_succeed' case. */
        ASSERT(v->domain->domain_id == d->domain_id);
        vcpu_pause_nosync(v);
        req.flags |= MEM_EVENT_FLAG_VCPU_PAUSED;
    }
        
    /* XXX: Need to reserve a request, not just check the ring! */
    if(mem_event_check_ring(d)) return page;

    req.flags |= MEM_EVENT_FLAG_OUT_OF_MEM;
    req.gfn = gfn;
    req.p2mt = p2m_ram_shared;
    req.vcpu_id = v->vcpu_id;
    mem_event_put_request(d, &req);

    return page;
}

int mem_sharing_sharing_resume(struct domain *d)
{
    mem_event_response_t rsp;

    /* Get request off the ring */
    mem_event_get_response(d, &rsp);

    /* Unpause domain/vcpu */
    if( rsp.flags & MEM_EVENT_FLAG_VCPU_PAUSED )
        vcpu_unpause(d->vcpu[rsp.vcpu_id]);
    if( rsp.flags & MEM_EVENT_FLAG_DOM_PAUSED )
        domain_unpause(d);

    return 0;
}

int mem_sharing_debug_mfn(unsigned long mfn)
{
    struct page_info *page;

    if(!mfn_valid(_mfn(mfn)))
    {
        printk("Invalid MFN=%lx\n", mfn);
        return -1;
    }
    page = mfn_to_page(_mfn(mfn));

    printk("Debug page: MFN=%lx is ci=%lx, ti=%lx, owner_id=%d\n",
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
    struct page_info *page;

    mfn = gfn_to_mfn(d, gfn, &p2mt);
    page = mfn_to_page(mfn);

    printk("Debug for domain=%d, gfn=%lx, ", 
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
    ASSERT(t->gt_version != 0);
    if (t->gt_version == 1)
        return (grant_entry_header_t*)&shared_entry_v1(t, ref);
    else
        return &shared_entry_v2(t, ref).hdr;
}

int mem_sharing_debug_gref(struct domain *d, grant_ref_t ref)
{
    grant_entry_header_t *shah;
    uint16_t status;
    unsigned long gfn;

    if(d->grant_table->gt_version < 1)
    {
        printk("Asked to debug [dom=%d,gref=%d], but not yet inited.\n",
                d->domain_id, ref);
        return -1;
    }
    shah = shared_entry_header(d->grant_table, ref);
    if (d->grant_table->gt_version == 1) 
    {
        grant_entry_v1_t *sha1;
        sha1 = &shared_entry_v1(d->grant_table, ref);
        status = shah->flags;
        gfn = sha1->frame;
    } 
    else 
    {
        grant_entry_v2_t *sha2;
        sha2 = &shared_entry_v2(d->grant_table, ref);
        status = status_entry(d->grant_table, ref);
        gfn = sha2->full_page.frame;
    }
    
    printk("==> Grant [dom=%d,ref=%d], status=%x. ", 
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

    mfn = gfn_to_mfn(d, gfn, &p2mt);

    /* Check if mfn is valid */
    ret = -EINVAL;
    if (!mfn_valid(mfn))
        goto out;

    /* Check p2m type */
    if (!p2m_is_sharable(p2mt))
        goto out;

    /* Try to convert the mfn to the sharable type */
    page = mfn_to_page(mfn);
    ret = page_make_sharable(d, page, expected_refcnt); 
    if(ret) 
        goto out;

    /* Create the handle */
    ret = -ENOMEM;
    shr_lock(); 
    handle = next_handle++;  
    if((hash_entry = mem_sharing_hash_insert(handle, mfn)) == NULL)
    {
        shr_unlock();
        goto out;
    }
    if((gfn_info = mem_sharing_gfn_alloc()) == NULL)
    {
        mem_sharing_hash_destroy(hash_entry);
        shr_unlock();
        goto out;
    }

    /* Change the p2m type */
    if(p2m_change_type(d, gfn, p2mt, p2m_ram_shared) != p2mt) 
    {
        /* This is unlikely, as the type must have changed since we've checked
         * it a few lines above.
         * The mfn needs to revert back to rw type. This should never fail,
         * since no-one knew that the mfn was temporarily sharable */
        ASSERT(page_make_private(d, page) == 0);
        mem_sharing_hash_destroy(hash_entry);
        mem_sharing_gfn_destroy(gfn_info);
        shr_unlock();
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
    shr_unlock();

    ret = 0;

out:
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

    ret = -1;
    se = mem_sharing_hash_lookup(sh);
    if(se == NULL) goto err_out;
    ret = -2;
    ce = mem_sharing_hash_lookup(ch);
    if(ce == NULL) goto err_out;
    spage = mfn_to_page(se->mfn); 
    cpage = mfn_to_page(ce->mfn); 
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

    mfn = gfn_to_mfn(d, gfn, &p2mt);

    page = mfn_to_page(mfn);
    handle = page->shr_handle;
 
    /* Remove the gfn_info from the list */
    shr_lock();
    hash_entry = mem_sharing_hash_lookup(handle); 
    list_for_each(le, &hash_entry->gfns)
    {
        gfn_info = list_entry(le, struct gfn_info, list);
        if((gfn_info->gfn == gfn) && (gfn_info->domain == d->domain_id))
            goto gfn_found;
    }
    printk("Could not find gfn_info for shared gfn: %lx\n", gfn);
    BUG();
gfn_found: 
    /* Delete gfn_info from the list, but hold on to it, until we've allocated
     * memory to make a copy */
    list_del(&gfn_info->list);
    last_gfn = list_empty(&hash_entry->gfns);

    /* If the GFN is getting destroyed drop the references to MFN 
     * (possibly freeing the page), and exit early */
    if(flags & MEM_SHARING_DESTROY_GFN)
    {
        mem_sharing_gfn_destroy(gfn_info);
        if(last_gfn) mem_sharing_hash_delete(handle);
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
    page = mem_sharing_alloc_page(d, gfn, flags & MEM_SHARING_MUST_SUCCEED);
    BUG_ON(!page && (flags & MEM_SHARING_MUST_SUCCEED));
    if(!page) 
    {
        /* We've failed to obtain memory for private page. Need to re-add the
         * gfn_info to relevant list */
        list_add(&gfn_info->list, &hash_entry->gfns);
        shr_unlock();
        return -ENOMEM;
    }

    s = map_domain_page(__page_to_mfn(old_page));
    t = map_domain_page(__page_to_mfn(page));
    memcpy(t, s, PAGE_SIZE);
    unmap_domain_page(s);
    unmap_domain_page(t);

    ASSERT(set_shared_p2m_entry(d, gfn, page_to_mfn(page)) != 0);
    put_page_and_type(old_page);

private_page_found:    
    /* We've got a private page, we can commit the gfn destruction */
    mem_sharing_gfn_destroy(gfn_info);
    if(last_gfn) mem_sharing_hash_delete(handle);
    shr_unlock();

    if(p2m_change_type(d, gfn, p2m_ram_shared, p2m_ram_rw) != 
                                                p2m_ram_shared) 
    {
        printk("Could not change p2m type.\n");
        BUG();
    }
    /* Update m2p entry */
    set_gpfn_from_mfn(mfn_x(page_to_mfn(page)), gfn);

    return 0;
}

void mem_sharing_init(void)
{
    printk("Initing memory sharing.\n");
    mem_sharing_hash_init();
}

