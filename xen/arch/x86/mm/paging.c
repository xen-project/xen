/******************************************************************************
 * arch/x86/paging.c
 *
 * x86 specific paging support
 * Copyright (c) 2007 Advanced Micro Devices (Wei Huang)
 * Copyright (c) 2007 XenSource Inc.
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

#include <xen/init.h>
#include <asm/paging.h>
#include <asm/shadow.h>
#include <asm/p2m.h>
#include <asm/hap.h>
#include <asm/guest_access.h>
#include <xsm/xsm.h>

#define hap_enabled(d) (hvm_funcs.hap_supported && is_hvm_domain(d))

/* Printouts */
#define PAGING_PRINTK(_f, _a...)                                     \
    debugtrace_printk("pg: %s(): " _f, __func__, ##_a)
#define PAGING_ERROR(_f, _a...)                                      \
    printk("pg error: %s(): " _f, __func__, ##_a)
#define PAGING_DEBUG(flag, _f, _a...)                                \
    do {                                                             \
        if (PAGING_DEBUG_ ## flag)                                   \
            debugtrace_printk("pgdebug: %s(): " _f, __func__, ##_a); \
    } while (0)

/************************************************/
/*              LOG DIRTY SUPPORT               */
/************************************************/
/* Override macros from asm/page.h to make them work with mfn_t */
#undef mfn_to_page
#define mfn_to_page(_m) (frame_table + mfn_x(_m))
#undef mfn_valid
#define mfn_valid(_mfn) (mfn_x(_mfn) < max_page)
#undef page_to_mfn
#define page_to_mfn(_pg) (_mfn((_pg) - frame_table))

/* The log-dirty lock.  This protects the log-dirty bitmap from
 * concurrent accesses (and teardowns, etc).
 *
 * Locking discipline: always acquire shadow or HAP lock before this one.
 *
 * Because mark_dirty is called from a lot of places, the log-dirty lock
 * may be acquired with the shadow or HAP locks already held.  When the
 * log-dirty code makes callbacks into HAP or shadow code to reset
 * various traps that will trigger the mark_dirty calls, it must *not*
 * have the log-dirty lock held, or it risks deadlock.  Because the only
 * purpose of those calls is to make sure that *guest* actions will
 * cause mark_dirty to be called (hypervisor actions explictly call it
 * anyway), it is safe to release the log-dirty lock before the callback
 * as long as the domain is paused for the entire operation. */

#define log_dirty_lock_init(_d)                                   \
    do {                                                          \
        spin_lock_init(&(_d)->arch.paging.log_dirty.lock);        \
        (_d)->arch.paging.log_dirty.locker = -1;                  \
        (_d)->arch.paging.log_dirty.locker_function = "nobody";   \
    } while (0)

#define log_dirty_lock(_d)                                                   \
    do {                                                                     \
        if (unlikely((_d)->arch.paging.log_dirty.locker==current->processor))\
        {                                                                    \
            printk("Error: paging log dirty lock held by %s\n",              \
                   (_d)->arch.paging.log_dirty.locker_function);             \
            BUG();                                                           \
        }                                                                    \
        spin_lock(&(_d)->arch.paging.log_dirty.lock);                        \
        ASSERT((_d)->arch.paging.log_dirty.locker == -1);                    \
        (_d)->arch.paging.log_dirty.locker = current->processor;             \
        (_d)->arch.paging.log_dirty.locker_function = __func__;              \
    } while (0)

#define log_dirty_unlock(_d)                                              \
    do {                                                                  \
        ASSERT((_d)->arch.paging.log_dirty.locker == current->processor); \
        (_d)->arch.paging.log_dirty.locker = -1;                          \
        (_d)->arch.paging.log_dirty.locker_function = "nobody";           \
        spin_unlock(&(_d)->arch.paging.log_dirty.lock);                   \
    } while (0)

static mfn_t paging_new_log_dirty_page(struct domain *d, void **mapping_p)
{
    mfn_t mfn;
    struct page_info *page = alloc_domheap_page(NULL);

    if ( unlikely(page == NULL) )
    {
        d->arch.paging.log_dirty.failed_allocs++;
        return _mfn(INVALID_MFN);
    }

    d->arch.paging.log_dirty.allocs++;
    mfn = page_to_mfn(page);
    *mapping_p = map_domain_page(mfn_x(mfn));

    return mfn;
}

static mfn_t paging_new_log_dirty_leaf(struct domain *d, uint8_t **leaf_p)
{
    mfn_t mfn = paging_new_log_dirty_page(d, (void **)leaf_p);
    if ( mfn_valid(mfn) )
        clear_page(*leaf_p);
    return mfn;
}

static mfn_t paging_new_log_dirty_node(struct domain *d, mfn_t **node_p)
{
    int i;
    mfn_t mfn = paging_new_log_dirty_page(d, (void **)node_p);
    if ( mfn_valid(mfn) )
        for ( i = 0; i < LOGDIRTY_NODE_ENTRIES; i++ )
            (*node_p)[i] = _mfn(INVALID_MFN);
    return mfn;
}

int paging_alloc_log_dirty_bitmap(struct domain *d)
{
    mfn_t *mapping;

    if ( mfn_valid(d->arch.paging.log_dirty.top) )
        return 0;

    d->arch.paging.log_dirty.top = paging_new_log_dirty_node(d, &mapping);
    if ( unlikely(!mfn_valid(d->arch.paging.log_dirty.top)) )
    {
        /* Clear error indicator since we're reporting this one */
        d->arch.paging.log_dirty.failed_allocs = 0;
        return -ENOMEM;
    }
    unmap_domain_page(mapping);

    return 0;
}

static void paging_free_log_dirty_page(struct domain *d, mfn_t mfn)
{
    d->arch.paging.log_dirty.allocs--;
    free_domheap_page(mfn_to_page(mfn));
}    

void paging_free_log_dirty_bitmap(struct domain *d)
{
    mfn_t *l4, *l3, *l2;
    int i4, i3, i2;

    if ( !mfn_valid(d->arch.paging.log_dirty.top) )
        return;

    dprintk(XENLOG_DEBUG, "%s: used %d pages for domain %d dirty logging\n",
            __FUNCTION__, d->arch.paging.log_dirty.allocs, d->domain_id);

    l4 = map_domain_page(mfn_x(d->arch.paging.log_dirty.top));

    for ( i4 = 0; i4 < LOGDIRTY_NODE_ENTRIES; i4++ )
    {
        if ( !mfn_valid(l4[i4]) )
            continue;

        l3 = map_domain_page(mfn_x(l4[i4]));

        for ( i3 = 0; i3 < LOGDIRTY_NODE_ENTRIES; i3++ )
        {
            if ( !mfn_valid(l3[i3]) )
                continue;

            l2 = map_domain_page(mfn_x(l3[i3]));

            for ( i2 = 0; i2 < LOGDIRTY_NODE_ENTRIES; i2++ )
                if ( mfn_valid(l2[i2]) )
                    paging_free_log_dirty_page(d, l2[i2]);

            unmap_domain_page(l2);
            paging_free_log_dirty_page(d, l3[i3]);
        }

        unmap_domain_page(l3);
        paging_free_log_dirty_page(d, l4[i4]);
    }

    unmap_domain_page(l4);
    paging_free_log_dirty_page(d, d->arch.paging.log_dirty.top);

    d->arch.paging.log_dirty.top = _mfn(INVALID_MFN);
    ASSERT(d->arch.paging.log_dirty.allocs == 0);
    d->arch.paging.log_dirty.failed_allocs = 0;
}

int paging_log_dirty_enable(struct domain *d)
{
    int ret;

    domain_pause(d);
    log_dirty_lock(d);

    if ( paging_mode_log_dirty(d) )
    {
        ret = -EINVAL;
        goto out;
    }

    ret = paging_alloc_log_dirty_bitmap(d);
    if ( ret != 0 )
    {
        paging_free_log_dirty_bitmap(d);
        goto out;
    }

    log_dirty_unlock(d);

    /* Safe because the domain is paused. */
    ret = d->arch.paging.log_dirty.enable_log_dirty(d);

    /* Possibility of leaving the bitmap allocated here but it'll be
     * tidied on domain teardown. */

    domain_unpause(d);
    return ret;

 out:
    log_dirty_unlock(d);
    domain_unpause(d);
    return ret;
}

int paging_log_dirty_disable(struct domain *d)
{
    int ret;

    domain_pause(d);
    /* Safe because the domain is paused. */
    ret = d->arch.paging.log_dirty.disable_log_dirty(d);
    log_dirty_lock(d);
    if ( !paging_mode_log_dirty(d) )
        paging_free_log_dirty_bitmap(d);
    log_dirty_unlock(d);
    domain_unpause(d);

    return ret;
}

/* Mark a page as dirty */
void paging_mark_dirty(struct domain *d, unsigned long guest_mfn)
{
    unsigned long pfn;
    mfn_t gmfn;
    int changed;
    mfn_t mfn, *l4, *l3, *l2;
    uint8_t *l1;
    int i1, i2, i3, i4;

    gmfn = _mfn(guest_mfn);

    if ( !paging_mode_log_dirty(d) || !mfn_valid(gmfn) )
        return;

    log_dirty_lock(d);

    ASSERT(mfn_valid(d->arch.paging.log_dirty.top));

    /* We /really/ mean PFN here, even for non-translated guests. */
    pfn = get_gpfn_from_mfn(mfn_x(gmfn));

    /*
     * Values with the MSB set denote MFNs that aren't really part of the
     * domain's pseudo-physical memory map (e.g., the shared info frame).
     * Nothing to do here...
     */
    if ( unlikely(!VALID_M2P(pfn)) )
        goto out;

    i1 = L1_LOGDIRTY_IDX(pfn);
    i2 = L2_LOGDIRTY_IDX(pfn);
    i3 = L3_LOGDIRTY_IDX(pfn);
    i4 = L4_LOGDIRTY_IDX(pfn);

    l4 = map_domain_page(mfn_x(d->arch.paging.log_dirty.top));
    mfn = l4[i4];
    if ( !mfn_valid(mfn) )
        mfn = l4[i4] = paging_new_log_dirty_node(d, &l3);
    else
        l3 = map_domain_page(mfn_x(mfn));
    unmap_domain_page(l4);
    if ( unlikely(!mfn_valid(mfn)) )
        goto out;

    mfn = l3[i3];
    if ( !mfn_valid(mfn) )
        mfn = l3[i3] = paging_new_log_dirty_node(d, &l2);
    else
        l2 = map_domain_page(mfn_x(mfn));
    unmap_domain_page(l3);
    if ( unlikely(!mfn_valid(mfn)) )
        goto out;

    mfn = l2[i2];
    if ( !mfn_valid(mfn) )
        mfn = l2[i2] = paging_new_log_dirty_leaf(d, &l1);
    else
        l1 = map_domain_page(mfn_x(mfn));
    unmap_domain_page(l2);
    if ( unlikely(!mfn_valid(mfn)) )
        goto out;

    changed = !__test_and_set_bit(i1, l1);
    unmap_domain_page(l1);
    if ( changed )
    {
        PAGING_DEBUG(LOGDIRTY, 
                     "marked mfn %" PRI_mfn " (pfn=%lx), dom %d\n",
                     mfn_x(gmfn), pfn, d->domain_id);
        d->arch.paging.log_dirty.dirty_count++;
    }

 out:
    log_dirty_unlock(d);
}

/* Read a domain's log-dirty bitmap and stats.  If the operation is a CLEAN,
 * clear the bitmap and stats as well. */
int paging_log_dirty_op(struct domain *d, struct xen_domctl_shadow_op *sc)
{
    int rv = 0, clean = 0, peek = 1;
    unsigned long pages = 0;
    mfn_t *l4, *l3, *l2;
    uint8_t *l1;
    int i4, i3, i2;

    domain_pause(d);
    log_dirty_lock(d);

    clean = (sc->op == XEN_DOMCTL_SHADOW_OP_CLEAN);

    PAGING_DEBUG(LOGDIRTY, "log-dirty %s: dom %u faults=%u dirty=%u\n",
                 (clean) ? "clean" : "peek",
                 d->domain_id,
                 d->arch.paging.log_dirty.fault_count,
                 d->arch.paging.log_dirty.dirty_count);

    sc->stats.fault_count = d->arch.paging.log_dirty.fault_count;
    sc->stats.dirty_count = d->arch.paging.log_dirty.dirty_count;

    if ( clean )
    {
        d->arch.paging.log_dirty.fault_count = 0;
        d->arch.paging.log_dirty.dirty_count = 0;
    }

    if ( guest_handle_is_null(sc->dirty_bitmap) )
        /* caller may have wanted just to clean the state or access stats. */
        peek = 0;

    if ( (peek || clean) && !mfn_valid(d->arch.paging.log_dirty.top) )
    {
        rv = -EINVAL; /* perhaps should be ENOMEM? */
        goto out;
    }

    if ( unlikely(d->arch.paging.log_dirty.failed_allocs) ) {
        printk("%s: %d failed page allocs while logging dirty pages\n",
               __FUNCTION__, d->arch.paging.log_dirty.failed_allocs);
        rv = -ENOMEM;
        goto out;
    }

    pages = 0;
    l4 = map_domain_page(mfn_x(d->arch.paging.log_dirty.top));

    for ( i4 = 0;
          (pages < sc->pages) && (i4 < LOGDIRTY_NODE_ENTRIES);
          i4++ )
    {
        l3 = mfn_valid(l4[i4]) ? map_domain_page(mfn_x(l4[i4])) : NULL;
        for ( i3 = 0;
              (pages < sc->pages) && (i3 < LOGDIRTY_NODE_ENTRIES);
              i3++ )
        {
            l2 = ((l3 && mfn_valid(l3[i3])) ?
                  map_domain_page(mfn_x(l3[i3])) : NULL);
            for ( i2 = 0;
                  (pages < sc->pages) && (i2 < LOGDIRTY_NODE_ENTRIES);
                  i2++ )
            {
                static uint8_t zeroes[PAGE_SIZE];
                unsigned int bytes = PAGE_SIZE;
                l1 = ((l2 && mfn_valid(l2[i2])) ?
                      map_domain_page(mfn_x(l2[i2])) : zeroes);
                if ( unlikely(((sc->pages - pages + 7) >> 3) < bytes) )
                    bytes = (unsigned int)((sc->pages - pages + 7) >> 3);
                if ( likely(peek) )
                {
                    if ( copy_to_guest_offset(sc->dirty_bitmap, pages >> 3,
                                              l1, bytes) != 0 )
                    {
                        rv = -EFAULT;
                        goto out;
                    }
                }
                if ( clean && l1 != zeroes )
                    clear_page(l1);
                pages += bytes << 3;
                if ( l1 != zeroes )
                    unmap_domain_page(l1);
            }
            if ( l2 )
                unmap_domain_page(l2);
        }
        if ( l3 )
            unmap_domain_page(l3);
    }
    unmap_domain_page(l4);

    if ( pages < sc->pages )
        sc->pages = pages;

    log_dirty_unlock(d);

    if ( clean )
    {
        /* We need to further call clean_dirty_bitmap() functions of specific
         * paging modes (shadow or hap).  Safe because the domain is paused. */
        d->arch.paging.log_dirty.clean_dirty_bitmap(d);
    }
    domain_unpause(d);
    return rv;

 out:
    log_dirty_unlock(d);
    domain_unpause(d);
    return rv;
}


/* Note that this function takes three function pointers. Callers must supply
 * these functions for log dirty code to call. This function usually is
 * invoked when paging is enabled. Check shadow_enable() and hap_enable() for
 * reference.
 *
 * These function pointers must not be followed with the log-dirty lock held.
 */
void paging_log_dirty_init(struct domain *d,
                           int    (*enable_log_dirty)(struct domain *d),
                           int    (*disable_log_dirty)(struct domain *d),
                           void   (*clean_dirty_bitmap)(struct domain *d))
{
    /* We initialize log dirty lock first */
    log_dirty_lock_init(d);

    d->arch.paging.log_dirty.enable_log_dirty = enable_log_dirty;
    d->arch.paging.log_dirty.disable_log_dirty = disable_log_dirty;
    d->arch.paging.log_dirty.clean_dirty_bitmap = clean_dirty_bitmap;
    d->arch.paging.log_dirty.top = _mfn(INVALID_MFN);
}

/* This function fress log dirty bitmap resources. */
void paging_log_dirty_teardown(struct domain*d)
{
    log_dirty_lock(d);
    paging_free_log_dirty_bitmap(d);
    log_dirty_unlock(d);
}
/************************************************/
/*           CODE FOR PAGING SUPPORT            */
/************************************************/
/* Domain paging struct initialization. */
void paging_domain_init(struct domain *d)
{
    p2m_init(d);

    /* The order of the *_init calls below is important, as the later
     * ones may rewrite some common fields.  Shadow pagetables are the
     * default... */
    shadow_domain_init(d);

    /* ... but we will use hardware assistance if it's available. */
    if ( hap_enabled(d) )
        hap_domain_init(d);
}

/* vcpu paging struct initialization goes here */
void paging_vcpu_init(struct vcpu *v)
{
    if ( hap_enabled(v->domain) )
        hap_vcpu_init(v);
    else
        shadow_vcpu_init(v);
}


int paging_domctl(struct domain *d, xen_domctl_shadow_op_t *sc,
                  XEN_GUEST_HANDLE(void) u_domctl)
{
    int rc;

    if ( unlikely(d == current->domain) )
    {
        gdprintk(XENLOG_INFO, "Tried to do a paging op on itself.\n");
        return -EINVAL;
    }

    if ( unlikely(d->is_dying) )
    {
        gdprintk(XENLOG_INFO, "Ignoring paging op on dying domain %u\n",
                 d->domain_id);
        return 0;
    }

    if ( unlikely(d->vcpu[0] == NULL) )
    {
        PAGING_ERROR("Paging op on a domain (%u) with no vcpus\n",
                     d->domain_id);
        return -EINVAL;
    }

    rc = xsm_shadow_control(d, sc->op);
    if ( rc )
        return rc;

    /* Code to handle log-dirty. Note that some log dirty operations
     * piggy-back on shadow operations. For example, when
     * XEN_DOMCTL_SHADOW_OP_OFF is called, it first checks whether log dirty
     * mode is enabled. If does, we disables log dirty and continues with
     * shadow code. For this reason, we need to further dispatch domctl
     * to next-level paging code (shadow or hap).
     */
    switch ( sc->op )
    {
    case XEN_DOMCTL_SHADOW_OP_ENABLE_LOGDIRTY:
        return paging_log_dirty_enable(d);

    case XEN_DOMCTL_SHADOW_OP_ENABLE:
        if ( sc->mode & XEN_DOMCTL_SHADOW_ENABLE_LOG_DIRTY )
            return paging_log_dirty_enable(d);

    case XEN_DOMCTL_SHADOW_OP_OFF:
        if ( paging_mode_log_dirty(d) )
            if ( (rc = paging_log_dirty_disable(d)) != 0 )
                return rc;

    case XEN_DOMCTL_SHADOW_OP_CLEAN:
    case XEN_DOMCTL_SHADOW_OP_PEEK:
        return paging_log_dirty_op(d, sc);
    }

    /* Here, dispatch domctl to the appropriate paging code */
    if ( hap_enabled(d) )
        return hap_domctl(d, sc, u_domctl);
    else
        return shadow_domctl(d, sc, u_domctl);
}

/* Call when destroying a domain */
void paging_teardown(struct domain *d)
{
    if ( hap_enabled(d) )
        hap_teardown(d);
    else
        shadow_teardown(d);

    /* clean up log dirty resources. */
    paging_log_dirty_teardown(d);
}

/* Call once all of the references to the domain have gone away */
void paging_final_teardown(struct domain *d)
{
    if ( hap_enabled(d) )
        hap_final_teardown(d);
    else
        shadow_final_teardown(d);
}

/* Enable an arbitrary paging-assistance mode.  Call once at domain
 * creation. */
int paging_enable(struct domain *d, u32 mode)
{
    if ( hap_enabled(d) )
        return hap_enable(d, mode | PG_HAP_enable);
    else
        return shadow_enable(d, mode | PG_SH_enable);
}

/* Print paging-assistance info to the console */
void paging_dump_domain_info(struct domain *d)
{
    if ( paging_mode_enabled(d) )
    {
        printk("    paging assistance: ");
        if ( paging_mode_shadow(d) )
            printk("shadow ");
        if ( paging_mode_hap(d) )
            printk("hap ");
        if ( paging_mode_refcounts(d) )
            printk("refcounts ");
        if ( paging_mode_log_dirty(d) )
            printk("log_dirty ");
        if ( paging_mode_translate(d) )
            printk("translate ");
        if ( paging_mode_external(d) )
            printk("external ");
        printk("\n");
    }
}

void paging_dump_vcpu_info(struct vcpu *v)
{
    if ( paging_mode_enabled(v->domain) )
    {
        printk("    paging assistance: ");
        if ( paging_mode_shadow(v->domain) )
        {
            if ( v->arch.paging.mode )
                printk("shadowed %u-on-%u\n",
                       v->arch.paging.mode->guest_levels,
                       v->arch.paging.mode->shadow.shadow_levels);
            else
                printk("not shadowed\n");
        }
        else if ( paging_mode_hap(v->domain) && v->arch.paging.mode )
            printk("hap, %u levels\n",
                   v->arch.paging.mode->guest_levels);
        else
            printk("none\n");
    }
}


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
