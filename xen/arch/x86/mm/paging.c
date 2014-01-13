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
#include <xen/guest_access.h>
#include <asm/paging.h>
#include <asm/shadow.h>
#include <asm/p2m.h>
#include <asm/hap.h>
#include <asm/hvm/nestedhvm.h>
#include <xen/numa.h>
#include <xsm/xsm.h>

#include "mm-locks.h"

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

/* Per-CPU variable for enforcing the lock ordering */
DEFINE_PER_CPU(int, mm_lock_level);

/* Override macros from asm/page.h to make them work with mfn_t */
#undef mfn_to_page
#define mfn_to_page(_m) __mfn_to_page(mfn_x(_m))
#undef mfn_valid
#define mfn_valid(_mfn) __mfn_valid(mfn_x(_mfn))
#undef page_to_mfn
#define page_to_mfn(_pg) _mfn(__page_to_mfn(_pg))

/************************************************/
/*              LOG DIRTY SUPPORT               */
/************************************************/

static mfn_t paging_new_log_dirty_page(struct domain *d)
{
    struct page_info *page;

    page = d->arch.paging.alloc_page(d);
    if ( unlikely(page == NULL) )
    {
        d->arch.paging.log_dirty.failed_allocs++;
        return _mfn(INVALID_MFN);
    }

    d->arch.paging.log_dirty.allocs++;

    return page_to_mfn(page);
}

/* Alloc and init a new leaf node */
static mfn_t paging_new_log_dirty_leaf(struct domain *d)
{
    mfn_t mfn = paging_new_log_dirty_page(d);
    if ( mfn_valid(mfn) )
    {
        void *leaf = map_domain_page(mfn_x(mfn));
        clear_page(leaf);
        unmap_domain_page(leaf);
    }
    return mfn;
}

/* Alloc and init a new non-leaf node */
static mfn_t paging_new_log_dirty_node(struct domain *d)
{
    mfn_t mfn = paging_new_log_dirty_page(d);
    if ( mfn_valid(mfn) )
    {
        int i;
        mfn_t *node = map_domain_page(mfn_x(mfn));
        for ( i = 0; i < LOGDIRTY_NODE_ENTRIES; i++ )
            node[i] = _mfn(INVALID_MFN);
        unmap_domain_page(node);
    }
    return mfn;
}

/* get the top of the log-dirty bitmap trie */
static mfn_t *paging_map_log_dirty_bitmap(struct domain *d)
{
    if ( likely(mfn_valid(d->arch.paging.log_dirty.top)) )
        return map_domain_page(mfn_x(d->arch.paging.log_dirty.top));
    return NULL;
}

static void paging_free_log_dirty_page(struct domain *d, mfn_t mfn)
{
    d->arch.paging.log_dirty.allocs--;
    d->arch.paging.free_page(d, mfn_to_page(mfn));
}

void paging_free_log_dirty_bitmap(struct domain *d)
{
    mfn_t *l4, *l3, *l2;
    int i4, i3, i2;

    if ( !mfn_valid(d->arch.paging.log_dirty.top) )
        return;

    paging_lock(d);

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

    paging_unlock(d);
}

int paging_log_dirty_enable(struct domain *d)
{
    int ret;

    if ( paging_mode_log_dirty(d) )
        return -EINVAL;

    domain_pause(d);
    ret = d->arch.paging.log_dirty.enable_log_dirty(d);
    domain_unpause(d);

    return ret;
}

int paging_log_dirty_disable(struct domain *d)
{
    int ret;

    domain_pause(d);
    /* Safe because the domain is paused. */
    ret = d->arch.paging.log_dirty.disable_log_dirty(d);
    if ( !paging_mode_log_dirty(d) )
        paging_free_log_dirty_bitmap(d);
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
    unsigned long *l1;
    int i1, i2, i3, i4;

    gmfn = _mfn(guest_mfn);

    if ( !paging_mode_log_dirty(d) || !mfn_valid(gmfn) ||
         page_get_owner(mfn_to_page(gmfn)) != d )
        return;

    /* We /really/ mean PFN here, even for non-translated guests. */
    pfn = get_gpfn_from_mfn(mfn_x(gmfn));
    /* Shared MFNs should NEVER be marked dirty */
    BUG_ON(SHARED_M2P(pfn));

    /*
     * Values with the MSB set denote MFNs that aren't really part of the
     * domain's pseudo-physical memory map (e.g., the shared info frame).
     * Nothing to do here...
     */
    if ( unlikely(!VALID_M2P(pfn)) )
        return;

    i1 = L1_LOGDIRTY_IDX(pfn);
    i2 = L2_LOGDIRTY_IDX(pfn);
    i3 = L3_LOGDIRTY_IDX(pfn);
    i4 = L4_LOGDIRTY_IDX(pfn);

    /* Recursive: this is called from inside the shadow code */
    paging_lock_recursive(d);

    if ( unlikely(!mfn_valid(d->arch.paging.log_dirty.top)) ) 
    {
         d->arch.paging.log_dirty.top = paging_new_log_dirty_node(d);
         if ( unlikely(!mfn_valid(d->arch.paging.log_dirty.top)) )
             goto out;
    }

    l4 = paging_map_log_dirty_bitmap(d);
    mfn = l4[i4];
    if ( !mfn_valid(mfn) )
        l4[i4] = mfn = paging_new_log_dirty_node(d);
    unmap_domain_page(l4);
    if ( !mfn_valid(mfn) )
        goto out;

    l3 = map_domain_page(mfn_x(mfn));
    mfn = l3[i3];
    if ( !mfn_valid(mfn) )
        l3[i3] = mfn = paging_new_log_dirty_node(d);
    unmap_domain_page(l3);
    if ( !mfn_valid(mfn) )
        goto out;

    l2 = map_domain_page(mfn_x(mfn));
    mfn = l2[i2];
    if ( !mfn_valid(mfn) )
        l2[i2] = mfn = paging_new_log_dirty_leaf(d);
    unmap_domain_page(l2);
    if ( !mfn_valid(mfn) )
        goto out;

    l1 = map_domain_page(mfn_x(mfn));
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
    /* We've already recorded any failed allocations */
    paging_unlock(d);
    return;
}


/* Is this guest page dirty? */
int paging_mfn_is_dirty(struct domain *d, mfn_t gmfn)
{
    unsigned long pfn;
    mfn_t mfn, *l4, *l3, *l2;
    unsigned long *l1;
    int rv;

    ASSERT(paging_locked_by_me(d));
    ASSERT(paging_mode_log_dirty(d));

    /* We /really/ mean PFN here, even for non-translated guests. */
    pfn = get_gpfn_from_mfn(mfn_x(gmfn));
    /* Shared pages are always read-only; invalid pages can't be dirty. */
    if ( unlikely(SHARED_M2P(pfn) || !VALID_M2P(pfn)) )
        return 0;

    mfn = d->arch.paging.log_dirty.top;
    if ( !mfn_valid(mfn) )
        return 0;

    l4 = map_domain_page(mfn_x(mfn));
    mfn = l4[L4_LOGDIRTY_IDX(pfn)];
    unmap_domain_page(l4);
    if ( !mfn_valid(mfn) )
        return 0;

    l3 = map_domain_page(mfn_x(mfn));
    mfn = l3[L3_LOGDIRTY_IDX(pfn)];
    unmap_domain_page(l3);
    if ( !mfn_valid(mfn) )
        return 0;

    l2 = map_domain_page(mfn_x(mfn));
    mfn = l2[L2_LOGDIRTY_IDX(pfn)];
    unmap_domain_page(l2);
    if ( !mfn_valid(mfn) )
        return 0;

    l1 = map_domain_page(mfn_x(mfn));
    rv = test_bit(L1_LOGDIRTY_IDX(pfn), l1);
    unmap_domain_page(l1);
    return rv;
}


/* Read a domain's log-dirty bitmap and stats.  If the operation is a CLEAN,
 * clear the bitmap and stats as well. */
int paging_log_dirty_op(struct domain *d, struct xen_domctl_shadow_op *sc)
{
    int rv = 0, clean = 0, peek = 1;
    unsigned long pages = 0;
    mfn_t *l4 = NULL, *l3 = NULL, *l2 = NULL;
    unsigned long *l1 = NULL;
    int i4, i3, i2;

    domain_pause(d);
    paging_lock(d);

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

    if ( unlikely(d->arch.paging.log_dirty.failed_allocs) ) {
        printk("%s: %d failed page allocs while logging dirty pages\n",
               __FUNCTION__, d->arch.paging.log_dirty.failed_allocs);
        rv = -ENOMEM;
        goto out;
    }

    pages = 0;
    l4 = paging_map_log_dirty_bitmap(d);

    for ( i4 = 0;
          (pages < sc->pages) && (i4 < LOGDIRTY_NODE_ENTRIES);
          i4++ )
    {
        l3 = (l4 && mfn_valid(l4[i4])) ? map_domain_page(mfn_x(l4[i4])) : NULL;
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
                unsigned int bytes = PAGE_SIZE;
                l1 = ((l2 && mfn_valid(l2[i2])) ?
                      map_domain_page(mfn_x(l2[i2])) : NULL);
                if ( unlikely(((sc->pages - pages + 7) >> 3) < bytes) )
                    bytes = (unsigned int)((sc->pages - pages + 7) >> 3);
                if ( likely(peek) )
                {
                    if ( (l1 ? copy_to_guest_offset(sc->dirty_bitmap,
                                                    pages >> 3, (uint8_t *)l1,
                                                    bytes)
                             : clear_guest_offset(sc->dirty_bitmap,
                                                  pages >> 3, bytes)) != 0 )
                    {
                        rv = -EFAULT;
                        goto out;
                    }
                }
                pages += bytes << 3;
                if ( l1 )
                {
                    if ( clean )
                        clear_page(l1);
                    unmap_domain_page(l1);
                }
            }
            if ( l2 )
                unmap_domain_page(l2);
        }
        if ( l3 )
            unmap_domain_page(l3);
    }
    if ( l4 )
        unmap_domain_page(l4);

    if ( pages < sc->pages )
        sc->pages = pages;

    paging_unlock(d);

    if ( clean )
    {
        /* We need to further call clean_dirty_bitmap() functions of specific
         * paging modes (shadow or hap).  Safe because the domain is paused. */
        d->arch.paging.log_dirty.clean_dirty_bitmap(d);
    }
    domain_unpause(d);
    return rv;

 out:
    paging_unlock(d);
    domain_unpause(d);

    if ( l1 )
        unmap_domain_page(l1);
    if ( l2 )
        unmap_domain_page(l2);
    if ( l3 )
        unmap_domain_page(l3);
    if ( l4 )
        unmap_domain_page(l4);

    return rv;
}

int paging_log_dirty_range(struct domain *d,
                            unsigned long begin_pfn,
                            unsigned long nr,
                            XEN_GUEST_HANDLE_64(uint8) dirty_bitmap)
{
    int rv = 0;
    unsigned long pages = 0;
    mfn_t *l4, *l3, *l2;
    unsigned long *l1;
    int b1, b2, b3, b4;
    int i2, i3, i4;

    d->arch.paging.log_dirty.clean_dirty_bitmap(d);
    paging_lock(d);

    PAGING_DEBUG(LOGDIRTY, "log-dirty-range: dom %u faults=%u dirty=%u\n",
                 d->domain_id,
                 d->arch.paging.log_dirty.fault_count,
                 d->arch.paging.log_dirty.dirty_count);

    if ( unlikely(d->arch.paging.log_dirty.failed_allocs) ) {
        printk("%s: %d failed page allocs while logging dirty pages\n",
               __FUNCTION__, d->arch.paging.log_dirty.failed_allocs);
        rv = -ENOMEM;
        goto out;
    }

    if ( !d->arch.paging.log_dirty.fault_count &&
         !d->arch.paging.log_dirty.dirty_count ) {
        unsigned int size = BITS_TO_LONGS(nr);

        if ( clear_guest(dirty_bitmap, size * BYTES_PER_LONG) != 0 )
            rv = -EFAULT;
        goto out;
    }
    d->arch.paging.log_dirty.fault_count = 0;
    d->arch.paging.log_dirty.dirty_count = 0;

    b1 = L1_LOGDIRTY_IDX(begin_pfn);
    b2 = L2_LOGDIRTY_IDX(begin_pfn);
    b3 = L3_LOGDIRTY_IDX(begin_pfn);
    b4 = L4_LOGDIRTY_IDX(begin_pfn);
    l4 = paging_map_log_dirty_bitmap(d);

    for ( i4 = b4;
          (pages < nr) && (i4 < LOGDIRTY_NODE_ENTRIES);
          i4++ )
    {
        l3 = (l4 && mfn_valid(l4[i4])) ? map_domain_page(mfn_x(l4[i4])) : NULL;
        for ( i3 = b3;
              (pages < nr) && (i3 < LOGDIRTY_NODE_ENTRIES);
              i3++ )
        {
            l2 = ((l3 && mfn_valid(l3[i3])) ?
                  map_domain_page(mfn_x(l3[i3])) : NULL);
            for ( i2 = b2;
                  (pages < nr) && (i2 < LOGDIRTY_NODE_ENTRIES);
                  i2++ )
            {
                unsigned int bytes = PAGE_SIZE;
                uint8_t *s;
                l1 = ((l2 && mfn_valid(l2[i2])) ?
                      map_domain_page(mfn_x(l2[i2])) : NULL);

                s = ((uint8_t*)l1) + (b1 >> 3);
                bytes -= b1 >> 3;

                if ( likely(((nr - pages + 7) >> 3) < bytes) )
                    bytes = (unsigned int)((nr - pages + 7) >> 3);

                if ( !l1 )
                {
                    if ( clear_guest_offset(dirty_bitmap, pages >> 3,
                                            bytes) != 0 )
                    {
                        rv = -EFAULT;
                        goto out;
                    }
                }
                /* begin_pfn is not 32K aligned, hence we have to bit
                 * shift the bitmap */
                else if ( b1 & 0x7 )
                {
                    int i, j;
                    uint32_t *l = (uint32_t*) s;
                    int bits = b1 & 0x7;
                    int bitmask = (1 << bits) - 1;
                    int size = (bytes + BYTES_PER_LONG - 1) / BYTES_PER_LONG;
                    unsigned long bitmap[size];
                    static unsigned long printed = 0;

                    if ( printed != begin_pfn )
                    {
                        dprintk(XENLOG_DEBUG, "%s: begin_pfn %lx is not 32K aligned!\n",
                                __FUNCTION__, begin_pfn);
                        printed = begin_pfn;
                    }

                    for ( i = 0; i < size - 1; i++, l++ ) {
                        bitmap[i] = ((*l) >> bits) |
                            (((*((uint8_t*)(l + 1))) & bitmask) << (sizeof(*l) * 8 - bits));
                    }
                    s = (uint8_t*) l;
                    size = BYTES_PER_LONG - ((b1 >> 3) & 0x3);
                    bitmap[i] = 0;
                    for ( j = 0; j < size; j++, s++ )
                        bitmap[i] |= (*s) << (j * 8);
                    bitmap[i] = (bitmap[i] >> bits) | (bitmask << (size * 8 - bits));
                    if ( copy_to_guest_offset(dirty_bitmap, (pages >> 3),
                                (uint8_t*) bitmap, bytes) != 0 )
                    {
                        rv = -EFAULT;
                        goto out;
                    }
                }
                else
                {
                    if ( copy_to_guest_offset(dirty_bitmap, pages >> 3,
                                              s, bytes) != 0 )
                    {
                        rv = -EFAULT;
                        goto out;
                    }
                }

                pages += bytes << 3;
                if ( l1 )
                {
                    clear_page(l1);
                    unmap_domain_page(l1);
                }
                b1 = b1 & 0x7;
            }
            b2 = 0;
            if ( l2 )
                unmap_domain_page(l2);
        }
        b3 = 0;
        if ( l3 )
            unmap_domain_page(l3);
    }
    if ( l4 )
        unmap_domain_page(l4);

    paging_unlock(d);

    return rv;

 out:
    paging_unlock(d);
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
    d->arch.paging.log_dirty.enable_log_dirty = enable_log_dirty;
    d->arch.paging.log_dirty.disable_log_dirty = disable_log_dirty;
    d->arch.paging.log_dirty.clean_dirty_bitmap = clean_dirty_bitmap;
}

/* This function fress log dirty bitmap resources. */
static void paging_log_dirty_teardown(struct domain*d)
{
    paging_free_log_dirty_bitmap(d);
}

/************************************************/
/*           CODE FOR PAGING SUPPORT            */
/************************************************/
/* Domain paging struct initialization. */
int paging_domain_init(struct domain *d, unsigned int domcr_flags)
{
    int rc;

    if ( (rc = p2m_init(d)) != 0 )
        return rc;

    mm_lock_init(&d->arch.paging.lock);

    /* This must be initialized separately from the rest of the
     * log-dirty init code as that can be called more than once and we
     * don't want to leak any active log-dirty bitmaps */
    d->arch.paging.log_dirty.top = _mfn(INVALID_MFN);

    /* The order of the *_init calls below is important, as the later
     * ones may rewrite some common fields.  Shadow pagetables are the
     * default... */
    shadow_domain_init(d, domcr_flags);

    /* ... but we will use hardware assistance if it's available. */
    if ( hap_enabled(d) )
        hap_domain_init(d);

    return 0;
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

    if ( unlikely(d->vcpu == NULL) || unlikely(d->vcpu[0] == NULL) )
    {
        gdprintk(XENLOG_DEBUG, "Paging op on a domain (%u) with no vcpus\n",
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

    case XEN_DOMCTL_SHADOW_OP_ENABLE:
        if ( !(sc->mode & XEN_DOMCTL_SHADOW_ENABLE_LOG_DIRTY) )
            break;
        /* Else fall through... */
    case XEN_DOMCTL_SHADOW_OP_ENABLE_LOGDIRTY:
        if ( hap_enabled(d) )
            hap_logdirty_init(d);
        return paging_log_dirty_enable(d);

    case XEN_DOMCTL_SHADOW_OP_OFF:
        if ( paging_mode_log_dirty(d) )
            if ( (rc = paging_log_dirty_disable(d)) != 0 )
                return rc;
        break;

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

    /* Move populate-on-demand cache back to domain_list for destruction */
    p2m_pod_empty_cache(d);
}

/* Call once all of the references to the domain have gone away */
void paging_final_teardown(struct domain *d)
{
    if ( hap_enabled(d) )
        hap_final_teardown(d);
    else
        shadow_final_teardown(d);

    p2m_final_teardown(d);
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

/* Called from the guest to indicate that a process is being torn down
 * and therefore its pagetables will soon be discarded */
void pagetable_dying(struct domain *d, paddr_t gpa)
{
    struct vcpu *v;

    ASSERT(paging_mode_shadow(d));

    v = d->vcpu[0];
    v->arch.paging.mode->shadow.pagetable_dying(v, gpa);
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
            if ( paging_get_hostmode(v) )
                printk("shadowed %u-on-%u\n",
                       paging_get_hostmode(v)->guest_levels,
                       paging_get_hostmode(v)->shadow.shadow_levels);
            else
                printk("not shadowed\n");
        }
        else if ( paging_mode_hap(v->domain) && paging_get_hostmode(v) )
            printk("hap, %u levels\n",
                   paging_get_hostmode(v)->guest_levels);
        else
            printk("none\n");
    }
}

const struct paging_mode *paging_get_mode(struct vcpu *v)
{
    if (!nestedhvm_is_n2(v))
        return paging_get_hostmode(v);

    return paging_get_nestedmode(v);
}

void paging_update_nestedmode(struct vcpu *v)
{
    ASSERT(nestedhvm_enabled(v->domain));
    if (nestedhvm_paging_mode_hap(v))
        /* nested-on-nested */
        v->arch.paging.nestedmode = hap_paging_get_mode(v);
    else
        /* TODO: shadow-on-shadow */
        v->arch.paging.nestedmode = NULL;
    hvm_asid_flush_vcpu(v);
}

void paging_write_p2m_entry(struct p2m_domain *p2m, unsigned long gfn,
                            l1_pgentry_t *p, mfn_t table_mfn,
                            l1_pgentry_t new, unsigned int level)
{
    struct domain *d = p2m->domain;
    struct vcpu *v = current;
    if ( v->domain != d )
        v = d->vcpu ? d->vcpu[0] : NULL;
    if ( likely(v && paging_mode_enabled(d) && paging_get_hostmode(v) != NULL) )
    {
        return paging_get_hostmode(v)->write_p2m_entry(v, gfn, p, table_mfn,
                                                       new, level);
    }
    else
        safe_write_pte(p, new);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
