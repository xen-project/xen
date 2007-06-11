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

/* Xen command-line option to enable hardware-assisted paging */
int opt_hap_enabled;
boolean_param("hap", opt_hap_enabled);

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

/* allocate bitmap resources for log dirty */
int paging_alloc_log_dirty_bitmap(struct domain *d)
{
    if ( d->arch.paging.log_dirty.bitmap != NULL )
        return 0;

    d->arch.paging.log_dirty.bitmap_size =
        (domain_get_maximum_gpfn(d) + BITS_PER_LONG) & ~(BITS_PER_LONG - 1);
    d->arch.paging.log_dirty.bitmap = 
        xmalloc_array(unsigned long,
                      d->arch.paging.log_dirty.bitmap_size / BITS_PER_LONG);
    if ( d->arch.paging.log_dirty.bitmap == NULL )
    {
        d->arch.paging.log_dirty.bitmap_size = 0;
        return -ENOMEM;
    }
    memset(d->arch.paging.log_dirty.bitmap, 0,
           d->arch.paging.log_dirty.bitmap_size/8);

    return 0;
}

/* free bitmap resources */
void paging_free_log_dirty_bitmap(struct domain *d)
{
    d->arch.paging.log_dirty.bitmap_size = 0;
    if ( d->arch.paging.log_dirty.bitmap )
    {
        xfree(d->arch.paging.log_dirty.bitmap);
        d->arch.paging.log_dirty.bitmap = NULL;
    }
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

    gmfn = _mfn(guest_mfn);

    if ( !paging_mode_log_dirty(d) || !mfn_valid(gmfn) )
        return;

    log_dirty_lock(d);

    ASSERT(d->arch.paging.log_dirty.bitmap != NULL);

    /* We /really/ mean PFN here, even for non-translated guests. */
    pfn = get_gpfn_from_mfn(mfn_x(gmfn));

    /*
     * Values with the MSB set denote MFNs that aren't really part of the 
     * domain's pseudo-physical memory map (e.g., the shared info frame).
     * Nothing to do here...
     */
    if ( unlikely(!VALID_M2P(pfn)) )
    {
        log_dirty_unlock(d);
        return;
    }

    if ( likely(pfn < d->arch.paging.log_dirty.bitmap_size) ) 
    { 
        if ( !__test_and_set_bit(pfn, d->arch.paging.log_dirty.bitmap) )
        {
            PAGING_DEBUG(LOGDIRTY, 
                         "marked mfn %" PRI_mfn " (pfn=%lx), dom %d\n",
                         mfn_x(gmfn), pfn, d->domain_id);
            d->arch.paging.log_dirty.dirty_count++;
        }
    }
    else
    {
        PAGING_PRINTK("mark_dirty OOR! "
                      "mfn=%" PRI_mfn " pfn=%lx max=%x (dom %d)\n"
                      "owner=%d c=%08x t=%" PRtype_info "\n",
                      mfn_x(gmfn), 
                      pfn, 
                      d->arch.paging.log_dirty.bitmap_size,
                      d->domain_id,
                      (page_get_owner(mfn_to_page(gmfn))
                       ? page_get_owner(mfn_to_page(gmfn))->domain_id
                       : -1),
                      mfn_to_page(gmfn)->count_info, 
                      mfn_to_page(gmfn)->u.inuse.type_info);
    }
    
    log_dirty_unlock(d);
}

/* Read a domain's log-dirty bitmap and stats.  If the operation is a CLEAN, 
 * clear the bitmap and stats as well. */
int paging_log_dirty_op(struct domain *d, struct xen_domctl_shadow_op *sc)
{
    int i, rv = 0, clean = 0, peek = 1;

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

    if ( (peek || clean) && (d->arch.paging.log_dirty.bitmap == NULL) )
    {
        rv = -EINVAL; /* perhaps should be ENOMEM? */
        goto out;
    }
 
    if ( sc->pages > d->arch.paging.log_dirty.bitmap_size )
        sc->pages = d->arch.paging.log_dirty.bitmap_size;

#define CHUNK (8*1024) /* Transfer and clear in 1kB chunks for L1 cache. */
    for ( i = 0; i < sc->pages; i += CHUNK )
    {
        int bytes = ((((sc->pages - i) > CHUNK)
                      ? CHUNK
                      : (sc->pages - i)) + 7) / 8;

        if ( likely(peek) )
        {
            if ( copy_to_guest_offset(
                sc->dirty_bitmap, i/8,
                (uint8_t *)d->arch.paging.log_dirty.bitmap + (i/8), bytes) )
            {
                rv = -EFAULT;
                goto out;
            }
        }

        if ( clean )
            memset((uint8_t *)d->arch.paging.log_dirty.bitmap + (i/8), 0, bytes);
    }
#undef CHUNK

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
    if ( opt_hap_enabled && is_hvm_domain(d) )
        hap_domain_init(d);
}

/* vcpu paging struct initialization goes here */
void paging_vcpu_init(struct vcpu *v)
{
    if ( opt_hap_enabled && is_hvm_vcpu(v) )
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
        gdprintk(XENLOG_INFO, "Dom %u tried to do a paging op on itself.\n",
                 d->domain_id);
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
    if ( opt_hap_enabled && is_hvm_domain(d) )
	return hap_domctl(d, sc, u_domctl);
    else
	return shadow_domctl(d, sc, u_domctl);
}

/* Call when destroying a domain */
void paging_teardown(struct domain *d)
{
    if ( opt_hap_enabled && is_hvm_domain(d) )
        hap_teardown(d);
    else
        shadow_teardown(d);

    /* clean up log dirty resources. */
    paging_log_dirty_teardown(d);
}

/* Call once all of the references to the domain have gone away */
void paging_final_teardown(struct domain *d)
{
    if ( opt_hap_enabled && is_hvm_domain(d) )
        hap_final_teardown(d);
    else
        shadow_final_teardown(d);
}

/* Enable an arbitrary paging-assistance mode.  Call once at domain
 * creation. */
int paging_enable(struct domain *d, u32 mode)
{
    if ( opt_hap_enabled && is_hvm_domain(d) )
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
                printk("shadowed %u-on-%u, %stranslated\n",
                       v->arch.paging.mode->guest_levels,
                       v->arch.paging.mode->shadow.shadow_levels,
                       paging_vcpu_mode_translate(v) ? "" : "not ");
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
