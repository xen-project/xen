/******************************************************************************
 * arch/x86/mm/shadow/private.h
 *
 * Shadow code that is private, and does not need to be multiply compiled.
 * Parts of this code are Copyright (c) 2006 by XenSource Inc.
 * Parts of this code are Copyright (c) 2006 by Michael A Fetterman
 * Parts based on earlier work by Michael A Fetterman, Ian Pratt et al.
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

#ifndef _XEN_SHADOW_PRIVATE_H
#define _XEN_SHADOW_PRIVATE_H

// In order to override the definition of mfn_to_page, we make sure page.h has
// been included...
#include <asm/page.h>
#include <xen/domain_page.h>
#include <asm/x86_emulate.h>
#include <asm/hvm/support.h>


/******************************************************************************
 * Debug and error-message output
 */
#define SHADOW_PRINTK(_f, _a...)                                     \
    debugtrace_printk("sh: %s(): " _f, __func__, ##_a)
#define SHADOW_ERROR(_f, _a...)                                      \
    printk("sh error: %s(): " _f, __func__, ##_a)
#define SHADOW_DEBUG(flag, _f, _a...)                                \
    do {                                                              \
        if (SHADOW_DEBUG_ ## flag)                                   \
            debugtrace_printk("shdebug: %s(): " _f, __func__, ##_a); \
    } while (0)

// The flags for use with SHADOW_DEBUG:
#define SHADOW_DEBUG_PROPAGATE         1
#define SHADOW_DEBUG_MAKE_SHADOW       1
#define SHADOW_DEBUG_DESTROY_SHADOW    1
#define SHADOW_DEBUG_P2M               0
#define SHADOW_DEBUG_A_AND_D           1
#define SHADOW_DEBUG_EMULATE           1
#define SHADOW_DEBUG_LOGDIRTY          0


/******************************************************************************
 * Auditing routines 
 */

#if SHADOW_AUDIT & SHADOW_AUDIT_ENTRIES_FULL
extern void shadow_audit_tables(struct vcpu *v);
#else
#define shadow_audit_tables(_v) do {} while(0)
#endif

#if SHADOW_AUDIT & SHADOW_AUDIT_P2M
extern void shadow_audit_p2m(struct domain *d);
#else
#define shadow_audit_p2m(_d) do {} while(0)
#endif


/******************************************************************************
 * Macro for dealing with the naming of the internal names of the
 * shadow code's external entry points.
 */
#define SHADOW_INTERNAL_NAME_HIDDEN(name, shadow_levels, guest_levels) \
    name ## __shadow_ ## shadow_levels ## _guest_ ## guest_levels
#define SHADOW_INTERNAL_NAME(name, shadow_levels, guest_levels) \
    SHADOW_INTERNAL_NAME_HIDDEN(name, shadow_levels, guest_levels)

#if CONFIG_PAGING_LEVELS == 2
#define GUEST_LEVELS  2
#define SHADOW_LEVELS 2
#include "multi.h"
#undef GUEST_LEVELS
#undef SHADOW_LEVELS
#endif /* CONFIG_PAGING_LEVELS == 2 */

#if CONFIG_PAGING_LEVELS == 3
#define GUEST_LEVELS  2
#define SHADOW_LEVELS 3
#include "multi.h"
#undef GUEST_LEVELS
#undef SHADOW_LEVELS

#define GUEST_LEVELS  3
#define SHADOW_LEVELS 3
#include "multi.h"
#undef GUEST_LEVELS
#undef SHADOW_LEVELS
#endif /* CONFIG_PAGING_LEVELS == 3 */

#if CONFIG_PAGING_LEVELS == 4
#define GUEST_LEVELS  2
#define SHADOW_LEVELS 3
#include "multi.h"
#undef GUEST_LEVELS
#undef SHADOW_LEVELS

#define GUEST_LEVELS  3
#define SHADOW_LEVELS 3
#include "multi.h"
#undef GUEST_LEVELS
#undef SHADOW_LEVELS

#define GUEST_LEVELS  3
#define SHADOW_LEVELS 4
#include "multi.h"
#undef GUEST_LEVELS
#undef SHADOW_LEVELS

#define GUEST_LEVELS  4
#define SHADOW_LEVELS 4
#include "multi.h"
#undef GUEST_LEVELS
#undef SHADOW_LEVELS
#endif /* CONFIG_PAGING_LEVELS == 4 */


/******************************************************************************
 * Various function declarations 
 */

/* x86 emulator support */
extern struct x86_emulate_ops shadow_emulator_ops;

/* Hash table functions */
mfn_t shadow_hash_lookup(struct vcpu *v, unsigned long n, u8 t);
void  shadow_hash_insert(struct vcpu *v, unsigned long n, u8 t, mfn_t smfn);
void  shadow_hash_delete(struct vcpu *v, unsigned long n, u8 t, mfn_t smfn);

/* shadow promotion */
void shadow_promote(struct vcpu *v, mfn_t gmfn, u32 type);
void shadow_demote(struct vcpu *v, mfn_t gmfn, u32 type);

/* Shadow page allocation functions */
void  shadow_prealloc(struct domain *d, unsigned int order);
mfn_t shadow_alloc(struct domain *d, 
                    u32 shadow_type,
                    unsigned long backpointer);
void  shadow_free(struct domain *d, mfn_t smfn);

/* Function to convert a shadow to log-dirty */
void shadow_convert_to_log_dirty(struct vcpu *v, mfn_t smfn);

/* Dispatcher function: call the per-mode function that will unhook the
 * non-Xen mappings in this top-level shadow mfn */
void shadow_unhook_mappings(struct vcpu *v, mfn_t smfn);

/* Install the xen mappings in various flavours of shadow */
void sh_install_xen_entries_in_l4(struct vcpu *v, mfn_t gl4mfn, mfn_t sl4mfn);
void sh_install_xen_entries_in_l2h(struct vcpu *v, mfn_t sl2hmfn);
void sh_install_xen_entries_in_l2(struct vcpu *v, mfn_t gl2mfn, mfn_t sl2mfn);


/******************************************************************************
 * MFN/page-info handling 
 */

// Override mfn_to_page from asm/page.h, which was #include'd above,
// in order to make it work with our mfn type.
#undef mfn_to_page
#define mfn_to_page(_mfn) (frame_table + mfn_x(_mfn))

// Override page_to_mfn from asm/page.h, which was #include'd above,
// in order to make it work with our mfn type.
#undef page_to_mfn
#define page_to_mfn(_pg) (_mfn((_pg) - frame_table))

// Override mfn_valid from asm/page.h, which was #include'd above,
// in order to make it work with our mfn type.
#undef mfn_valid
#define mfn_valid(_mfn) (mfn_x(_mfn) < max_page)

// Provide mfn_t-aware versions of common xen functions
static inline void *
sh_map_domain_page(mfn_t mfn)
{
    /* XXX Using the monitor-table as a map will happen here  */
    return map_domain_page(mfn_x(mfn));
}

static inline void 
sh_unmap_domain_page(void *p) 
{
    /* XXX Using the monitor-table as a map will happen here  */
    unmap_domain_page(p);
}

static inline void *
sh_map_domain_page_global(mfn_t mfn)
{
    /* XXX Using the monitor-table as a map will happen here  */
    return map_domain_page_global(mfn_x(mfn));
}

static inline void 
sh_unmap_domain_page_global(void *p) 
{
    /* XXX Using the monitor-table as a map will happen here  */
    unmap_domain_page_global(p);
}

static inline int
sh_mfn_is_dirty(struct domain *d, mfn_t gmfn)
/* Is this guest page dirty?  Call only in log-dirty mode. */
{
    unsigned long pfn;
    ASSERT(shadow_mode_log_dirty(d));
    ASSERT(d->arch.shadow.dirty_bitmap != NULL);

    /* We /really/ mean PFN here, even for non-translated guests. */
    pfn = get_gpfn_from_mfn(mfn_x(gmfn));
    if ( likely(VALID_M2P(pfn))
         && likely(pfn < d->arch.shadow.dirty_bitmap_size) 
         && test_bit(pfn, d->arch.shadow.dirty_bitmap) )
        return 1;

    return 0;
}

static inline int
sh_mfn_is_a_page_table(mfn_t gmfn)
{
    struct page_info *page = mfn_to_page(gmfn);
    struct domain *owner;
    unsigned long type_info;

    if ( !valid_mfn(gmfn) )
        return 0;

    owner = page_get_owner(page);
    if ( owner && shadow_mode_refcounts(owner) 
         && (page->count_info & PGC_page_table) )
        return 1; 

    type_info = page->u.inuse.type_info & PGT_type_mask;
    return type_info && (type_info <= PGT_l4_page_table);
}


/**************************************************************************/
/* Shadow-page refcounting. See comment in shadow-common.c about the  
 * use of struct page_info fields for shadow pages */

void sh_destroy_shadow(struct vcpu *v, mfn_t smfn);

/* Increase the refcount of a shadow page.  Arguments are the mfn to refcount, 
 * and the physical address of the shadow entry that holds the ref (or zero
 * if the ref is held by something else) */
static inline void sh_get_ref(mfn_t smfn, paddr_t entry_pa)
{
    u32 x, nx;
    struct page_info *page = mfn_to_page(smfn);

    ASSERT(mfn_valid(smfn));

    x = page->count_info & PGC_SH_count_mask;
    nx = x + 1;

    if ( unlikely(nx & ~PGC_SH_count_mask) )
    {
        SHADOW_PRINTK("shadow ref overflow, gmfn=%" PRtype_info " smfn=%lx\n",
                       page->u.inuse.type_info, mfn_x(smfn));
        domain_crash_synchronous();
    }
    
    /* Guarded by the shadow lock, so no need for atomic update */
    page->count_info &= ~PGC_SH_count_mask;
    page->count_info |= nx;

    /* We remember the first shadow entry that points to each shadow. */
    if ( entry_pa != 0 && page->up == 0 ) 
        page->up = entry_pa;
}


/* Decrease the refcount of a shadow page.  As for get_ref, takes the
 * physical address of the shadow entry that held this reference. */
static inline void sh_put_ref(struct vcpu *v, mfn_t smfn, paddr_t entry_pa)
{
    u32 x, nx;
    struct page_info *page = mfn_to_page(smfn);

    ASSERT(mfn_valid(smfn));
    ASSERT(page_get_owner(page) == NULL);

    /* If this is the entry in the up-pointer, remove it */
    if ( entry_pa != 0 && page->up == entry_pa ) 
        page->up = 0;

    x = page->count_info & PGC_SH_count_mask;
    nx = x - 1;

    if ( unlikely(x == 0) ) 
    {
        SHADOW_PRINTK("shadow ref underflow, smfn=%lx oc=%08x t=%" 
                       PRtype_info "\n",
                       mfn_x(smfn),
                       page->count_info & PGC_SH_count_mask,
                       page->u.inuse.type_info);
        domain_crash_synchronous();
    }

    /* Guarded by the shadow lock, so no need for atomic update */
    page->count_info &= ~PGC_SH_count_mask;
    page->count_info |= nx;

    if ( unlikely(nx == 0) ) 
        sh_destroy_shadow(v, smfn);
}


/* Pin a shadow page: take an extra refcount and set the pin bit. */
static inline void sh_pin(mfn_t smfn)
{
    struct page_info *page;
    
    ASSERT(mfn_valid(smfn));
    page = mfn_to_page(smfn);
    if ( !(page->count_info & PGC_SH_pinned) ) 
    {
        sh_get_ref(smfn, 0);
        page->count_info |= PGC_SH_pinned;
    }
}

/* Unpin a shadow page: unset the pin bit and release the extra ref. */
static inline void sh_unpin(struct vcpu *v, mfn_t smfn)
{
    struct page_info *page;
    
    ASSERT(mfn_valid(smfn));
    page = mfn_to_page(smfn);
    if ( page->count_info & PGC_SH_pinned )
    {
        page->count_info &= ~PGC_SH_pinned;
        sh_put_ref(v, smfn, 0);
    }
}

#endif /* _XEN_SHADOW_PRIVATE_H */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
