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
 * Levels of self-test and paranoia
 */

#define SHADOW_AUDIT_HASH           0x01  /* Check current hash bucket */
#define SHADOW_AUDIT_HASH_FULL      0x02  /* Check every hash bucket */
#define SHADOW_AUDIT_ENTRIES        0x04  /* Check this walk's shadows */
#define SHADOW_AUDIT_ENTRIES_FULL   0x08  /* Check every shadow */
#define SHADOW_AUDIT_ENTRIES_MFNS   0x10  /* Check gfn-mfn map in shadows */
#define SHADOW_AUDIT_P2M            0x20  /* Check the p2m table */

#ifdef NDEBUG
#define SHADOW_AUDIT                   0
#define SHADOW_AUDIT_ENABLE            0
#else
#define SHADOW_AUDIT                0x15  /* Basic audit of all except p2m. */
#define SHADOW_AUDIT_ENABLE         shadow_audit_enable
extern int shadow_audit_enable;
#endif

/******************************************************************************
 * Levels of optimization
 */

#define SHOPT_WRITABLE_HEURISTIC  0x01  /* Guess at RW PTEs via linear maps */
#define SHOPT_EARLY_UNSHADOW      0x02  /* Unshadow l1s on fork or exit */
#define SHOPT_FAST_FAULT_PATH     0x04  /* Fast-path MMIO and not-present */
#define SHOPT_PREFETCH            0x08  /* Shadow multiple entries per fault */
#define SHOPT_LINUX_L3_TOPLEVEL   0x10  /* Pin l3es on early 64bit linux */
#define SHOPT_SKIP_VERIFY         0x20  /* Skip PTE v'fy when safe to do so */

#define SHADOW_OPTIMIZATIONS      0x3f


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
 * The shadow lock.
 *
 * This lock is per-domain.  It is intended to allow us to make atomic
 * updates to the software TLB that the shadow tables provide.
 * 
 * Specifically, it protects:
 *   - all changes to shadow page table pages
 *   - the shadow hash table
 *   - the shadow page allocator 
 *   - all changes to guest page table pages
 *   - all changes to the page_info->tlbflush_timestamp
 *   - the page_info->count fields on shadow pages
 *   - the shadow dirty bit array and count
 */
#ifndef CONFIG_SMP
#error shadow.h currently requires CONFIG_SMP
#endif

#define shadow_lock_init(_d)                            \
    do {                                                \
        spin_lock_init(&(_d)->arch.shadow.lock);        \
        (_d)->arch.shadow.locker = -1;                  \
        (_d)->arch.shadow.locker_function = "nobody";   \
    } while (0)

#define shadow_locked_by_me(_d)                     \
    (current->processor == (_d)->arch.shadow.locker)

#define shadow_lock(_d)                                                 \
    do {                                                                \
        if ( unlikely((_d)->arch.shadow.locker == current->processor) ) \
        {                                                               \
            printk("Error: shadow lock held by %s\n",                   \
                   (_d)->arch.shadow.locker_function);                  \
            BUG();                                                      \
        }                                                               \
        spin_lock(&(_d)->arch.shadow.lock);                             \
        ASSERT((_d)->arch.shadow.locker == -1);                         \
        (_d)->arch.shadow.locker = current->processor;                  \
        (_d)->arch.shadow.locker_function = __func__;                   \
    } while (0)

#define shadow_unlock(_d)                                       \
    do {                                                        \
        ASSERT((_d)->arch.shadow.locker == current->processor); \
        (_d)->arch.shadow.locker = -1;                          \
        (_d)->arch.shadow.locker_function = "nobody";           \
        spin_unlock(&(_d)->arch.shadow.lock);                   \
    } while (0)



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
 * Page metadata for shadow pages.
 */

struct shadow_page_info
{
    union {
        /* When in use, guest page we're a shadow of */
        unsigned long backpointer;
        /* When free, order of the freelist we're on */
        unsigned int order;
    };
    union {
        /* When in use, next shadow in this hash chain */
        struct shadow_page_info *next_shadow;
        /* When free, TLB flush time when freed */
        u32 tlbflush_timestamp;
    };
    struct {
        unsigned int type:4;      /* What kind of shadow is this? */
        unsigned int pinned:1;    /* Is the shadow pinned? */
        unsigned int logdirty:1;  /* Was it made in log-dirty mode? */
        unsigned int count:26;    /* Reference count */
        u32 mbz;                  /* Must be zero: this is where the owner 
                                   * field lives in a non-shadow page */
    } __attribute__((packed));
    union {
        /* For unused shadow pages, a list of pages of this order; 
         * for pinnable shadows, if pinned, a list of other pinned shadows
         * (see sh_type_is_pinnable() below for the definition of 
         * "pinnable" shadow types). */
        struct list_head list;
        /* For non-pinnable shadows, a higher entry that points at us */
        paddr_t up;
    };
};

/* The structure above *must* be the same size as a struct page_info
 * from mm.h, since we'll be using the same space in the frametable. 
 * Also, the mbz field must line up with the owner field of normal 
 * pages, so they look properly like anonymous/xen pages. */
static inline void shadow_check_page_struct_offsets(void) {
    BUILD_BUG_ON(sizeof (struct shadow_page_info) 
                 != sizeof (struct page_info));
    BUILD_BUG_ON(offsetof(struct shadow_page_info, mbz) 
                 != offsetof(struct page_info, u.inuse._domain));
};

/* Shadow type codes */
#define SH_type_none           (0U) /* on the shadow free list */
#define SH_type_min_shadow     (1U)
#define SH_type_l1_32_shadow   (1U) /* shadowing a 32-bit L1 guest page */
#define SH_type_fl1_32_shadow  (2U) /* L1 shadow for a 32b 4M superpage */
#define SH_type_l2_32_shadow   (3U) /* shadowing a 32-bit L2 guest page */
#define SH_type_l1_pae_shadow  (4U) /* shadowing a pae L1 page */
#define SH_type_fl1_pae_shadow (5U) /* L1 shadow for pae 2M superpg */
#define SH_type_l2_pae_shadow  (6U) /* shadowing a pae L2-low page */
#define SH_type_l2h_pae_shadow (7U) /* shadowing a pae L2-high page */
#define SH_type_l1_64_shadow   (8U) /* shadowing a 64-bit L1 page */
#define SH_type_fl1_64_shadow  (9U) /* L1 shadow for 64-bit 2M superpg */
#define SH_type_l2_64_shadow  (10U) /* shadowing a 64-bit L2 page */
#define SH_type_l3_64_shadow  (11U) /* shadowing a 64-bit L3 page */
#define SH_type_l4_64_shadow  (12U) /* shadowing a 64-bit L4 page */
#define SH_type_max_shadow    (12U)
#define SH_type_p2m_table     (13U) /* in use as the p2m table */
#define SH_type_monitor_table (14U) /* in use as a monitor table */
#define SH_type_unused        (15U)

/* 
 * What counts as a pinnable shadow?
 */

static inline int sh_type_is_pinnable(struct vcpu *v, unsigned int t) 
{
    /* Top-level shadow types in each mode can be pinned, so that they 
     * persist even when not currently in use in a guest CR3 */
    if ( t == SH_type_l2_32_shadow
         || t == SH_type_l2_pae_shadow
         || t == SH_type_l2h_pae_shadow 
         || t == SH_type_l4_64_shadow )
        return 1;

#if (SHADOW_OPTIMIZATIONS & SHOPT_LINUX_L3_TOPLEVEL) 
    /* Early 64-bit linux used three levels of pagetables for the guest
     * and context switched by changing one l4 entry in a per-cpu l4
     * page.  When we're shadowing those kernels, we have to pin l3
     * shadows so they don't just evaporate on every context switch.
     * For all other guests, we'd rather use the up-pointer field in l3s. */ 
    if ( unlikely((v->domain->arch.shadow.opt_flags & SHOPT_LINUX_L3_TOPLEVEL) 
                  && CONFIG_PAGING_LEVELS >= 4
                  && t == SH_type_l3_64_shadow) )
        return 1;
#endif

    /* Everything else is not pinnable, and can use the "up" pointer */
    return 0;
}

/*
 * Definitions for the shadow_flags field in page_info.
 * These flags are stored on *guest* pages...
 * Bits 1-13 are encodings for the shadow types.
 */
#define SHF_page_type_mask \
    (((1u << (SH_type_max_shadow + 1u)) - 1u) - \
     ((1u << SH_type_min_shadow) - 1u))

#define SHF_L1_32   (1u << SH_type_l1_32_shadow)
#define SHF_FL1_32  (1u << SH_type_fl1_32_shadow)
#define SHF_L2_32   (1u << SH_type_l2_32_shadow)
#define SHF_L1_PAE  (1u << SH_type_l1_pae_shadow)
#define SHF_FL1_PAE (1u << SH_type_fl1_pae_shadow)
#define SHF_L2_PAE  (1u << SH_type_l2_pae_shadow)
#define SHF_L2H_PAE (1u << SH_type_l2h_pae_shadow)
#define SHF_L1_64   (1u << SH_type_l1_64_shadow)
#define SHF_FL1_64  (1u << SH_type_fl1_64_shadow)
#define SHF_L2_64   (1u << SH_type_l2_64_shadow)
#define SHF_L3_64   (1u << SH_type_l3_64_shadow)
#define SHF_L4_64   (1u << SH_type_l4_64_shadow)

#define SHF_32  (SHF_L1_32|SHF_FL1_32|SHF_L2_32)
#define SHF_PAE (SHF_L1_PAE|SHF_FL1_PAE|SHF_L2_PAE|SHF_L2H_PAE)
#define SHF_64  (SHF_L1_64|SHF_FL1_64|SHF_L2_64|SHF_L3_64|SHF_L4_64)

/* Used for hysteresis when automatically unhooking mappings on fork/exit */
#define SHF_unhooked_mappings (1u<<31)


/******************************************************************************
 * Various function declarations 
 */

/* Hash table functions */
mfn_t shadow_hash_lookup(struct vcpu *v, unsigned long n, unsigned int t);
void  shadow_hash_insert(struct vcpu *v, 
                         unsigned long n, unsigned int t, mfn_t smfn);
void  shadow_hash_delete(struct vcpu *v, 
                         unsigned long n, unsigned int t, mfn_t smfn);

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

/* Update the shadows in response to a pagetable write from Xen */
extern int sh_validate_guest_entry(struct vcpu *v, mfn_t gmfn, 
                                   void *entry, u32 size);

/* Update the shadows in response to a pagetable write from a HVM guest */
extern void sh_validate_guest_pt_write(struct vcpu *v, mfn_t gmfn, 
                                       void *entry, u32 size);

/* Remove all writeable mappings of a guest frame from the shadows.
 * Returns non-zero if we need to flush TLBs. 
 * level and fault_addr desribe how we found this to be a pagetable;
 * level==0 means we have some other reason for revoking write access. */
extern int sh_remove_write_access(struct vcpu *v, mfn_t readonly_mfn,
                                  unsigned int level,
                                  unsigned long fault_addr);

/******************************************************************************
 * Flags used in the return value of the shadow_set_lXe() functions...
 */

/* We actually wrote something new to the shadow */
#define SHADOW_SET_CHANGED            0x1
/* Caller should flush TLBs to clear the old entry */
#define SHADOW_SET_FLUSH              0x2
/* Something went wrong: the shadow entry was invalid or refcount failed */
#define SHADOW_SET_ERROR              0x4


/******************************************************************************
 * MFN/page-info handling 
 */

// Override mfn_to_page from asm/page.h, which was #include'd above,
// in order to make it work with our mfn type.
#undef mfn_to_page
#define mfn_to_page(_m) (frame_table + mfn_x(_m))
#define mfn_to_shadow_page(_m) ((struct shadow_page_info *)mfn_to_page(_m))

// Override page_to_mfn from asm/page.h, which was #include'd above,
// in order to make it work with our mfn type.
#undef page_to_mfn
#define page_to_mfn(_pg) (_mfn((_pg) - frame_table))
#define shadow_page_to_mfn(_spg) (page_to_mfn((struct page_info *)_spg))

// Override mfn_valid from asm/page.h, which was #include'd above,
// in order to make it work with our mfn type.
#undef mfn_valid
#define mfn_valid(_mfn) (mfn_x(_mfn) < max_page)

#if GUEST_PAGING_LEVELS >= 3
# define is_lo_pte(_vaddr) (((_vaddr)&0x4)==0)
#else
# define is_lo_pte(_vaddr) (1)
#endif

static inline int
sh_mfn_is_a_page_table(mfn_t gmfn)
{
    struct page_info *page = mfn_to_page(gmfn);
    struct domain *owner;
    unsigned long type_info;

    if ( !mfn_valid(gmfn) )
        return 0;

    owner = page_get_owner(page);
    if ( owner && shadow_mode_refcounts(owner) 
         && (page->count_info & PGC_page_table) )
        return 1; 

    type_info = page->u.inuse.type_info & PGT_type_mask;
    return type_info && (type_info <= PGT_l4_page_table);
}

// Provide mfn_t-aware versions of common xen functions
static inline void *
sh_map_domain_page(mfn_t mfn)
{
    return map_domain_page(mfn_x(mfn));
}

static inline void 
sh_unmap_domain_page(void *p) 
{
    unmap_domain_page(p);
}

static inline void *
sh_map_domain_page_global(mfn_t mfn)
{
    return map_domain_page_global(mfn_x(mfn));
}

static inline void 
sh_unmap_domain_page_global(void *p) 
{
    unmap_domain_page_global(p);
}

static inline mfn_t
pagetable_get_mfn(pagetable_t pt)
{
    return _mfn(pagetable_get_pfn(pt));
}

static inline pagetable_t
pagetable_from_mfn(mfn_t mfn)
{
    return pagetable_from_pfn(mfn_x(mfn));
}


/******************************************************************************
 * Log-dirty mode bitmap handling
 */

extern void sh_mark_dirty(struct domain *d, mfn_t gmfn);

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


/**************************************************************************/
/* Shadow-page refcounting. */

void sh_destroy_shadow(struct vcpu *v, mfn_t smfn);

/* Increase the refcount of a shadow page.  Arguments are the mfn to refcount, 
 * and the physical address of the shadow entry that holds the ref (or zero
 * if the ref is held by something else).  
 * Returns 0 for failure, 1 for success. */
static inline int sh_get_ref(struct vcpu *v, mfn_t smfn, paddr_t entry_pa)
{
    u32 x, nx;
    struct shadow_page_info *sp = mfn_to_shadow_page(smfn);

    ASSERT(mfn_valid(smfn));

    x = sp->count;
    nx = x + 1;

    if ( unlikely(nx >= 1U<<26) )
    {
        SHADOW_PRINTK("shadow ref overflow, gmfn=%" PRtype_info " smfn=%lx\n",
                       sp->backpointer, mfn_x(smfn));
        return 0;
    }
    
    /* Guarded by the shadow lock, so no need for atomic update */
    sp->count = nx;

    /* We remember the first shadow entry that points to each shadow. */
    if ( entry_pa != 0 
         && sh_type_is_pinnable(v, sp->type) 
         && sp->up == 0 ) 
        sp->up = entry_pa;
    
    return 1;
}


/* Decrease the refcount of a shadow page.  As for get_ref, takes the
 * physical address of the shadow entry that held this reference. */
static inline void sh_put_ref(struct vcpu *v, mfn_t smfn, paddr_t entry_pa)
{
    u32 x, nx;
    struct shadow_page_info *sp = mfn_to_shadow_page(smfn);

    ASSERT(mfn_valid(smfn));
    ASSERT(sp->mbz == 0);

    /* If this is the entry in the up-pointer, remove it */
    if ( entry_pa != 0 
         && sh_type_is_pinnable(v, sp->type) 
         && sp->up == entry_pa ) 
        sp->up = 0;

    x = sp->count;
    nx = x - 1;

    if ( unlikely(x == 0) ) 
    {
        SHADOW_ERROR("shadow ref underflow, smfn=%lx oc=%08x t=%#x\n",
                     mfn_x(smfn), sp->count, sp->type);
        BUG();
    }

    /* Guarded by the shadow lock, so no need for atomic update */
    sp->count = nx;

    if ( unlikely(nx == 0) ) 
        sh_destroy_shadow(v, smfn);
}


/* Pin a shadow page: take an extra refcount, set the pin bit,
 * and put the shadow at the head of the list of pinned shadows.
 * Returns 0 for failure, 1 for success. */
static inline int sh_pin(struct vcpu *v, mfn_t smfn)
{
    struct shadow_page_info *sp;
    
    ASSERT(mfn_valid(smfn));
    sp = mfn_to_shadow_page(smfn);
    ASSERT(sh_type_is_pinnable(v, sp->type));
    if ( sp->pinned ) 
    {
        /* Already pinned: take it out of the pinned-list so it can go 
         * at the front */
        list_del(&sp->list);
    }
    else
    {
        /* Not pinned: pin it! */
        if ( !sh_get_ref(v, smfn, 0) )
            return 0;
        sp->pinned = 1;
    }
    /* Put it at the head of the list of pinned shadows */
    list_add(&sp->list, &v->domain->arch.shadow.pinned_shadows);
    return 1;
}

/* Unpin a shadow page: unset the pin bit, take the shadow off the list
 * of pinned shadows, and release the extra ref. */
static inline void sh_unpin(struct vcpu *v, mfn_t smfn)
{
    struct shadow_page_info *sp;
    
    ASSERT(mfn_valid(smfn));
    sp = mfn_to_shadow_page(smfn);
    ASSERT(sh_type_is_pinnable(v, sp->type));
    if ( sp->pinned )
    {
        sp->pinned = 0;
        list_del(&sp->list);
        sp->up = 0; /* in case this stops being a pinnable type in future */
        sh_put_ref(v, smfn, 0);
    }
}


/**************************************************************************/
/* PTE-write emulation. */

struct sh_emulate_ctxt {
    struct x86_emulate_ctxt ctxt;

    /* [HVM] Cache of up to 15 bytes of instruction. */
    uint8_t insn_buf[15];
    uint8_t insn_buf_bytes;

    /* [HVM] Cache of segment registers already gathered for this emulation. */
    unsigned int valid_seg_regs;
    struct segment_register seg_reg[6];
};

struct x86_emulate_ops *shadow_init_emulation(
    struct sh_emulate_ctxt *sh_ctxt, struct cpu_user_regs *regs);

#endif /* _XEN_SHADOW_PRIVATE_H */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
