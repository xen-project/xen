/******************************************************************************
 * include/asm-x86/shadow.h
 * 
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

#ifndef _XEN_SHADOW_H
#define _XEN_SHADOW_H

#include <public/domctl.h> 
#include <xen/sched.h>
#include <xen/perfc.h>
#include <xen/domain_page.h>
#include <asm/flushtlb.h>

/* How to make sure a page is not referred to in a shadow PT */
/* This will need to be a for_each_vcpu if we go to per-vcpu shadows */ 
#define shadow_drop_references(_d, _p)                      \
    shadow_remove_all_mappings((_d)->vcpu[0], _mfn(page_to_mfn(_p)))
#define shadow_sync_and_drop_references(_d, _p)             \
    shadow_remove_all_mappings((_d)->vcpu[0], _mfn(page_to_mfn(_p)))

/* How to add and remove entries in the p2m mapping. */
#define guest_physmap_add_page(_d, _p, _m)                  \
    shadow_guest_physmap_add_page((_d), (_p), (_m))
#define guest_physmap_remove_page(_d, _p, _m   )            \
    shadow_guest_physmap_remove_page((_d), (_p), (_m))

/* Shadow PT operation mode : shadow-mode variable in arch_domain. */

#define SHM2_shift 10
/* We're in one of the shadow modes */
#define SHM2_enable    (1U << SHM2_shift)
/* Refcounts based on shadow tables instead of guest tables */
#define SHM2_refcounts (XEN_DOMCTL_SHADOW_ENABLE_REFCOUNT << SHM2_shift)
/* Enable log dirty mode */
#define SHM2_log_dirty (XEN_DOMCTL_SHADOW_ENABLE_LOG_DIRTY << SHM2_shift)
/* Xen does p2m translation, not guest */
#define SHM2_translate (XEN_DOMCTL_SHADOW_ENABLE_TRANSLATE << SHM2_shift)
/* Xen does not steal address space from the domain for its own booking;
 * requires VT or similar mechanisms */
#define SHM2_external  (XEN_DOMCTL_SHADOW_ENABLE_EXTERNAL << SHM2_shift)

#define shadow_mode_enabled(_d)   ((_d)->arch.shadow.mode)
#define shadow_mode_refcounts(_d) ((_d)->arch.shadow.mode & SHM2_refcounts)
#define shadow_mode_log_dirty(_d) ((_d)->arch.shadow.mode & SHM2_log_dirty)
#define shadow_mode_translate(_d) ((_d)->arch.shadow.mode & SHM2_translate)
#define shadow_mode_external(_d)  ((_d)->arch.shadow.mode & SHM2_external)

/* Xen traps & emulates all reads of all page table pages:
 *not yet supported
 */
#define shadow_mode_trap_reads(_d) ({ (void)(_d); 0; })

// flags used in the return value of the shadow_set_lXe() functions...
#define SHADOW_SET_CHANGED            0x1
#define SHADOW_SET_FLUSH              0x2
#define SHADOW_SET_ERROR              0x4
#define SHADOW_SET_L3PAE_RECOPY       0x8

// How do we tell that we have a 32-bit PV guest in a 64-bit Xen?
#ifdef __x86_64__
#define pv_32bit_guest(_v) 0 // not yet supported
#else
#define pv_32bit_guest(_v) !hvm_guest(v)
#endif

/* The shadow lock.
 *
 * This lock is per-domain.  It is intended to allow us to make atomic
 * updates to the software TLB that the shadow tables provide.
 * 
 * Specifically, it protects:
 *   - all changes to shadow page table pages
 *   - the shadow hash table
 *   - the shadow page allocator 
 *   - all changes to guest page table pages; if/when the notion of
 *     out-of-sync pages is added to this code, then the shadow lock is
 *     protecting all guest page table pages which are not listed as
 *     currently as both guest-writable and out-of-sync...
 *     XXX -- need to think about this relative to writable page tables.
 *   - all changes to the page_info->tlbflush_timestamp
 *   - the page_info->count fields on shadow pages
 *   - the shadow dirty bit array and count
 *   - XXX
 */
#ifndef CONFIG_SMP
#error shadow.h currently requires CONFIG_SMP
#endif

#define shadow_lock_init(_d)                                   \
    do {                                                        \
        spin_lock_init(&(_d)->arch.shadow.lock);               \
        (_d)->arch.shadow.locker = -1;                         \
        (_d)->arch.shadow.locker_function = "nobody";          \
    } while (0)

#define shadow_lock_is_acquired(_d)                            \
    (current->processor == (_d)->arch.shadow.locker)

#define shadow_lock(_d)                                                 \
    do {                                                                 \
        if ( unlikely((_d)->arch.shadow.locker == current->processor) ) \
        {                                                                \
            printk("Error: shadow lock held by %s\n",                   \
                   (_d)->arch.shadow.locker_function);                  \
            BUG();                                                       \
        }                                                                \
        spin_lock(&(_d)->arch.shadow.lock);                             \
        ASSERT((_d)->arch.shadow.locker == -1);                         \
        (_d)->arch.shadow.locker = current->processor;                  \
        (_d)->arch.shadow.locker_function = __func__;                   \
    } while (0)

#define shadow_unlock(_d)                                              \
    do {                                                                \
        ASSERT((_d)->arch.shadow.locker == current->processor);        \
        (_d)->arch.shadow.locker = -1;                                 \
        (_d)->arch.shadow.locker_function = "nobody";                  \
        spin_unlock(&(_d)->arch.shadow.lock);                          \
    } while (0)

/* 
 * Levels of self-test and paranoia
 * XXX should go in config files somewhere?  
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

/* 
 * Levels of optimization
 * XXX should go in config files somewhere?  
 */
#define SHOPT_WRITABLE_HEURISTIC  0x01  /* Guess at RW PTEs via linear maps */
#define SHOPT_EARLY_UNSHADOW      0x02  /* Unshadow l1s on fork or exit */

#define SHADOW_OPTIMIZATIONS      0x03


/* With shadow pagetables, the different kinds of address start 
 * to get get confusing.
 * 
 * Virtual addresses are what they usually are: the addresses that are used 
 * to accessing memory while the guest is running.  The MMU translates from 
 * virtual addresses to machine addresses. 
 * 
 * (Pseudo-)physical addresses are the abstraction of physical memory the
 * guest uses for allocation and so forth.  For the purposes of this code, 
 * we can largely ignore them.
 *
 * Guest frame numbers (gfns) are the entries that the guest puts in its
 * pagetables.  For normal paravirtual guests, they are actual frame numbers,
 * with the translation done by the guest.  
 * 
 * Machine frame numbers (mfns) are the entries that the hypervisor puts
 * in the shadow page tables.
 *
 * Elsewhere in the xen code base, the name "gmfn" is generally used to refer
 * to a "machine frame number, from the guest's perspective", or in other
 * words, pseudo-physical frame numbers.  However, in the shadow code, the
 * term "gmfn" means "the mfn of a guest page"; this combines naturally with
 * other terms such as "smfn" (the mfn of a shadow page), gl2mfn (the mfn of a
 * guest L2 page), etc...
 */

/* With this defined, we do some ugly things to force the compiler to
 * give us type safety between mfns and gfns and other integers.
 * TYPE_SAFE(int foo) defines a foo_t, and _foo() and foo_x() functions 
 * that translate beween int and foo_t.
 * 
 * It does have some performance cost because the types now have 
 * a different storage attribute, so may not want it on all the time. */
#ifndef NDEBUG
#define TYPE_SAFETY 1
#endif

#ifdef TYPE_SAFETY
#define TYPE_SAFE(_type,_name)                                  \
typedef struct { _type _name; } _name##_t;                      \
static inline _name##_t _##_name(_type n) { return (_name##_t) { n }; } \
static inline _type _name##_x(_name##_t n) { return n._name; }
#else
#define TYPE_SAFE(_type,_name)                                          \
typedef _type _name##_t;                                                \
static inline _name##_t _##_name(_type n) { return n; }                 \
static inline _type _name##_x(_name##_t n) { return n; }
#endif

TYPE_SAFE(unsigned long,mfn)
#define SH_PRI_mfn "05lx"

static inline int
valid_mfn(mfn_t m)
{
    return VALID_MFN(mfn_x(m));
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

static inline int
shadow_vcpu_mode_translate(struct vcpu *v)
{
    // Returns true if this VCPU needs to be using the P2M table to translate
    // between GFNs and MFNs.
    //
    // This is true of translated HVM domains on a vcpu which has paging
    // enabled.  (HVM vcpu's with paging disabled are using the p2m table as
    // its paging table, so no translation occurs in this case.)
    //
    // It is also true for translated PV domains.
    //
    return v->arch.shadow.translate_enabled;
}


/**************************************************************************/
/* Mode-specific entry points into the shadow code */

struct x86_emulate_ctxt;
struct shadow_paging_mode {
    int           (*page_fault            )(struct vcpu *v, unsigned long va,
                                            struct cpu_user_regs *regs);
    int           (*invlpg                )(struct vcpu *v, unsigned long va);
    unsigned long (*gva_to_gpa            )(struct vcpu *v, unsigned long va);
    unsigned long (*gva_to_gfn            )(struct vcpu *v, unsigned long va);
    void          (*update_cr3            )(struct vcpu *v);
    int           (*map_and_validate_gl1e )(struct vcpu *v, mfn_t gmfn,
                                            void *new_guest_entry, u32 size);
    int           (*map_and_validate_gl2e )(struct vcpu *v, mfn_t gmfn,
                                            void *new_guest_entry, u32 size);
    int           (*map_and_validate_gl2he)(struct vcpu *v, mfn_t gmfn,
                                            void *new_guest_entry, u32 size);
    int           (*map_and_validate_gl3e )(struct vcpu *v, mfn_t gmfn,
                                            void *new_guest_entry, u32 size);
    int           (*map_and_validate_gl4e )(struct vcpu *v, mfn_t gmfn,
                                            void *new_guest_entry, u32 size);
    void          (*detach_old_tables     )(struct vcpu *v);
    int           (*x86_emulate_write     )(struct vcpu *v, unsigned long va,
                                            void *src, u32 bytes,
                                            struct x86_emulate_ctxt *ctxt);
    int           (*x86_emulate_cmpxchg   )(struct vcpu *v, unsigned long va,
                                            unsigned long old, 
                                            unsigned long new,
                                            unsigned int bytes,
                                            struct x86_emulate_ctxt *ctxt);
    int           (*x86_emulate_cmpxchg8b )(struct vcpu *v, unsigned long va,
                                            unsigned long old_lo, 
                                            unsigned long old_hi, 
                                            unsigned long new_lo,
                                            unsigned long new_hi,
                                            struct x86_emulate_ctxt *ctxt);
    mfn_t         (*make_monitor_table    )(struct vcpu *v);
    void          (*destroy_monitor_table )(struct vcpu *v, mfn_t mmfn);
    void *        (*guest_map_l1e         )(struct vcpu *v, unsigned long va,
                                            unsigned long *gl1mfn);
    void          (*guest_get_eff_l1e     )(struct vcpu *v, unsigned long va,
                                            void *eff_l1e);
#if SHADOW_OPTIMIZATIONS & SHOPT_WRITABLE_HEURISTIC
    int           (*guess_wrmap           )(struct vcpu *v, 
                                            unsigned long vaddr, mfn_t gmfn);
#endif
    /* For outsiders to tell what mode we're in */
    unsigned int shadow_levels;
    unsigned int guest_levels;
};

static inline int shadow_guest_paging_levels(struct vcpu *v)
{
    ASSERT(v->arch.shadow.mode != NULL);
    return v->arch.shadow.mode->guest_levels;
}

/**************************************************************************/
/* Entry points into the shadow code */

/* Turning on shadow test mode */
int shadow_test_enable(struct domain *d);

/* Handler for shadow control ops: enabling and disabling shadow modes, 
 * and log-dirty bitmap ops all happen through here. */
int shadow_domctl(struct domain *d, 
                   xen_domctl_shadow_op_t *sc,
                   XEN_GUEST_HANDLE(xen_domctl_t) u_domctl);

/* Call when destroying a domain */
void shadow_teardown(struct domain *d);

/* Call once all of the references to the domain have gone away */
void shadow_final_teardown(struct domain *d);


/* Mark a page as dirty in the bitmap */
void sh_do_mark_dirty(struct domain *d, mfn_t gmfn);
static inline void mark_dirty(struct domain *d, unsigned long gmfn)
{
    if ( likely(!shadow_mode_log_dirty(d)) )
        return;

    shadow_lock(d);
    sh_do_mark_dirty(d, _mfn(gmfn));
    shadow_unlock(d);
}

/* Internal version, for when the shadow lock is already held */
static inline void sh_mark_dirty(struct domain *d, mfn_t gmfn)
{
    ASSERT(shadow_lock_is_acquired(d));
    if ( unlikely(shadow_mode_log_dirty(d)) )
        sh_do_mark_dirty(d, gmfn);
}

static inline int
shadow_fault(unsigned long va, struct cpu_user_regs *regs)
/* Called from pagefault handler in Xen, and from the HVM trap handlers
 * for pagefaults.  Returns 1 if this fault was an artefact of the
 * shadow code (and the guest should retry) or 0 if it is not (and the
 * fault should be handled elsewhere or passed to the guest). */
{
    struct vcpu *v = current;
    perfc_incrc(shadow_fault);
    return v->arch.shadow.mode->page_fault(v, va, regs);
}

static inline int
shadow_invlpg(struct vcpu *v, unsigned long va)
/* Called when the guest requests an invlpg.  Returns 1 if the invlpg
 * instruction should be issued on the hardware, or 0 if it's safe not
 * to do so. */
{
    return v->arch.shadow.mode->invlpg(v, va);
}

static inline unsigned long
shadow_gva_to_gpa(struct vcpu *v, unsigned long va)
/* Called to translate a guest virtual address to what the *guest*
 * pagetables would map it to. */
{
    return v->arch.shadow.mode->gva_to_gpa(v, va);
}

static inline unsigned long
shadow_gva_to_gfn(struct vcpu *v, unsigned long va)
/* Called to translate a guest virtual address to what the *guest*
 * pagetables would map it to. */
{
    return v->arch.shadow.mode->gva_to_gfn(v, va);
}

static inline void
shadow_update_cr3(struct vcpu *v)
/* Updates all the things that are derived from the guest's CR3. 
 * Called when the guest changes CR3. */
{
    shadow_lock(v->domain);
    v->arch.shadow.mode->update_cr3(v);
    shadow_unlock(v->domain);
}


/* Should be called after CR3 is updated.
 * Updates vcpu->arch.cr3 and, for HVM guests, vcpu->arch.hvm_vcpu.cpu_cr3.
 * 
 * Also updates other state derived from CR3 (vcpu->arch.guest_vtable,
 * shadow_vtable, etc).
 *
 * Uses values found in vcpu->arch.(guest_table and guest_table_user), and
 * for HVM guests, arch.monitor_table and hvm's guest CR3.
 *
 * Update ref counts to shadow tables appropriately.
 * For PAE, relocate L3 entries, if necessary, into low memory.
 */
static inline void update_cr3(struct vcpu *v)
{
    unsigned long cr3_mfn=0;

    if ( shadow_mode_enabled(v->domain) )
    {
        shadow_update_cr3(v);
        return;
    }

#if CONFIG_PAGING_LEVELS == 4
    if ( !(v->arch.flags & TF_kernel_mode) )
        cr3_mfn = pagetable_get_pfn(v->arch.guest_table_user);
    else
#endif
        cr3_mfn = pagetable_get_pfn(v->arch.guest_table);

    make_cr3(v, cr3_mfn);
}

extern void sh_update_paging_modes(struct vcpu *v);

/* Should be called to initialise paging structures if the paging mode
 * has changed, and when bringing up a VCPU for the first time. */
static inline void shadow_update_paging_modes(struct vcpu *v)
{
    ASSERT(shadow_mode_enabled(v->domain));
    shadow_lock(v->domain);
    sh_update_paging_modes(v);
    shadow_unlock(v->domain);
}

static inline void
shadow_detach_old_tables(struct vcpu *v)
{
    if ( v->arch.shadow.mode )
        v->arch.shadow.mode->detach_old_tables(v);
}

static inline mfn_t
shadow_make_monitor_table(struct vcpu *v)
{
    return v->arch.shadow.mode->make_monitor_table(v);
}

static inline void
shadow_destroy_monitor_table(struct vcpu *v, mfn_t mmfn)
{
    v->arch.shadow.mode->destroy_monitor_table(v, mmfn);
}

static inline void *
guest_map_l1e(struct vcpu *v, unsigned long addr, unsigned long *gl1mfn)
{
    if ( likely(!shadow_mode_translate(v->domain)) )
    {
        l2_pgentry_t l2e;
        ASSERT(!shadow_mode_external(v->domain));
        /* Find this l1e and its enclosing l1mfn in the linear map */
        if ( __copy_from_user(&l2e, 
                              &__linear_l2_table[l2_linear_offset(addr)],
                              sizeof(l2_pgentry_t)) != 0 )
            return NULL;
        /* Check flags that it will be safe to read the l1e */
        if ( (l2e_get_flags(l2e) & (_PAGE_PRESENT | _PAGE_PSE)) 
             != _PAGE_PRESENT )
            return NULL;
        *gl1mfn = l2e_get_pfn(l2e);
        return &__linear_l1_table[l1_linear_offset(addr)];
    }

    return v->arch.shadow.mode->guest_map_l1e(v, addr, gl1mfn);
}

static inline void
guest_unmap_l1e(struct vcpu *v, void *p)
{
    if ( unlikely(shadow_mode_translate(v->domain)) )
        unmap_domain_page(p);
}

static inline void
guest_get_eff_l1e(struct vcpu *v, unsigned long addr, void *eff_l1e)
{
    if ( likely(!shadow_mode_translate(v->domain)) )
    {
        ASSERT(!shadow_mode_external(v->domain));
        if ( __copy_from_user(eff_l1e, 
                              &__linear_l1_table[l1_linear_offset(addr)],
                              sizeof(l1_pgentry_t)) != 0 )
            *(l1_pgentry_t *)eff_l1e = l1e_empty();
        return;
    }
        
    v->arch.shadow.mode->guest_get_eff_l1e(v, addr, eff_l1e);
}

static inline void
guest_get_eff_kern_l1e(struct vcpu *v, unsigned long addr, void *eff_l1e)
{
#if defined(__x86_64__)
    int user_mode = !(v->arch.flags & TF_kernel_mode);
#define TOGGLE_MODE() if ( user_mode ) toggle_guest_mode(v)
#else
#define TOGGLE_MODE() ((void)0)
#endif

    TOGGLE_MODE();
    guest_get_eff_l1e(v, addr, eff_l1e);
    TOGGLE_MODE();
}


/* Validate a pagetable change from the guest and update the shadows. */
extern int shadow_validate_guest_entry(struct vcpu *v, mfn_t gmfn,
                                        void *new_guest_entry);
extern int __shadow_validate_guest_entry(struct vcpu *v, mfn_t gmfn, 
                                         void *entry, u32 size);

/* Update the shadows in response to a pagetable write from a HVM guest */
extern void shadow_validate_guest_pt_write(struct vcpu *v, mfn_t gmfn, 
                                            void *entry, u32 size);

/* Remove all writeable mappings of a guest frame from the shadows.
 * Returns non-zero if we need to flush TLBs. 
 * level and fault_addr desribe how we found this to be a pagetable;
 * level==0 means we have some other reason for revoking write access. */
extern int shadow_remove_write_access(struct vcpu *v, mfn_t readonly_mfn,
                                       unsigned int level,
                                       unsigned long fault_addr);

/* Remove all mappings of the guest mfn from the shadows. 
 * Returns non-zero if we need to flush TLBs. */
extern int shadow_remove_all_mappings(struct vcpu *v, mfn_t target_mfn);

void
shadow_remove_all_shadows_and_parents(struct vcpu *v, mfn_t gmfn);
/* This is a HVM page that we thing is no longer a pagetable.
 * Unshadow it, and recursively unshadow pages that reference it. */

/* Remove all shadows of the guest mfn. */
extern void sh_remove_shadows(struct vcpu *v, mfn_t gmfn, int all);
static inline void shadow_remove_all_shadows(struct vcpu *v, mfn_t gmfn)
{
    int was_locked = shadow_lock_is_acquired(v->domain);
    if ( !was_locked )
        shadow_lock(v->domain);
    sh_remove_shadows(v, gmfn, 1);
    if ( !was_locked )
        shadow_unlock(v->domain);
}

/* Add a page to a domain */
void
shadow_guest_physmap_add_page(struct domain *d, unsigned long gfn,
                               unsigned long mfn);

/* Remove a page from a domain */
void
shadow_guest_physmap_remove_page(struct domain *d, unsigned long gfn,
                                  unsigned long mfn);

/*
 * Definitions for the shadow_flags field in page_info.
 * These flags are stored on *guest* pages...
 * Bits 1-13 are encodings for the shadow types.
 */
#define PGC_SH_type_to_index(_type) ((_type) >> PGC_SH_type_shift)
#define SHF_page_type_mask \
    (((1u << (PGC_SH_type_to_index(PGC_SH_max_shadow) + 1u)) - 1u) - \
     ((1u << PGC_SH_type_to_index(PGC_SH_min_shadow)) - 1u))

#define SHF_L1_32   (1u << PGC_SH_type_to_index(PGC_SH_l1_32_shadow))
#define SHF_FL1_32  (1u << PGC_SH_type_to_index(PGC_SH_fl1_32_shadow))
#define SHF_L2_32   (1u << PGC_SH_type_to_index(PGC_SH_l2_32_shadow))
#define SHF_L1_PAE  (1u << PGC_SH_type_to_index(PGC_SH_l1_pae_shadow))
#define SHF_FL1_PAE (1u << PGC_SH_type_to_index(PGC_SH_fl1_pae_shadow))
#define SHF_L2_PAE  (1u << PGC_SH_type_to_index(PGC_SH_l2_pae_shadow))
#define SHF_L2H_PAE (1u << PGC_SH_type_to_index(PGC_SH_l2h_pae_shadow))
#define SHF_L3_PAE  (1u << PGC_SH_type_to_index(PGC_SH_l3_pae_shadow))
#define SHF_L1_64   (1u << PGC_SH_type_to_index(PGC_SH_l1_64_shadow))
#define SHF_FL1_64  (1u << PGC_SH_type_to_index(PGC_SH_fl1_64_shadow))
#define SHF_L2_64   (1u << PGC_SH_type_to_index(PGC_SH_l2_64_shadow))
#define SHF_L3_64   (1u << PGC_SH_type_to_index(PGC_SH_l3_64_shadow))
#define SHF_L4_64   (1u << PGC_SH_type_to_index(PGC_SH_l4_64_shadow))

/* Used for hysteresis when automatically unhooking mappings on fork/exit */
#define SHF_unhooked_mappings (1u<<31)

/* 
 * Allocation of shadow pages 
 */

/* Return the minumum acceptable number of shadow pages a domain needs */
unsigned int shadow_min_acceptable_pages(struct domain *d);

/* Set the pool of shadow pages to the required number of MB.
 * Input will be rounded up to at least min_acceptable_shadow_pages().
 * Returns 0 for success, 1 for failure. */
unsigned int shadow_set_allocation(struct domain *d, 
                                    unsigned int megabytes,
                                    int *preempted);

/* Return the size of the shadow pool, rounded up to the nearest MB */
static inline unsigned int shadow_get_allocation(struct domain *d)
{
    unsigned int pg = d->arch.shadow.total_pages;
    return ((pg >> (20 - PAGE_SHIFT))
            + ((pg & ((1 << (20 - PAGE_SHIFT)) - 1)) ? 1 : 0));
}

/*
 * Linked list for chaining entries in the shadow hash table. 
 */
struct shadow_hash_entry {
    struct shadow_hash_entry *next;
    mfn_t smfn;                 /* MFN of the shadow */
#ifdef _x86_64_ /* Shorten 'n' so we don't waste a whole word on storing 't' */
    unsigned long n:56;         /* MFN of guest PT or GFN of guest superpage */
#else
    unsigned long n;            /* MFN of guest PT or GFN of guest superpage */
#endif
    unsigned char t;            /* shadow type bits, or 0 for empty */
};

#define SHADOW_HASH_BUCKETS 251
/* Other possibly useful primes are 509, 1021, 2039, 4093, 8191, 16381 */


#if SHADOW_OPTIMIZATIONS & SHOPT_CACHE_WALKS
/* Optimization: cache the results of guest walks.  This helps with MMIO
 * and emulated writes, which tend to issue very similar walk requests
 * repeatedly.  We keep the results of the last few walks, and blow
 * away the cache on guest cr3 write, mode change, or page fault. */

#define SH_WALK_CACHE_ENTRIES 4

/* Rather than cache a guest walk, which would include mapped pointers 
 * to pages, we cache what a TLB would remember about the walk: the 
 * permissions and the l1 gfn */
struct shadow_walk_cache {
    unsigned long va;           /* The virtual address (or 0 == unused) */
    unsigned long gfn;          /* The gfn from the effective l1e   */
    u32 permissions;            /* The aggregated permission bits   */
};
#endif


/**************************************************************************/
/* Guest physmap (p2m) support */

/* Walk another domain's P2M table, mapping pages as we go */
extern mfn_t
sh_gfn_to_mfn_foreign(struct domain *d, unsigned long gpfn);


/* General conversion function from gfn to mfn */
static inline mfn_t
sh_gfn_to_mfn(struct domain *d, unsigned long gfn)
{
    if ( !shadow_mode_translate(d) )
        return _mfn(gfn);
    else if ( likely(current->domain == d) )
        return _mfn(get_mfn_from_gpfn(gfn));
    else
        return sh_gfn_to_mfn_foreign(d, gfn);
}

// vcpu-specific version of gfn_to_mfn().  This is where we hide the dirty
// little secret that, for hvm guests with paging disabled, nearly all of the
// shadow code actually think that the guest is running on *untranslated* page
// tables (which is actually domain->phys_table).
//
static inline mfn_t
sh_vcpu_gfn_to_mfn(struct vcpu *v, unsigned long gfn)
{ 
    if ( !shadow_vcpu_mode_translate(v) )
        return _mfn(gfn);
    if ( likely(current->domain == v->domain) )
        return _mfn(get_mfn_from_gpfn(gfn));
    return sh_gfn_to_mfn_foreign(v->domain, gfn);
}

static inline unsigned long
sh_mfn_to_gfn(struct domain *d, mfn_t mfn)
{
    if ( shadow_mode_translate(d) )
        return get_gpfn_from_mfn(mfn_x(mfn));
    else
        return mfn_x(mfn);
}

static inline l1_pgentry_t
gl1e_to_ml1e(struct domain *d, l1_pgentry_t l1e)
{
    if ( unlikely(shadow_mode_translate(d)) )
        l1e = l1e_from_pfn(gmfn_to_mfn(d, l1e_get_pfn(l1e)),
                           l1e_get_flags(l1e));
    return l1e;
}

#endif /* _XEN_SHADOW_H */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
      
