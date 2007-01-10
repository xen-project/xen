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

/*****************************************************************************
 * Macros to tell which shadow paging mode a domain is in */

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
 * not yet supported */
#define shadow_mode_trap_reads(_d) ({ (void)(_d); 0; })


/******************************************************************************
 * The equivalent for a particular vcpu of a shadowed domain. */

/* Is this vcpu using the P2M table to translate between GFNs and MFNs?
 *
 * This is true of translated HVM domains on a vcpu which has paging
 * enabled.  (HVM vcpus with paging disabled are using the p2m table as
 * its paging table, so no translation occurs in this case.)
 * It is also true for all vcpus of translated PV domains. */
#define shadow_vcpu_mode_translate(_v) ((_v)->arch.shadow.translate_enabled)

/*
 * 32on64 support
 */
#ifdef __x86_64__
#define pv_32bit_guest(_v) (!is_hvm_vcpu(_v) && IS_COMPAT((_v)->domain))
#else
#define pv_32bit_guest(_v) (!is_hvm_vcpu(_v))
#endif

/******************************************************************************
 * With shadow pagetables, the different kinds of address start 
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

/* Macro for printk formats: use as printk("%"SH_PRI_mfn"\n", mfn_x(foo)); */
#define SH_PRI_mfn "05lx"


/*****************************************************************************
 * Mode-specific entry points into the shadow code.  
 *
 * These shouldn't be used directly by callers; rather use the functions
 * below which will indirect through this table as appropriate. */

struct sh_emulate_ctxt;
struct shadow_paging_mode {
    int           (*page_fault            )(struct vcpu *v, unsigned long va,
                                            struct cpu_user_regs *regs);
    int           (*invlpg                )(struct vcpu *v, unsigned long va);
    paddr_t       (*gva_to_gpa            )(struct vcpu *v, unsigned long va);
    unsigned long (*gva_to_gfn            )(struct vcpu *v, unsigned long va);
    void          (*update_cr3            )(struct vcpu *v, int do_locking);
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
                                            struct sh_emulate_ctxt *sh_ctxt);
    int           (*x86_emulate_cmpxchg   )(struct vcpu *v, unsigned long va,
                                            unsigned long old, 
                                            unsigned long new,
                                            unsigned int bytes,
                                            struct sh_emulate_ctxt *sh_ctxt);
    int           (*x86_emulate_cmpxchg8b )(struct vcpu *v, unsigned long va,
                                            unsigned long old_lo, 
                                            unsigned long old_hi, 
                                            unsigned long new_lo,
                                            unsigned long new_hi,
                                            struct sh_emulate_ctxt *sh_ctxt);
    mfn_t         (*make_monitor_table    )(struct vcpu *v);
    void          (*destroy_monitor_table )(struct vcpu *v, mfn_t mmfn);
    void *        (*guest_map_l1e         )(struct vcpu *v, unsigned long va,
                                            unsigned long *gl1mfn);
    void          (*guest_get_eff_l1e     )(struct vcpu *v, unsigned long va,
                                            void *eff_l1e);
    int           (*guess_wrmap           )(struct vcpu *v, 
                                            unsigned long vaddr, mfn_t gmfn);
    /* For outsiders to tell what mode we're in */
    unsigned int shadow_levels;
    unsigned int guest_levels;
};


/*****************************************************************************
 * Entry points into the shadow code */

/* Set up the shadow-specific parts of a domain struct at start of day.
 * Called for  every domain from arch_domain_create() */
void shadow_domain_init(struct domain *d);

/* Enable an arbitrary shadow mode.  Call once at domain creation. */
int shadow_enable(struct domain *d, u32 mode);

/* Handler for shadow control ops: operations from user-space to enable
 * and disable ephemeral shadow modes (test mode and log-dirty mode) and
 * manipulate the log-dirty bitmap. */
int shadow_domctl(struct domain *d, 
                  xen_domctl_shadow_op_t *sc,
                  XEN_GUEST_HANDLE(void) u_domctl);

/* Call when destroying a domain */
void shadow_teardown(struct domain *d);

/* Call once all of the references to the domain have gone away */
void shadow_final_teardown(struct domain *d);

/* Mark a page as dirty in the log-dirty bitmap: called when Xen 
 * makes changes to guest memory on its behalf. */
void shadow_mark_dirty(struct domain *d, mfn_t gmfn);
/* Cleaner version so we don't pepper shadow_mode tests all over the place */
static inline void mark_dirty(struct domain *d, unsigned long gmfn)
{
    if ( unlikely(shadow_mode_log_dirty(d)) )
        shadow_mark_dirty(d, _mfn(gmfn));
}

/* Handle page-faults caused by the shadow pagetable mechanisms.
 * Called from pagefault handler in Xen, and from the HVM trap handlers
 * for pagefaults.  Returns 1 if this fault was an artefact of the
 * shadow code (and the guest should retry) or 0 if it is not (and the
 * fault should be handled elsewhere or passed to the guest). */
static inline int shadow_fault(unsigned long va, struct cpu_user_regs *regs)
{
    struct vcpu *v = current;
    perfc_incrc(shadow_fault);
    return v->arch.shadow.mode->page_fault(v, va, regs);
}

/* Handle invlpg requests on shadowed vcpus. 
 * Returns 1 if the invlpg instruction should be issued on the hardware, 
 * or 0 if it's safe not to do so. */
static inline int shadow_invlpg(struct vcpu *v, unsigned long va)
{
    return v->arch.shadow.mode->invlpg(v, va);
}

/* Translate a guest virtual address to the physical address that the
 * *guest* pagetables would map it to. */
static inline paddr_t shadow_gva_to_gpa(struct vcpu *v, unsigned long va)
{
    if ( unlikely(!shadow_vcpu_mode_translate(v)) )
        return (paddr_t) va;
    return v->arch.shadow.mode->gva_to_gpa(v, va);
}

/* Translate a guest virtual address to the frame number that the
 * *guest* pagetables would map it to. */
static inline unsigned long shadow_gva_to_gfn(struct vcpu *v, unsigned long va)
{
    if ( unlikely(!shadow_vcpu_mode_translate(v)) )
        return va >> PAGE_SHIFT;
    return v->arch.shadow.mode->gva_to_gfn(v, va);
}

/* Update all the things that are derived from the guest's CR3.  
 * Called when the guest changes CR3; the caller can then use v->arch.cr3 
 * as the value to load into the host CR3 to schedule this vcpu */
static inline void shadow_update_cr3(struct vcpu *v)
{
    v->arch.shadow.mode->update_cr3(v, 1);
}

/* Update all the things that are derived from the guest's CR0/CR3/CR4.
 * Called to initialize paging structures if the paging mode
 * has changed, and when bringing up a VCPU for the first time. */
void shadow_update_paging_modes(struct vcpu *v);


/*****************************************************************************
 * Access to the guest pagetables */

/* Get a mapping of a PV guest's l1e for this virtual address. */
static inline void *
guest_map_l1e(struct vcpu *v, unsigned long addr, unsigned long *gl1mfn)
{
    l2_pgentry_t l2e;

    if ( unlikely(shadow_mode_translate(v->domain)) )
        return v->arch.shadow.mode->guest_map_l1e(v, addr, gl1mfn);

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

/* Pull down the mapping we got from guest_map_l1e() */
static inline void
guest_unmap_l1e(struct vcpu *v, void *p)
{
    if ( unlikely(shadow_mode_translate(v->domain)) )
        unmap_domain_page(p);
}

/* Read the guest's l1e that maps this address. */
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

/* Read the guest's l1e that maps this address, from the kernel-mode
 * pagetables. */
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

/* Write a new value into the guest pagetable, and update the shadows 
 * appropriately.  Returns 0 if we page-faulted, 1 for success. */
int shadow_write_guest_entry(struct vcpu *v, intpte_t *p,
                             intpte_t new, mfn_t gmfn);

/* Cmpxchg a new value into the guest pagetable, and update the shadows 
 * appropriately. Returns 0 if we page-faulted, 1 if not.
 * N.B. caller should check the value of "old" to see if the
 * cmpxchg itself was successful. */
int shadow_cmpxchg_guest_entry(struct vcpu *v, intpte_t *p,
                               intpte_t *old, intpte_t new, mfn_t gmfn);

/* Remove all mappings of the guest page from the shadows. 
 * This is called from common code.  It does not flush TLBs. */
int sh_remove_all_mappings(struct vcpu *v, mfn_t target_mfn);
static inline void 
shadow_drop_references(struct domain *d, struct page_info *p)
{
    /* See the comment about locking in sh_remove_all_mappings */
    sh_remove_all_mappings(d->vcpu[0], _mfn(page_to_mfn(p)));
}

/* Remove all shadows of the guest mfn. */
void sh_remove_shadows(struct vcpu *v, mfn_t gmfn, int fast, int all);
static inline void shadow_remove_all_shadows(struct vcpu *v, mfn_t gmfn)
{
    /* See the comment about locking in sh_remove_shadows */
    sh_remove_shadows(v, gmfn, 0 /* Be thorough */, 1 /* Must succeed */);
}

/**************************************************************************/
/* Guest physmap (p2m) support 
 *
 * The phys_to_machine_mapping is the reversed mapping of MPT for full
 * virtualization.  It is only used by shadow_mode_translate()==true
 * guests, so we steal the address space that would have normally
 * been used by the read-only MPT map.
 */
#define phys_to_machine_mapping ((l1_pgentry_t *)RO_MPT_VIRT_START)

/* Add a page to a domain's p2m table */
void shadow_guest_physmap_add_page(struct domain *d, unsigned long gfn,
                                   unsigned long mfn);

/* Remove a page from a domain's p2m table */
void shadow_guest_physmap_remove_page(struct domain *d, unsigned long gfn,
                                      unsigned long mfn);

/* Aliases, called from common code. */
#define guest_physmap_add_page    shadow_guest_physmap_add_page
#define guest_physmap_remove_page shadow_guest_physmap_remove_page

/* Read the current domain's P2M table. */
static inline mfn_t sh_gfn_to_mfn_current(unsigned long gfn)
{
    l1_pgentry_t l1e = l1e_empty();
    int ret;

    if ( gfn > current->domain->arch.max_mapped_pfn )
        return _mfn(INVALID_MFN);

    /* Don't read off the end of the p2m table */
    ASSERT(gfn < (RO_MPT_VIRT_END - RO_MPT_VIRT_START) / sizeof(l1_pgentry_t));

    ret = __copy_from_user(&l1e,
                           &phys_to_machine_mapping[gfn],
                           sizeof(l1e));

    if ( (ret == 0) && (l1e_get_flags(l1e) & _PAGE_PRESENT) )
        return _mfn(l1e_get_pfn(l1e));

    return _mfn(INVALID_MFN);
}

/* Read another domain's P2M table, mapping pages as we go */
mfn_t sh_gfn_to_mfn_foreign(struct domain *d, unsigned long gpfn);

/* General conversion function from gfn to mfn */
static inline mfn_t
sh_gfn_to_mfn(struct domain *d, unsigned long gfn)
{
    if ( !shadow_mode_translate(d) )
        return _mfn(gfn);
    if ( likely(current->domain == d) )
        return sh_gfn_to_mfn_current(gfn);
    else 
        return sh_gfn_to_mfn_foreign(d, gfn);
}

/* Compatibility function for HVM code */
static inline unsigned long get_mfn_from_gpfn(unsigned long pfn)
{
    return mfn_x(sh_gfn_to_mfn_current(pfn));
}

/* General conversion function from mfn to gfn */
static inline unsigned long
sh_mfn_to_gfn(struct domain *d, mfn_t mfn)
{
    if ( shadow_mode_translate(d) )
        return get_gpfn_from_mfn(mfn_x(mfn));
    else
        return mfn_x(mfn);
}

/* Is this guest address an mmio one? (i.e. not defined in p2m map) */
static inline int
mmio_space(paddr_t gpa)
{
    unsigned long gfn = gpa >> PAGE_SHIFT;    
    return !mfn_valid(mfn_x(sh_gfn_to_mfn_current(gfn)));
}

/* Translate the frame number held in an l1e from guest to machine */
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
