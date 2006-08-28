/******************************************************************************
 * arch/x86/mm/shadow/common.c
 *
 * Shadow code that does not need to be multiply compiled.
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

#define SHADOW 1

#include <xen/config.h>
#include <xen/types.h>
#include <xen/mm.h>
#include <xen/trace.h>
#include <xen/sched.h>
#include <xen/perfc.h>
#include <xen/irq.h>
#include <xen/domain_page.h>
#include <xen/guest_access.h>
#include <xen/keyhandler.h>
#include <asm/event.h>
#include <asm/page.h>
#include <asm/current.h>
#include <asm/flushtlb.h>
#include <asm/shadow.h>
#include "private.h"

#if SHADOW_AUDIT
int shadow_audit_enable = 0;

static void shadow_audit_key(unsigned char key)
{
    shadow_audit_enable = !shadow_audit_enable;
    printk("%s shadow_audit_enable=%d\n",
           __func__, shadow_audit_enable);
}

static int __init shadow_audit_key_init(void)
{
    register_keyhandler(
        'O', shadow_audit_key,  "toggle shadow audits");
    return 0;
}
__initcall(shadow_audit_key_init);
#endif /* SHADOW_AUDIT */

static void sh_free_log_dirty_bitmap(struct domain *d);

int _shadow_mode_refcounts(struct domain *d)
{
    return shadow_mode_refcounts(d);
}


/**************************************************************************/
/* x86 emulator support for the shadow code
 */

static int
sh_x86_emulate_read_std(unsigned long addr,
                         unsigned long *val,
                         unsigned int bytes,
                         struct x86_emulate_ctxt *ctxt)
{
    struct vcpu *v = current;
    if ( hvm_guest(v) )
    {
        *val = 0;
        // XXX -- this is WRONG.
        //        It entirely ignores the permissions in the page tables.
        //        In this case, that is only a user vs supervisor access check.
        //
        if ( hvm_copy(val, addr, bytes, HVM_COPY_IN) )
        {
#if 0
            SHADOW_PRINTK("d=%u v=%u a=%#lx v=%#lx bytes=%u\n",
                           v->domain->domain_id, v->vcpu_id, 
                           addr, *val, bytes);
#endif
            return X86EMUL_CONTINUE;
        }

        /* If we got here, there was nothing mapped here, or a bad GFN 
         * was mapped here.  This should never happen: we're here because
         * of a write fault at the end of the instruction we're emulating. */ 
        SHADOW_PRINTK("read failed to va %#lx\n", addr);
        return X86EMUL_PROPAGATE_FAULT;
    }
    else 
    {
        SHADOW_PRINTK("this operation is not emulated yet\n");
        return X86EMUL_UNHANDLEABLE;
    }
}

static int
sh_x86_emulate_write_std(unsigned long addr,
                          unsigned long val,
                          unsigned int bytes,
                          struct x86_emulate_ctxt *ctxt)
{
    struct vcpu *v = current;
#if 0
    SHADOW_PRINTK("d=%u v=%u a=%#lx v=%#lx bytes=%u\n",
                  v->domain->domain_id, v->vcpu_id, addr, val, bytes);
#endif
    if ( hvm_guest(v) )
    {
        // XXX -- this is WRONG.
        //        It entirely ignores the permissions in the page tables.
        //        In this case, that includes user vs supervisor, and
        //        write access.
        //
        if ( hvm_copy(&val, addr, bytes, HVM_COPY_OUT) )
            return X86EMUL_CONTINUE;

        /* If we got here, there was nothing mapped here, or a bad GFN 
         * was mapped here.  This should never happen: we're here because
         * of a write fault at the end of the instruction we're emulating,
         * which should be handled by sh_x86_emulate_write_emulated. */ 
        SHADOW_PRINTK("write failed to va %#lx\n", addr);
        return X86EMUL_PROPAGATE_FAULT;
    }
    else 
    {
        SHADOW_PRINTK("this operation is not emulated yet\n");
        return X86EMUL_UNHANDLEABLE;
    }
}

static int
sh_x86_emulate_write_emulated(unsigned long addr,
                               unsigned long val,
                               unsigned int bytes,
                               struct x86_emulate_ctxt *ctxt)
{
    struct vcpu *v = current;
#if 0
    SHADOW_PRINTK("d=%u v=%u a=%#lx v=%#lx bytes=%u\n",
                  v->domain->domain_id, v->vcpu_id, addr, val, bytes);
#endif
    if ( hvm_guest(v) )
    {
        return v->arch.shadow.mode->x86_emulate_write(v, addr, &val, bytes, ctxt);
    }
    else 
    {
        SHADOW_PRINTK("this operation is not emulated yet\n");
        return X86EMUL_UNHANDLEABLE;
    }
}

static int 
sh_x86_emulate_cmpxchg_emulated(unsigned long addr,
                                 unsigned long old,
                                 unsigned long new,
                                 unsigned int bytes,
                                 struct x86_emulate_ctxt *ctxt)
{
    struct vcpu *v = current;
#if 0
    SHADOW_PRINTK("d=%u v=%u a=%#lx o?=%#lx n:=%#lx bytes=%u\n",
                   v->domain->domain_id, v->vcpu_id, addr, old, new, bytes);
#endif
    if ( hvm_guest(v) )
    {
        return v->arch.shadow.mode->x86_emulate_cmpxchg(v, addr, old, new, 
                                                    bytes, ctxt);
    }
    else 
    {
        SHADOW_PRINTK("this operation is not emulated yet\n");
        return X86EMUL_UNHANDLEABLE;
    }
}

static int 
sh_x86_emulate_cmpxchg8b_emulated(unsigned long addr,
                                   unsigned long old_lo,
                                   unsigned long old_hi,
                                   unsigned long new_lo,
                                   unsigned long new_hi,
                                   struct x86_emulate_ctxt *ctxt)
{
    struct vcpu *v = current;
#if 0
    SHADOW_PRINTK("d=%u v=%u a=%#lx o?=%#lx:%lx n:=%#lx:%lx\n",
                   v->domain->domain_id, v->vcpu_id, addr, old_hi, old_lo,
                   new_hi, new_lo, ctxt);
#endif
    if ( hvm_guest(v) )
    {
        return v->arch.shadow.mode->x86_emulate_cmpxchg8b(v, addr, old_lo, old_hi,
                                                      new_lo, new_hi, ctxt);
    }
    else 
    {
        SHADOW_PRINTK("this operation is not emulated yet\n");
        return X86EMUL_UNHANDLEABLE;
    }
}


struct x86_emulate_ops shadow_emulator_ops = {
    .read_std           = sh_x86_emulate_read_std,
    .write_std          = sh_x86_emulate_write_std,
    .read_emulated      = sh_x86_emulate_read_std,
    .write_emulated     = sh_x86_emulate_write_emulated,
    .cmpxchg_emulated   = sh_x86_emulate_cmpxchg_emulated,
    .cmpxchg8b_emulated = sh_x86_emulate_cmpxchg8b_emulated,
};


/**************************************************************************/
/* Code for "promoting" a guest page to the point where the shadow code is
 * willing to let it be treated as a guest page table.  This generally
 * involves making sure there are no writable mappings available to the guest
 * for this page.
 */
void shadow_promote(struct vcpu *v, mfn_t gmfn, u32 type)
{
    struct page_info *page = mfn_to_page(gmfn);
    unsigned long type_info;

    ASSERT(valid_mfn(gmfn));

    /* We should never try to promote a gmfn that has writeable mappings */
    ASSERT(shadow_remove_write_access(v, gmfn, 0, 0) == 0);

    // Is the page already shadowed?
    if ( !test_and_set_bit(_PGC_page_table, &page->count_info) )
    {
        // No prior shadow exists...

        // Grab a type-ref.  We don't really care if we are racing with another
        // vcpu or not, or even what kind of type we get; we just want the type
        // count to be > 0.
        //
        do {
            type_info =
                page->u.inuse.type_info & (PGT_type_mask | PGT_va_mask);
        } while ( !get_page_type(page, type_info) );

        // Now that the type ref is non-zero, we can safely use the
        // shadow_flags.
        //
        page->shadow_flags = 0;
    }

    ASSERT(!test_bit(type >> PGC_SH_type_shift, &page->shadow_flags));
    set_bit(type >> PGC_SH_type_shift, &page->shadow_flags);
}

void shadow_demote(struct vcpu *v, mfn_t gmfn, u32 type)
{
    struct page_info *page = mfn_to_page(gmfn);

    ASSERT(test_bit(_PGC_page_table, &page->count_info));
    ASSERT(test_bit(type >> PGC_SH_type_shift, &page->shadow_flags));

    clear_bit(type >> PGC_SH_type_shift, &page->shadow_flags);

    if ( (page->shadow_flags & SHF_page_type_mask) == 0 )
    {
        // release the extra type ref
        put_page_type(page);

        // clear the is-a-page-table bit.
        clear_bit(_PGC_page_table, &page->count_info);
    }
}

/**************************************************************************/
/* Validate a pagetable change from the guest and update the shadows.
 * Returns a bitmask of SHADOW_SET_* flags. */

static int
__shadow_validate_guest_entry(struct vcpu *v, mfn_t gmfn, 
                               void *entry, u32 size)
{
    int result = 0;
    struct page_info *page = mfn_to_page(gmfn);

    sh_mark_dirty(v->domain, gmfn);
    
    // Determine which types of shadows are affected, and update each.
    //
    // Always validate L1s before L2s to prevent another cpu with a linear
    // mapping of this gmfn from seeing a walk that results from 
    // using the new L2 value and the old L1 value.  (It is OK for such a
    // guest to see a walk that uses the old L2 value with the new L1 value,
    // as hardware could behave this way if one level of the pagewalk occurs
    // before the store, and the next level of the pagewalk occurs after the
    // store.
    //
    // Ditto for L2s before L3s, etc.
    //

    if ( !(page->count_info & PGC_page_table) )
        return 0;  /* Not shadowed at all */

#if CONFIG_PAGING_LEVELS == 2
    if ( page->shadow_flags & SHF_L1_32 ) 
        result |= SHADOW_INTERNAL_NAME(sh_map_and_validate_gl1e, 2, 2)
            (v, gmfn, entry, size);
#else 
    if ( page->shadow_flags & SHF_L1_32 ) 
        result |= SHADOW_INTERNAL_NAME(sh_map_and_validate_gl1e, 3, 2)
            (v, gmfn, entry, size);
#endif

#if CONFIG_PAGING_LEVELS == 2
    if ( page->shadow_flags & SHF_L2_32 ) 
        result |= SHADOW_INTERNAL_NAME(sh_map_and_validate_gl2e, 2, 2)
            (v, gmfn, entry, size);
#else 
    if ( page->shadow_flags & SHF_L2_32 ) 
        result |= SHADOW_INTERNAL_NAME(sh_map_and_validate_gl2e, 3, 2)
            (v, gmfn, entry, size);
#endif

#if CONFIG_PAGING_LEVELS >= 3 
    if ( page->shadow_flags & SHF_L1_PAE ) 
        result |= SHADOW_INTERNAL_NAME(sh_map_and_validate_gl1e, 3, 3)
            (v, gmfn, entry, size);
    if ( page->shadow_flags & SHF_L2_PAE ) 
        result |= SHADOW_INTERNAL_NAME(sh_map_and_validate_gl2e, 3, 3)
            (v, gmfn, entry, size);
    if ( page->shadow_flags & SHF_L2H_PAE ) 
        result |= SHADOW_INTERNAL_NAME(sh_map_and_validate_gl2he, 3, 3)
            (v, gmfn, entry, size);
    if ( page->shadow_flags & SHF_L3_PAE ) 
        result |= SHADOW_INTERNAL_NAME(sh_map_and_validate_gl3e, 3, 3)
            (v, gmfn, entry, size);
#else /* 32-bit non-PAE hypervisor does not support PAE guests */
    ASSERT((page->shadow_flags & (SHF_L3_PAE|SHF_L2_PAE|SHF_L1_PAE)) == 0);
#endif

#if CONFIG_PAGING_LEVELS >= 4 
    if ( page->shadow_flags & SHF_L1_64 ) 
        result |= SHADOW_INTERNAL_NAME(sh_map_and_validate_gl1e, 4, 4)
            (v, gmfn, entry, size);
    if ( page->shadow_flags & SHF_L2_64 ) 
        result |= SHADOW_INTERNAL_NAME(sh_map_and_validate_gl2e, 4, 4)
            (v, gmfn, entry, size);
    if ( page->shadow_flags & SHF_L3_64 ) 
        result |= SHADOW_INTERNAL_NAME(sh_map_and_validate_gl3e, 4, 4)
            (v, gmfn, entry, size);
    if ( page->shadow_flags & SHF_L4_64 ) 
        result |= SHADOW_INTERNAL_NAME(sh_map_and_validate_gl4e, 4, 4)
            (v, gmfn, entry, size);
#else /* 32-bit/PAE hypervisor does not support 64-bit guests */
    ASSERT((page->shadow_flags 
            & (SHF_L4_64|SHF_L3_64|SHF_L2_64|SHF_L1_64)) == 0);
#endif

    return result;
}


int
shadow_validate_guest_entry(struct vcpu *v, mfn_t gmfn, void *entry)
/* This is the entry point from hypercalls. It returns a bitmask of all the 
 * results of shadow_set_l*e() calls, so the caller knows to do TLB flushes. */
{
    int rc;

    ASSERT(shadow_lock_is_acquired(v->domain));
    rc = __shadow_validate_guest_entry(v, gmfn, entry, sizeof(l1_pgentry_t));
    shadow_audit_tables(v);
    return rc;
}

void
shadow_validate_guest_pt_write(struct vcpu *v, mfn_t gmfn,
                                void *entry, u32 size)
/* This is the entry point for emulated writes to pagetables in HVM guests */
{
    struct domain *d = v->domain;
    int rc;

    ASSERT(shadow_lock_is_acquired(v->domain));
    rc = __shadow_validate_guest_entry(v, gmfn, entry, size);
    if ( rc & SHADOW_SET_FLUSH )
    {
        // Flush everyone except the local processor, which will flush when it
        // re-enters the HVM guest.
        //
        cpumask_t mask = d->domain_dirty_cpumask;
        cpu_clear(v->processor, mask);
        flush_tlb_mask(mask);
    }
    if ( rc & SHADOW_SET_ERROR ) 
    {
        /* This page is probably not a pagetable any more: tear it out of the 
         * shadows, along with any tables that reference it */
        shadow_remove_all_shadows_and_parents(v, gmfn);
    }
    /* We ignore the other bits: since we are about to change CR3 on
     * VMENTER we don't need to do any extra TLB flushes. */ 
}


/**************************************************************************/
/* Memory management for shadow pages. */ 

/* Meaning of the count_info field in shadow pages
 * ----------------------------------------------
 * 
 * A count of all references to this page from other shadow pages and
 * guest CR3s (a.k.a. v->arch.shadow.table).  
 *
 * The top bits hold the shadow type and the pinned bit.  Top-level
 * shadows are pinned so that they don't disappear when not in a CR3
 * somewhere.
 *
 * We don't need to use get|put_page for this as the updates are all
 * protected by the shadow lock.  We can't use get|put_page for this
 * as the size of the count on shadow pages is different from that on
 * normal guest pages.
 */

/* Meaning of the type_info field in shadow pages
 * ----------------------------------------------
 * 
 * type_info use depends on the shadow type (from count_info)
 * 
 * PGC_SH_none : This page is in the shadow free pool.  type_info holds
 *                the chunk order for our freelist allocator.
 *
 * PGC_SH_l*_shadow : This page is in use as a shadow. type_info 
 *                     holds the mfn of the guest page being shadowed,
 *
 * PGC_SH_fl1_*_shadow : This page is being used to shatter a superpage.
 *                        type_info holds the gfn being shattered.
 *
 * PGC_SH_monitor_table : This page is part of a monitor table.
 *                         type_info is not used.
 */

/* Meaning of the _domain field in shadow pages
 * --------------------------------------------
 *
 * In shadow pages, this field will always have its least significant bit
 * set.  This ensures that all attempts to get_page() will fail (as all
 * valid pickled domain pointers have a zero for their least significant bit).
 * Instead, the remaining upper bits are used to record the shadow generation
 * counter when the shadow was created.
 */

/* Meaning of the shadow_flags field
 * ----------------------------------
 * 
 * In guest pages that are shadowed, one bit for each kind of shadow they have.
 * 
 * In shadow pages, will be used for holding a representation of the populated
 * entries in this shadow (either a min/max, or a bitmap, or ...)
 *
 * In monitor-table pages, holds the level of the particular page (to save
 * spilling the shadow types into an extra bit by having three types of monitor
 * page).
 */

/* Meaning of the list_head struct in shadow pages
 * -----------------------------------------------
 *
 * In free shadow pages, this is used to hold the free-lists of chunks.
 *
 * In top-level shadow tables, this holds a linked-list of all top-level
 * shadows (used for recovering memory and destroying shadows). 
 *
 * In lower-level shadows, this holds the physical address of a higher-level
 * shadow entry that holds a reference to this shadow (or zero).
 */

/* Allocating shadow pages
 * -----------------------
 *
 * Most shadow pages are allocated singly, but there are two cases where we 
 * need to allocate multiple pages together.
 * 
 * 1: Shadowing 32-bit guest tables on PAE or 64-bit shadows.
 *    A 32-bit guest l1 table covers 4MB of virtuial address space,
 *    and needs to be shadowed by two PAE/64-bit l1 tables (covering 2MB
 *    of virtual address space each).  Similarly, a 32-bit guest l2 table 
 *    (4GB va) needs to be shadowed by four PAE/64-bit l2 tables (1GB va 
 *    each).  These multi-page shadows are contiguous and aligned; 
 *    functions for handling offsets into them are defined in shadow.c 
 *    (shadow_l1_index() etc.)
 *    
 * 2: Shadowing PAE top-level pages.  Each guest page that contains
 *    any PAE top-level pages requires two shadow pages to shadow it.
 *    They contain alternating l3 tables and pae_l3_bookkeeping structs.
 *
 * This table shows the allocation behaviour of the different modes:
 *
 * Xen paging      32b  pae  pae  64b  64b  64b
 * Guest paging    32b  32b  pae  32b  pae  64b
 * PV or HVM        *   HVM   *   HVM  HVM   * 
 * Shadow paging   32b  pae  pae  pae  pae  64b
 *
 * sl1 size         4k   8k   4k   8k   4k   4k
 * sl2 size         4k  16k   4k  16k   4k   4k
 * sl3 size         -    -    8k   -    8k   4k
 * sl4 size         -    -    -    -    -    4k
 *
 * We allocate memory from xen in four-page units and break them down
 * with a simple buddy allocator.  Can't use the xen allocator to handle
 * this as it only works for contiguous zones, and a domain's shadow
 * pool is made of fragments.
 *
 * In HVM guests, the p2m table is built out of shadow pages, and we provide 
 * a function for the p2m management to steal pages, in max-order chunks, from 
 * the free pool.  We don't provide for giving them back, yet.
 */

/* Figure out the least acceptable quantity of shadow memory.
 * The minimum memory requirement for always being able to free up a
 * chunk of memory is very small -- only three max-order chunks per
 * vcpu to hold the top level shadows and pages with Xen mappings in them.  
 *
 * But for a guest to be guaranteed to successfully execute a single
 * instruction, we must be able to map a large number (about thirty) VAs
 * at the same time, which means that to guarantee progress, we must
 * allow for more than ninety allocated pages per vcpu.  We round that
 * up to 128 pages, or half a megabyte per vcpu. */
unsigned int shadow_min_acceptable_pages(struct domain *d) 
{
    u32 vcpu_count = 0;
    struct vcpu *v;

    for_each_vcpu(d, v)
        vcpu_count++;

    return (vcpu_count * 128);
}

/* Using the type_info field to store freelist order */
#define SH_PFN_ORDER(_p) ((_p)->u.inuse.type_info)
#define SH_SET_PFN_ORDER(_p, _o)                       \
 do { (_p)->u.inuse.type_info = (_o); } while (0)
 

/* Figure out the order of allocation needed for a given shadow type */
static inline u32
shadow_order(u32 shadow_type) 
{
#if CONFIG_PAGING_LEVELS > 2
    static const u32 type_to_order[16] = {
        0, /* PGC_SH_none           */
        1, /* PGC_SH_l1_32_shadow   */
        1, /* PGC_SH_fl1_32_shadow  */
        2, /* PGC_SH_l2_32_shadow   */
        0, /* PGC_SH_l1_pae_shadow  */
        0, /* PGC_SH_fl1_pae_shadow */
        0, /* PGC_SH_l2_pae_shadow  */
        0, /* PGC_SH_l2h_pae_shadow */
        1, /* PGC_SH_l3_pae_shadow  */
        0, /* PGC_SH_l1_64_shadow   */
        0, /* PGC_SH_fl1_64_shadow  */
        0, /* PGC_SH_l2_64_shadow   */
        0, /* PGC_SH_l3_64_shadow   */
        0, /* PGC_SH_l4_64_shadow   */
        2, /* PGC_SH_p2m_table      */
        0  /* PGC_SH_monitor_table  */
        };
    u32 type = (shadow_type & PGC_SH_type_mask) >> PGC_SH_type_shift;
    return type_to_order[type];
#else  /* 32-bit Xen only ever shadows 32-bit guests on 32-bit shadows. */
    return 0;
#endif
}


/* Do we have a free chunk of at least this order? */
static inline int chunk_is_available(struct domain *d, int order)
{
    int i;
    
    for ( i = order; i <= SHADOW_MAX_ORDER; i++ )
        if ( !list_empty(&d->arch.shadow.freelists[i]) )
            return 1;
    return 0;
}

/* Dispatcher function: call the per-mode function that will unhook the
 * non-Xen mappings in this top-level shadow mfn */
void shadow_unhook_mappings(struct vcpu *v, mfn_t smfn)
{
    struct page_info *pg = mfn_to_page(smfn);
    switch ( (pg->count_info & PGC_SH_type_mask) >> PGC_SH_type_shift )
    {
    case PGC_SH_l2_32_shadow >> PGC_SH_type_shift:
#if CONFIG_PAGING_LEVELS == 2
        SHADOW_INTERNAL_NAME(sh_unhook_32b_mappings,2,2)(v,smfn);
#else
        SHADOW_INTERNAL_NAME(sh_unhook_32b_mappings,3,2)(v,smfn);
#endif
        break;
#if CONFIG_PAGING_LEVELS >= 3
    case PGC_SH_l3_pae_shadow >> PGC_SH_type_shift:
        SHADOW_INTERNAL_NAME(sh_unhook_pae_mappings,3,3)(v,smfn);
        break;
#endif
#if CONFIG_PAGING_LEVELS >= 4
    case PGC_SH_l4_64_shadow >> PGC_SH_type_shift:
        SHADOW_INTERNAL_NAME(sh_unhook_64b_mappings,4,4)(v,smfn);
        break;
#endif
    default:
        SHADOW_PRINTK("top-level shadow has bad type %08lx\n", 
                       (unsigned long)((pg->count_info & PGC_SH_type_mask)
                                       >> PGC_SH_type_shift));
        BUG();
    }
}


/* Make sure there is at least one chunk of the required order available
 * in the shadow page pool. This must be called before any calls to
 * shadow_alloc().  Since this will free existing shadows to make room,
 * it must be called early enough to avoid freeing shadows that the
 * caller is currently working on. */
void shadow_prealloc(struct domain *d, unsigned int order)
{
    /* Need a vpcu for calling unpins; for now, since we don't have
     * per-vcpu shadows, any will do */
    struct vcpu *v = d->vcpu[0];
    struct list_head *l, *t;
    struct page_info *pg;
    mfn_t smfn;

    if ( chunk_is_available(d, order) ) return; 
    
    /* Stage one: walk the list of top-level pages, unpinning them */
    perfc_incrc(shadow_prealloc_1);
    list_for_each_backwards_safe(l, t, &d->arch.shadow.toplevel_shadows)
    {
        pg = list_entry(l, struct page_info, list);
        smfn = page_to_mfn(pg);

#if CONFIG_PAGING_LEVELS >= 3
        if ( (pg->count_info & PGC_SH_type_mask) == PGC_SH_l3_pae_shadow )
        {
            /* For PAE, we need to unpin each subshadow on this shadow */
            SHADOW_INTERNAL_NAME(sh_unpin_all_l3_subshadows,3,3)(v, smfn);
        } 
        else 
#endif /* 32-bit code always takes this branch */
        {
            /* Unpin this top-level shadow */
            sh_unpin(v, smfn);
        }

        /* See if that freed up a chunk of appropriate size */
        if ( chunk_is_available(d, order) ) return;
    }

    /* Stage two: all shadow pages are in use in hierarchies that are
     * loaded in cr3 on some vcpu.  Walk them, unhooking the non-Xen
     * mappings. */
    perfc_incrc(shadow_prealloc_2);
    v = current;
    if ( v->domain != d )
        v = d->vcpu[0];
    /* Walk the list from the tail: recently used toplevels have been pulled
     * to the head */
    list_for_each_backwards_safe(l, t, &d->arch.shadow.toplevel_shadows)
    {
        pg = list_entry(l, struct page_info, list);
        smfn = page_to_mfn(pg);
        shadow_unhook_mappings(v, smfn);

        /* Need to flush TLB if we've altered our own tables */
        if ( !shadow_mode_external(d) 
             && pagetable_get_pfn(current->arch.shadow_table) == mfn_x(smfn) )
            local_flush_tlb();
        
        /* See if that freed up a chunk of appropriate size */
        if ( chunk_is_available(d, order) ) return;
    }
    
    /* Nothing more we can do: all remaining shadows are of pages that
     * hold Xen mappings for some vcpu.  This can never happen. */
    SHADOW_PRINTK("Can't pre-allocate %i shadow pages!\n"
                   "  shadow pages total = %u, free = %u, p2m=%u\n",
                   1 << order, 
                   d->arch.shadow.total_pages, 
                   d->arch.shadow.free_pages, 
                   d->arch.shadow.p2m_pages);
    BUG();
}


/* Allocate another shadow's worth of (contiguous, aligned) pages,
 * and fill in the type and backpointer fields of their page_infos. 
 * Never fails to allocate. */
mfn_t shadow_alloc(struct domain *d,  
                    u32 shadow_type,
                    unsigned long backpointer)
{
    struct page_info *pg = NULL;
    unsigned int order = shadow_order(shadow_type);
    cpumask_t mask;
    void *p;
    int i;

    ASSERT(shadow_lock_is_acquired(d));
    ASSERT(order <= SHADOW_MAX_ORDER);
    ASSERT(shadow_type != PGC_SH_none);
    perfc_incrc(shadow_alloc);

    /* Find smallest order which can satisfy the request. */
    for ( i = order; i <= SHADOW_MAX_ORDER; i++ )
        if ( !list_empty(&d->arch.shadow.freelists[i]) )
        {
            pg = list_entry(d->arch.shadow.freelists[i].next, 
                            struct page_info, list);
            list_del(&pg->list);
            
            /* We may have to halve the chunk a number of times. */
            while ( i != order )
            {
                i--;
                SH_SET_PFN_ORDER(pg, i);
                list_add_tail(&pg->list, &d->arch.shadow.freelists[i]);
                pg += 1 << i;
            }
            d->arch.shadow.free_pages -= 1 << order;

            /* Init page info fields and clear the pages */
            for ( i = 0; i < 1<<order ; i++ ) 
            {
                pg[i].u.inuse.type_info = backpointer;
                pg[i].count_info = shadow_type;
                pg[i].shadow_flags = 0;
                INIT_LIST_HEAD(&pg[i].list);
                /* Before we overwrite the old contents of this page, 
                 * we need to be sure that no TLB holds a pointer to it. */
                mask = d->domain_dirty_cpumask;
                tlbflush_filter(mask, pg[i].tlbflush_timestamp);
                if ( unlikely(!cpus_empty(mask)) )
                {
                    perfc_incrc(shadow_alloc_tlbflush);
                    flush_tlb_mask(mask);
                }
                /* Now safe to clear the page for reuse */
                p = sh_map_domain_page(page_to_mfn(pg+i));
                ASSERT(p != NULL);
                clear_page(p);
                sh_unmap_domain_page(p);
                perfc_incr(shadow_alloc_count);
            }
            return page_to_mfn(pg);
        }
    
    /* If we get here, we failed to allocate. This should never happen.
     * It means that we didn't call shadow_prealloc() correctly before
     * we allocated.  We can't recover by calling prealloc here, because
     * we might free up higher-level pages that the caller is working on. */
    SHADOW_PRINTK("Can't allocate %i shadow pages!\n", 1 << order);
    BUG();
}


/* Return some shadow pages to the pool. */
void shadow_free(struct domain *d, mfn_t smfn)
{
    struct page_info *pg = mfn_to_page(smfn); 
    u32 shadow_type;
    unsigned long order;
    unsigned long mask;
    int i;

    ASSERT(shadow_lock_is_acquired(d));
    perfc_incrc(shadow_free);

    shadow_type = pg->count_info & PGC_SH_type_mask;
    ASSERT(shadow_type != PGC_SH_none);
    ASSERT(shadow_type != PGC_SH_p2m_table);
    order = shadow_order(shadow_type);

    d->arch.shadow.free_pages += 1 << order;

    for ( i = 0; i < 1<<order; i++ ) 
    {
        /* Strip out the type: this is now a free shadow page */
        pg[i].count_info = 0;
        /* Remember the TLB timestamp so we will know whether to flush 
         * TLBs when we reuse the page.  Because the destructors leave the
         * contents of the pages in place, we can delay TLB flushes until
         * just before the allocator hands the page out again. */
        pg[i].tlbflush_timestamp = tlbflush_current_time();
        perfc_decr(shadow_alloc_count);
    }

    /* Merge chunks as far as possible. */
    while ( order < SHADOW_MAX_ORDER )
    {
        mask = 1 << order;
        if ( (mfn_x(page_to_mfn(pg)) & mask) ) {
            /* Merge with predecessor block? */
            if ( (((pg-mask)->count_info & PGC_SH_type_mask) != PGT_none) 
                 || (SH_PFN_ORDER(pg-mask) != order) )
                break;
            list_del(&(pg-mask)->list);
            pg -= mask;
        } else {
            /* Merge with successor block? */
            if ( (((pg+mask)->count_info & PGC_SH_type_mask) != PGT_none)
                 || (SH_PFN_ORDER(pg+mask) != order) )
                break;
            list_del(&(pg+mask)->list);
        }
        order++;
    }

    SH_SET_PFN_ORDER(pg, order);
    list_add_tail(&pg->list, &d->arch.shadow.freelists[order]);
}

/* Divert some memory from the pool to be used by the p2m mapping.
 * This action is irreversible: the p2m mapping only ever grows.
 * That's OK because the p2m table only exists for external domains,
 * and those domains can't ever turn off shadow mode.
 * Also, we only ever allocate a max-order chunk, so as to preserve
 * the invariant that shadow_prealloc() always works.
 * Returns 0 iff it can't get a chunk (the caller should then
 * free up some pages in domheap and call set_sh_allocation);
 * returns non-zero on success.
 */
static int
shadow_alloc_p2m_pages(struct domain *d)
{
    struct page_info *pg;
    u32 i;
    ASSERT(shadow_lock_is_acquired(d));
    
    if ( d->arch.shadow.total_pages 
         < (shadow_min_acceptable_pages(d) + (1<<SHADOW_MAX_ORDER)) )
        return 0; /* Not enough shadow memory: need to increase it first */
    
    pg = mfn_to_page(shadow_alloc(d, PGC_SH_p2m_table, 0));
    d->arch.shadow.p2m_pages += (1<<SHADOW_MAX_ORDER);
    d->arch.shadow.total_pages -= (1<<SHADOW_MAX_ORDER);
    for (i = 0; i < (1<<SHADOW_MAX_ORDER); i++)
    {
        /* Unlike shadow pages, mark p2m pages as owned by the domain */
        page_set_owner(&pg[i], d);
        list_add_tail(&pg[i].list, &d->arch.shadow.p2m_freelist);
    }
    return 1;
}

// Returns 0 if no memory is available...
mfn_t
shadow_alloc_p2m_page(struct domain *d)
{
    struct list_head *entry;
    mfn_t mfn;
    void *p;

    if ( list_empty(&d->arch.shadow.p2m_freelist) &&
         !shadow_alloc_p2m_pages(d) )
        return _mfn(0);
    entry = d->arch.shadow.p2m_freelist.next;
    list_del(entry);
    list_add_tail(entry, &d->arch.shadow.p2m_inuse);
    mfn = page_to_mfn(list_entry(entry, struct page_info, list));
    sh_get_ref(mfn, 0);
    p = sh_map_domain_page(mfn);
    clear_page(p);
    sh_unmap_domain_page(p);

    return mfn;
}

#if CONFIG_PAGING_LEVELS == 3
static void p2m_install_entry_in_monitors(struct domain *d, 
                                          l3_pgentry_t *l3e) 
/* Special case, only used for external-mode domains on PAE hosts:
 * update the mapping of the p2m table.  Once again, this is trivial in
 * other paging modes (one top-level entry points to the top-level p2m,
 * no maintenance needed), but PAE makes life difficult by needing a
 * copy the eight l3es of the p2m table in eight l2h slots in the
 * monitor table.  This function makes fresh copies when a p2m l3e
 * changes. */
{
    l2_pgentry_t *ml2e;
    struct vcpu *v;
    unsigned int index;

    index = ((unsigned long)l3e & ~PAGE_MASK) / sizeof(l3_pgentry_t);
    ASSERT(index < MACHPHYS_MBYTES>>1);

    for_each_vcpu(d, v) 
    {
        if ( pagetable_get_pfn(v->arch.monitor_table) == 0 ) 
            continue;
        ASSERT(shadow_mode_external(v->domain));

        SHADOW_DEBUG(P2M, "d=%u v=%u index=%u mfn=%#lx\n",
                      d->domain_id, v->vcpu_id, index, l3e_get_pfn(*l3e));

        if ( v == current ) /* OK to use linear map of monitor_table */
            ml2e = __linear_l2_table + l2_linear_offset(RO_MPT_VIRT_START);
        else 
        {
            l3_pgentry_t *ml3e;
            ml3e = sh_map_domain_page(pagetable_get_mfn(v->arch.monitor_table));
            ASSERT(l3e_get_flags(ml3e[3]) & _PAGE_PRESENT);
            ml2e = sh_map_domain_page(_mfn(l3e_get_pfn(ml3e[3])));
            ml2e += l2_table_offset(RO_MPT_VIRT_START);
            sh_unmap_domain_page(ml3e);
        }
        ml2e[index] = l2e_from_pfn(l3e_get_pfn(*l3e), __PAGE_HYPERVISOR);
        if ( v != current )
            sh_unmap_domain_page(ml2e);
    }
}
#endif

// Find the next level's P2M entry, checking for out-of-range gfn's...
// Returns NULL on error.
//
static l1_pgentry_t *
p2m_find_entry(void *table, unsigned long *gfn_remainder,
                   unsigned long gfn, u32 shift, u32 max)
{
    u32 index;

    index = *gfn_remainder >> shift;
    if ( index >= max )
    {
        SHADOW_DEBUG(P2M, "gfn=0x%lx out of range "
                      "(gfn_remainder=0x%lx shift=%d index=0x%x max=0x%x)\n",
                       gfn, *gfn_remainder, shift, index, max);
        return NULL;
    }
    *gfn_remainder &= (1 << shift) - 1;
    return (l1_pgentry_t *)table + index;
}

// Walk one level of the P2M table, allocating a new table if required.
// Returns 0 on error.
//
static int
p2m_next_level(struct domain *d, mfn_t *table_mfn, void **table, 
               unsigned long *gfn_remainder, unsigned long gfn, u32 shift, 
               u32 max, unsigned long type)
{
    l1_pgentry_t *p2m_entry;
    void *next;

    if ( !(p2m_entry = p2m_find_entry(*table, gfn_remainder, gfn,
                                      shift, max)) )
        return 0;

    if ( !(l1e_get_flags(*p2m_entry) & _PAGE_PRESENT) )
    {
        mfn_t mfn = shadow_alloc_p2m_page(d);
        if ( mfn_x(mfn) == 0 )
            return 0;
        *p2m_entry = l1e_from_pfn(mfn_x(mfn), __PAGE_HYPERVISOR|_PAGE_USER);
        mfn_to_page(mfn)->u.inuse.type_info = type | 1 | PGT_validated;
        mfn_to_page(mfn)->count_info = 1;
#if CONFIG_PAGING_LEVELS == 3
        if (type == PGT_l2_page_table)
        {
            /* We have written to the p2m l3: need to sync the per-vcpu
             * copies of it in the monitor tables */
            p2m_install_entry_in_monitors(d, (l3_pgentry_t *)p2m_entry);
        }
#endif
        /* The P2M can be shadowed: keep the shadows synced */
        if ( d->vcpu[0] )
            (void)__shadow_validate_guest_entry(d->vcpu[0], *table_mfn,
                                                 p2m_entry, sizeof *p2m_entry);
    }
    *table_mfn = _mfn(l1e_get_pfn(*p2m_entry));
    next = sh_map_domain_page(*table_mfn);
    sh_unmap_domain_page(*table);
    *table = next;

    return 1;
}

// Returns 0 on error (out of memory)
int
shadow_set_p2m_entry(struct domain *d, unsigned long gfn, mfn_t mfn)
{
    // XXX -- this might be able to be faster iff current->domain == d
    mfn_t table_mfn = pagetable_get_mfn(d->arch.phys_table);
    void *table = sh_map_domain_page(table_mfn);
    unsigned long gfn_remainder = gfn;
    l1_pgentry_t *p2m_entry;

#if CONFIG_PAGING_LEVELS >= 4
    if ( !p2m_next_level(d, &table_mfn, &table, &gfn_remainder, gfn,
                         L4_PAGETABLE_SHIFT - PAGE_SHIFT,
                         L4_PAGETABLE_ENTRIES, PGT_l3_page_table) )
        return 0;
#endif
#if CONFIG_PAGING_LEVELS >= 3
    // When using PAE Xen, we only allow 33 bits of pseudo-physical
    // address in translated guests (i.e. 8 GBytes).  This restriction
    // comes from wanting to map the P2M table into the 16MB RO_MPT hole
    // in Xen's address space for translated PV guests.
    //
    if ( !p2m_next_level(d, &table_mfn, &table, &gfn_remainder, gfn,
                         L3_PAGETABLE_SHIFT - PAGE_SHIFT,
                         (CONFIG_PAGING_LEVELS == 3
                          ? 8
                          : L3_PAGETABLE_ENTRIES),
                         PGT_l2_page_table) )
        return 0;
#endif
    if ( !p2m_next_level(d, &table_mfn, &table, &gfn_remainder, gfn,
                         L2_PAGETABLE_SHIFT - PAGE_SHIFT,
                         L2_PAGETABLE_ENTRIES, PGT_l1_page_table) )
        return 0;

    p2m_entry = p2m_find_entry(table, &gfn_remainder, gfn,
                               0, L1_PAGETABLE_ENTRIES);
    ASSERT(p2m_entry);
    if ( valid_mfn(mfn) )
        *p2m_entry = l1e_from_pfn(mfn_x(mfn), __PAGE_HYPERVISOR|_PAGE_USER);
    else
        *p2m_entry = l1e_empty();

    /* The P2M can be shadowed: keep the shadows synced */
    (void) __shadow_validate_guest_entry(d->vcpu[0], table_mfn, 
                                          p2m_entry, sizeof *p2m_entry);

    sh_unmap_domain_page(table);

    return 1;
}

// Allocate a new p2m table for a domain.
//
// The structure of the p2m table is that of a pagetable for xen (i.e. it is
// controlled by CONFIG_PAGING_LEVELS).
//
// Returns 0 if p2m table could not be initialized
//
static int
shadow_alloc_p2m_table(struct domain *d)
{
    mfn_t p2m_top;
    struct list_head *entry;
    unsigned int page_count = 0;
    
    SHADOW_PRINTK("allocating p2m table\n");
    ASSERT(pagetable_get_pfn(d->arch.phys_table) == 0);

    p2m_top = shadow_alloc_p2m_page(d);
    mfn_to_page(p2m_top)->count_info = 1;
    mfn_to_page(p2m_top)->u.inuse.type_info = 
#if CONFIG_PAGING_LEVELS == 4
        PGT_l4_page_table
#elif CONFIG_PAGING_LEVELS == 3
        PGT_l3_page_table
#elif CONFIG_PAGING_LEVELS == 2
        PGT_l2_page_table
#endif
        | 1 | PGT_validated;
   
    if ( mfn_x(p2m_top) == 0 )
        return 0;

    d->arch.phys_table = pagetable_from_mfn(p2m_top);

    SHADOW_PRINTK("populating p2m table\n");
 
    for ( entry = d->page_list.next;
          entry != &d->page_list;
          entry = entry->next )
    {
        struct page_info *page = list_entry(entry, struct page_info, list);
        mfn_t mfn = page_to_mfn(page);
        unsigned long gfn = get_gpfn_from_mfn(mfn_x(mfn));
        page_count++;
        if (
#ifdef __x86_64__
            (gfn != 0x5555555555555555L)
#else
            (gfn != 0x55555555L)
#endif
             && gfn != INVALID_M2P_ENTRY
             && !shadow_set_p2m_entry(d, gfn, mfn) )
        {
            SHADOW_PRINTK("failed to initialize p2m table, gfn=%05lx, mfn=%" SH_PRI_mfn "\n",
                           gfn, mfn_x(mfn));
            return 0;
        }
    }

    SHADOW_PRINTK("p2m table initialised (%u pages)\n", page_count);
    return 1;
}

mfn_t
sh_gfn_to_mfn_foreign(struct domain *d, unsigned long gpfn)
/* Read another domain's p2m entries */
{
    mfn_t mfn;
    unsigned long addr = gpfn << PAGE_SHIFT;
    l2_pgentry_t *l2e;
    l1_pgentry_t *l1e;
    
    ASSERT(shadow_mode_translate(d));
    mfn = pagetable_get_mfn(d->arch.phys_table);


#if CONFIG_PAGING_LEVELS > 2
    if ( gpfn > (RO_MPT_VIRT_END - RO_MPT_VIRT_START) / sizeof(l1_pgentry_t) ) 
        /* This pfn is higher than the p2m map can hold */
        return _mfn(INVALID_MFN);
#endif


#if CONFIG_PAGING_LEVELS >= 4
    { 
        l4_pgentry_t *l4e = sh_map_domain_page(mfn);
        l4e += l4_table_offset(addr);
        if ( (l4e_get_flags(*l4e) & _PAGE_PRESENT) == 0 )
        {
            sh_unmap_domain_page(l4e);
            return _mfn(INVALID_MFN);
        }
        mfn = _mfn(l4e_get_pfn(*l4e));
        sh_unmap_domain_page(l4e);
    }
#endif
#if CONFIG_PAGING_LEVELS >= 3
    {
        l3_pgentry_t *l3e = sh_map_domain_page(mfn);
        l3e += l3_table_offset(addr);
        if ( (l3e_get_flags(*l3e) & _PAGE_PRESENT) == 0 )
        {
            sh_unmap_domain_page(l3e);
            return _mfn(INVALID_MFN);
        }
        mfn = _mfn(l3e_get_pfn(*l3e));
        sh_unmap_domain_page(l3e);
    }
#endif

    l2e = sh_map_domain_page(mfn);
    l2e += l2_table_offset(addr);
    if ( (l2e_get_flags(*l2e) & _PAGE_PRESENT) == 0 )
    {
        sh_unmap_domain_page(l2e);
        return _mfn(INVALID_MFN);
    }
    mfn = _mfn(l2e_get_pfn(*l2e));
    sh_unmap_domain_page(l2e);

    l1e = sh_map_domain_page(mfn);
    l1e += l1_table_offset(addr);
    if ( (l1e_get_flags(*l1e) & _PAGE_PRESENT) == 0 )
    {
        sh_unmap_domain_page(l1e);
        return _mfn(INVALID_MFN);
    }
    mfn = _mfn(l1e_get_pfn(*l1e));
    sh_unmap_domain_page(l1e);

    return mfn;
}

unsigned long
shadow_gfn_to_mfn_foreign(unsigned long gpfn)
{
    return mfn_x(sh_gfn_to_mfn_foreign(current->domain, gpfn));
}


static void shadow_p2m_teardown(struct domain *d)
/* Return all the p2m pages to Xen.
 * We know we don't have any extra mappings to these pages */
{
    struct list_head *entry, *n;
    struct page_info *pg;

    d->arch.phys_table = pagetable_null();

    list_for_each_safe(entry, n, &d->arch.shadow.p2m_inuse)
    {
        pg = list_entry(entry, struct page_info, list);
        list_del(entry);
        /* Should have just the one ref we gave it in alloc_p2m_page() */
        if ( (pg->count_info & PGC_SH_count_mask) != 1 )
        {
            SHADOW_PRINTK("Odd p2m page count c=%#x t=%"PRtype_info"\n",
                           pg->count_info, pg->u.inuse.type_info);
        }
        ASSERT(page_get_owner(pg) == d);
        /* Free should not decrement domain's total allocation, since 
         * these pages were allocated without an owner. */
        page_set_owner(pg, NULL); 
        free_domheap_pages(pg, 0);
        d->arch.shadow.p2m_pages--;
        perfc_decr(shadow_alloc_count);
    }
    list_for_each_safe(entry, n, &d->arch.shadow.p2m_freelist)
    {
        list_del(entry);
        pg = list_entry(entry, struct page_info, list);
        ASSERT(page_get_owner(pg) == d);
        /* Free should not decrement domain's total allocation. */
        page_set_owner(pg, NULL); 
        free_domheap_pages(pg, 0);
        d->arch.shadow.p2m_pages--;
        perfc_decr(shadow_alloc_count);
    }
    ASSERT(d->arch.shadow.p2m_pages == 0);
}

/* Set the pool of shadow pages to the required number of pages.
 * Input will be rounded up to at least shadow_min_acceptable_pages(),
 * plus space for the p2m table.
 * Returns 0 for success, non-zero for failure. */
static unsigned int set_sh_allocation(struct domain *d, 
                                       unsigned int pages,
                                       int *preempted)
{
    struct page_info *pg;
    unsigned int lower_bound;
    int j;

    ASSERT(shadow_lock_is_acquired(d));
    
    /* Don't allocate less than the minimum acceptable, plus one page per
     * megabyte of RAM (for the p2m table) */
    lower_bound = shadow_min_acceptable_pages(d) + (d->tot_pages / 256);
    if ( pages > 0 && pages < lower_bound )
        pages = lower_bound;
    /* Round up to largest block size */
    pages = (pages + ((1<<SHADOW_MAX_ORDER)-1)) & ~((1<<SHADOW_MAX_ORDER)-1);

    SHADOW_PRINTK("current %i target %i\n", 
                   d->arch.shadow.total_pages, pages);

    while ( d->arch.shadow.total_pages != pages ) 
    {
        if ( d->arch.shadow.total_pages < pages ) 
        {
            /* Need to allocate more memory from domheap */
            pg = alloc_domheap_pages(NULL, SHADOW_MAX_ORDER, 0); 
            if ( pg == NULL ) 
            { 
                SHADOW_PRINTK("failed to allocate shadow pages.\n");
                return -ENOMEM;
            }
            d->arch.shadow.free_pages += 1<<SHADOW_MAX_ORDER;
            d->arch.shadow.total_pages += 1<<SHADOW_MAX_ORDER;
            for ( j = 0; j < 1<<SHADOW_MAX_ORDER; j++ ) 
            {
                pg[j].u.inuse.type_info = 0;  /* Free page */
                pg[j].tlbflush_timestamp = 0; /* Not in any TLB */
            }
            SH_SET_PFN_ORDER(pg, SHADOW_MAX_ORDER);
            list_add_tail(&pg->list, 
                          &d->arch.shadow.freelists[SHADOW_MAX_ORDER]);
        } 
        else if ( d->arch.shadow.total_pages > pages ) 
        {
            /* Need to return memory to domheap */
            shadow_prealloc(d, SHADOW_MAX_ORDER);
            ASSERT(!list_empty(&d->arch.shadow.freelists[SHADOW_MAX_ORDER]));
            pg = list_entry(d->arch.shadow.freelists[SHADOW_MAX_ORDER].next, 
                            struct page_info, list);
            list_del(&pg->list);
            d->arch.shadow.free_pages -= 1<<SHADOW_MAX_ORDER;
            d->arch.shadow.total_pages -= 1<<SHADOW_MAX_ORDER;
            free_domheap_pages(pg, SHADOW_MAX_ORDER);
        }

        /* Check to see if we need to yield and try again */
        if ( preempted && hypercall_preempt_check() )
        {
            *preempted = 1;
            return 0;
        }
    }

    return 0;
}

unsigned int shadow_set_allocation(struct domain *d, 
                                    unsigned int megabytes,
                                    int *preempted)
/* Hypercall interface to set the shadow memory allocation */
{
    unsigned int rv;
    shadow_lock(d);
    rv = set_sh_allocation(d, megabytes << (20 - PAGE_SHIFT), preempted); 
    SHADOW_PRINTK("dom %u allocation now %u pages (%u MB)\n",
                   d->domain_id,
                   d->arch.shadow.total_pages,
                   shadow_get_allocation(d));
    shadow_unlock(d);
    return rv;
}

/**************************************************************************/
/* Hash table for storing the guest->shadow mappings */

/* Hash function that takes a gfn or mfn, plus another byte of type info */
typedef u32 key_t;
static inline key_t sh_hash(unsigned long n, u8 t) 
{
    unsigned char *p = (unsigned char *)&n;
    key_t k = t;
    int i;
    for ( i = 0; i < sizeof(n) ; i++ ) k = (u32)p[i] + (k<<6) + (k<<16) - k;
    return k;
}

#if SHADOW_AUDIT & (SHADOW_AUDIT_HASH|SHADOW_AUDIT_HASH_FULL)

/* Before we get to the mechanism, define a pair of audit functions
 * that sanity-check the contents of the hash table. */
static void sh_hash_audit_bucket(struct domain *d, int bucket)
/* Audit one bucket of the hash table */
{
    struct shadow_hash_entry *e, *x;
    struct page_info *pg;

    if ( !(SHADOW_AUDIT_ENABLE) )
        return;

    e = &d->arch.shadow.hash_table[bucket];
    if ( e->t == 0 ) return; /* Bucket is empty */ 
    while ( e )
    {
        /* Empty link? */
        BUG_ON( e->t == 0 ); 
        /* Bogus type? */
        BUG_ON( e->t > (PGC_SH_max_shadow >> PGC_SH_type_shift) );
        /* Wrong bucket? */
        BUG_ON( sh_hash(e->n, e->t) % SHADOW_HASH_BUCKETS != bucket ); 
        /* Duplicate entry? */
        for ( x = e->next; x; x = x->next )
            BUG_ON( x->n == e->n && x->t == e->t );
        /* Bogus MFN? */
        BUG_ON( !valid_mfn(e->smfn) );
        pg = mfn_to_page(e->smfn);
        /* Not a shadow? */
        BUG_ON( page_get_owner(pg) != 0 );
        /* Wrong kind of shadow? */
        BUG_ON( (pg->count_info & PGC_SH_type_mask) >> PGC_SH_type_shift 
                != e->t ); 
        /* Bad backlink? */
        BUG_ON( pg->u.inuse.type_info != e->n );
        if ( e->t != (PGC_SH_fl1_32_shadow >> PGC_SH_type_shift)
             && e->t != (PGC_SH_fl1_pae_shadow >> PGC_SH_type_shift)
             && e->t != (PGC_SH_fl1_64_shadow >> PGC_SH_type_shift) )
        {
            /* Bad shadow flags on guest page? */
            BUG_ON( !(mfn_to_page(_mfn(e->n))->shadow_flags & (1<<e->t)) );
        }
        /* That entry was OK; on we go */
        e = e->next;
    }
}

#else
#define sh_hash_audit_bucket(_d, _b)
#endif /* Hashtable bucket audit */


#if SHADOW_AUDIT & SHADOW_AUDIT_HASH_FULL

static void sh_hash_audit(struct domain *d)
/* Full audit: audit every bucket in the table */
{
    int i;

    if ( !(SHADOW_AUDIT_ENABLE) )
        return;

    for ( i = 0; i < SHADOW_HASH_BUCKETS; i++ ) 
    {
        sh_hash_audit_bucket(d, i);
    }
}

#else
#define sh_hash_audit(_d)
#endif /* Hashtable bucket audit */

/* Memory management interface for bucket allocation.
 * These ought to come out of shadow memory, but at least on 32-bit
 * machines we are forced to allocate them from xenheap so that we can
 * address them. */
static struct shadow_hash_entry *sh_alloc_hash_entry(struct domain *d)
{
    struct shadow_hash_entry *extra, *x;
    int i;

    /* We need to allocate a new node. Ensure the free list is not empty. 
     * Allocate new entries in units the same size as the original table. */
    if ( unlikely(d->arch.shadow.hash_freelist == NULL) )
    {
        size_t sz = sizeof(void *) + (SHADOW_HASH_BUCKETS * sizeof(*x));
        extra = xmalloc_bytes(sz);

        if ( extra == NULL )
        {
            /* No memory left! */
            SHADOW_ERROR("xmalloc() failed when allocating hash buckets.\n");
            domain_crash_synchronous();
        }
        memset(extra, 0, sz);

        /* Record the allocation block so it can be correctly freed later. */
        *((struct shadow_hash_entry **)&extra[SHADOW_HASH_BUCKETS]) = 
            d->arch.shadow.hash_allocations;
        d->arch.shadow.hash_allocations = &extra[0];

        /* Thread a free chain through the newly-allocated nodes. */
        for ( i = 0; i < (SHADOW_HASH_BUCKETS - 1); i++ )
            extra[i].next = &extra[i+1];
        extra[i].next = NULL;

        /* Add the new nodes to the free list. */
        d->arch.shadow.hash_freelist = &extra[0];
    }

    /* Allocate a new node from the free list. */
    x = d->arch.shadow.hash_freelist;
    d->arch.shadow.hash_freelist = x->next;
    return x;
}

static void sh_free_hash_entry(struct domain *d, struct shadow_hash_entry *e)
{
    /* Mark the bucket as empty and return it to the free list */
    e->t = 0; 
    e->next = d->arch.shadow.hash_freelist;
    d->arch.shadow.hash_freelist = e;
}


/* Allocate and initialise the table itself.  
 * Returns 0 for success, 1 for error. */
static int shadow_hash_alloc(struct domain *d)
{
    struct shadow_hash_entry *table;

    ASSERT(shadow_lock_is_acquired(d));
    ASSERT(!d->arch.shadow.hash_table);

    table = xmalloc_array(struct shadow_hash_entry, SHADOW_HASH_BUCKETS);
    if ( !table ) return 1;
    memset(table, 0, 
           SHADOW_HASH_BUCKETS * sizeof (struct shadow_hash_entry));
    d->arch.shadow.hash_table = table;
    return 0;
}

/* Tear down the hash table and return all memory to Xen.
 * This function does not care whether the table is populated. */
static void shadow_hash_teardown(struct domain *d)
{
    struct shadow_hash_entry *a, *n;

    ASSERT(shadow_lock_is_acquired(d));
    ASSERT(d->arch.shadow.hash_table);

    /* Return the table itself */
    xfree(d->arch.shadow.hash_table);
    d->arch.shadow.hash_table = NULL;

    /* Return any extra allocations */
    a = d->arch.shadow.hash_allocations;
    while ( a ) 
    {
        /* We stored a linked-list pointer at the end of each allocation */
        n = *((struct shadow_hash_entry **)(&a[SHADOW_HASH_BUCKETS]));
        xfree(a);
        a = n;
    }
    d->arch.shadow.hash_allocations = NULL;
    d->arch.shadow.hash_freelist = NULL;
}


mfn_t shadow_hash_lookup(struct vcpu *v, unsigned long n, u8 t)
/* Find an entry in the hash table.  Returns the MFN of the shadow,
 * or INVALID_MFN if it doesn't exist */
{
    struct domain *d = v->domain;
    struct shadow_hash_entry *p, *x, *head;
    key_t key;

    ASSERT(shadow_lock_is_acquired(d));
    ASSERT(d->arch.shadow.hash_table);
    ASSERT(t);

    sh_hash_audit(d);

    perfc_incrc(shadow_hash_lookups);
    key = sh_hash(n, t);

    x = head = &d->arch.shadow.hash_table[key % SHADOW_HASH_BUCKETS];
    p = NULL;

    sh_hash_audit_bucket(d, key % SHADOW_HASH_BUCKETS);

    do
    {
        ASSERT(x->t || ((x == head) && (x->next == NULL)));

        if ( x->n == n && x->t == t )
        {
            /* Pull-to-front if 'x' isn't already the head item */
            if ( unlikely(x != head) )
            {
                if ( unlikely(d->arch.shadow.hash_walking != 0) )
                    /* Can't reorder: someone is walking the hash chains */
                    return x->smfn;
                else 
                {
                    /* Delete 'x' from list and reinsert after head. */
                    p->next = x->next;
                    x->next = head->next;
                    head->next = x;
                    
                    /* Swap 'x' contents with head contents. */
                    SWAP(head->n, x->n);
                    SWAP(head->t, x->t);
                    SWAP(head->smfn, x->smfn);
                }
            }
            else
            {
                perfc_incrc(shadow_hash_lookup_head);
            }
            return head->smfn;
        }

        p = x;
        x = x->next;
    }
    while ( x != NULL );

    perfc_incrc(shadow_hash_lookup_miss);
    return _mfn(INVALID_MFN);
}

void shadow_hash_insert(struct vcpu *v, unsigned long n, u8 t, mfn_t smfn)
/* Put a mapping (n,t)->smfn into the hash table */
{
    struct domain *d = v->domain;
    struct shadow_hash_entry *x, *head;
    key_t key;
    
    ASSERT(shadow_lock_is_acquired(d));
    ASSERT(d->arch.shadow.hash_table);
    ASSERT(t);

    sh_hash_audit(d);

    perfc_incrc(shadow_hash_inserts);
    key = sh_hash(n, t);

    head = &d->arch.shadow.hash_table[key % SHADOW_HASH_BUCKETS];

    sh_hash_audit_bucket(d, key % SHADOW_HASH_BUCKETS);

    /* If the bucket is empty then insert the new page as the head item. */
    if ( head->t == 0 )
    {
        head->n = n;
        head->t = t;
        head->smfn = smfn;
        ASSERT(head->next == NULL);
    }
    else 
    {
        /* Insert a new entry directly after the head item. */
        x = sh_alloc_hash_entry(d);
        x->n = n; 
        x->t = t;
        x->smfn = smfn;
        x->next = head->next;
        head->next = x;
    }
    
    sh_hash_audit_bucket(d, key % SHADOW_HASH_BUCKETS);
}

void shadow_hash_delete(struct vcpu *v, unsigned long n, u8 t, mfn_t smfn)
/* Excise the mapping (n,t)->smfn from the hash table */
{
    struct domain *d = v->domain;
    struct shadow_hash_entry *p, *x, *head;
    key_t key;

    ASSERT(shadow_lock_is_acquired(d));
    ASSERT(d->arch.shadow.hash_table);
    ASSERT(t);

    sh_hash_audit(d);

    perfc_incrc(shadow_hash_deletes);
    key = sh_hash(n, t);

    head = &d->arch.shadow.hash_table[key % SHADOW_HASH_BUCKETS];

    sh_hash_audit_bucket(d, key % SHADOW_HASH_BUCKETS);

    /* Match on head item? */
    if ( head->n == n && head->t == t )
    {
        if ( (x = head->next) != NULL )
        {
            /* Overwrite head with contents of following node. */
            head->n = x->n;
            head->t = x->t;
            head->smfn = x->smfn;

            /* Delete following node. */
            head->next = x->next;
            sh_free_hash_entry(d, x);
        }
        else
        {
            /* This bucket is now empty. Initialise the head node. */
            head->t = 0;
        }
    }
    else 
    {
        /* Not at the head; need to walk the chain */
        p = head;
        x = head->next; 
        
        while(1)
        {
            ASSERT(x); /* We can't have hit the end, since our target is
                        * still in the chain somehwere... */
            if ( x->n == n && x->t == t )
            {
                /* Delete matching node. */
                p->next = x->next;
                sh_free_hash_entry(d, x);
                break;
            }
            p = x;
            x = x->next;
        }
    }

    sh_hash_audit_bucket(d, key % SHADOW_HASH_BUCKETS);
}

typedef int (*hash_callback_t)(struct vcpu *v, mfn_t smfn, mfn_t other_mfn);

static void hash_foreach(struct vcpu *v, 
                         unsigned int callback_mask, 
                         hash_callback_t callbacks[], 
                         mfn_t callback_mfn)
/* Walk the hash table looking at the types of the entries and 
 * calling the appropriate callback function for each entry. 
 * The mask determines which shadow types we call back for, and the array
 * of callbacks tells us which function to call.
 * Any callback may return non-zero to let us skip the rest of the scan. 
 *
 * WARNING: Callbacks MUST NOT add or remove hash entries unless they 
 * then return non-zero to terminate the scan. */
{
    int i, done = 0;
    struct domain *d = v->domain;
    struct shadow_hash_entry *x;

    /* Say we're here, to stop hash-lookups reordering the chains */
    ASSERT(shadow_lock_is_acquired(d));
    ASSERT(d->arch.shadow.hash_walking == 0);
    d->arch.shadow.hash_walking = 1;

    callback_mask &= ~1; /* Never attempt to call back on empty buckets */
    for ( i = 0; i < SHADOW_HASH_BUCKETS; i++ ) 
    {
        /* WARNING: This is not safe against changes to the hash table.
         * The callback *must* return non-zero if it has inserted or
         * deleted anything from the hash (lookups are OK, though). */
        for ( x = &d->arch.shadow.hash_table[i]; x; x = x->next )
        {
            if ( callback_mask & (1 << x->t) ) 
            {
                ASSERT(x->t <= 15);
                ASSERT(callbacks[x->t] != NULL);
                if ( (done = callbacks[x->t](v, x->smfn, callback_mfn)) != 0 )
                    break;
            }
        }
        if ( done ) break; 
    }
    d->arch.shadow.hash_walking = 0; 
}


/**************************************************************************/
/* Destroy a shadow page: simple dispatcher to call the per-type destructor
 * which will decrement refcounts appropriately and return memory to the 
 * free pool. */

void sh_destroy_shadow(struct vcpu *v, mfn_t smfn)
{
    struct page_info *pg = mfn_to_page(smfn);
    u32 t = pg->count_info & PGC_SH_type_mask;


    SHADOW_PRINTK("smfn=%#lx\n", mfn_x(smfn));

    /* Double-check, if we can, that the shadowed page belongs to this
     * domain, (by following the back-pointer). */
    ASSERT(t == PGC_SH_fl1_32_shadow  ||  
           t == PGC_SH_fl1_pae_shadow ||  
           t == PGC_SH_fl1_64_shadow  || 
           t == PGC_SH_monitor_table  || 
           (page_get_owner(mfn_to_page(_mfn(pg->u.inuse.type_info))) 
            == v->domain)); 

    /* The down-shifts here are so that the switch statement is on nice
     * small numbers that the compiler will enjoy */
    switch ( t >> PGC_SH_type_shift )
    {
#if CONFIG_PAGING_LEVELS == 2
    case PGC_SH_l1_32_shadow >> PGC_SH_type_shift:
    case PGC_SH_fl1_32_shadow >> PGC_SH_type_shift:
        SHADOW_INTERNAL_NAME(sh_destroy_l1_shadow, 2, 2)(v, smfn); 
        break;
    case PGC_SH_l2_32_shadow >> PGC_SH_type_shift:
        SHADOW_INTERNAL_NAME(sh_destroy_l2_shadow, 2, 2)(v, smfn);
        break;
#else /* PAE or 64bit */
    case PGC_SH_l1_32_shadow >> PGC_SH_type_shift:
    case PGC_SH_fl1_32_shadow >> PGC_SH_type_shift:
        SHADOW_INTERNAL_NAME(sh_destroy_l1_shadow, 3, 2)(v, smfn);
        break;
    case PGC_SH_l2_32_shadow >> PGC_SH_type_shift:
        SHADOW_INTERNAL_NAME(sh_destroy_l2_shadow, 3, 2)(v, smfn);
        break;
#endif

#if CONFIG_PAGING_LEVELS >= 3
    case PGC_SH_l1_pae_shadow >> PGC_SH_type_shift:
    case PGC_SH_fl1_pae_shadow >> PGC_SH_type_shift:
        SHADOW_INTERNAL_NAME(sh_destroy_l1_shadow, 3, 3)(v, smfn);
        break;
    case PGC_SH_l2_pae_shadow >> PGC_SH_type_shift:
    case PGC_SH_l2h_pae_shadow >> PGC_SH_type_shift:
        SHADOW_INTERNAL_NAME(sh_destroy_l2_shadow, 3, 3)(v, smfn);
        break;
    case PGC_SH_l3_pae_shadow >> PGC_SH_type_shift:
        SHADOW_INTERNAL_NAME(sh_destroy_l3_shadow, 3, 3)(v, smfn);
        break;
#endif

#if CONFIG_PAGING_LEVELS >= 4
    case PGC_SH_l1_64_shadow >> PGC_SH_type_shift:
    case PGC_SH_fl1_64_shadow >> PGC_SH_type_shift:
        SHADOW_INTERNAL_NAME(sh_destroy_l1_shadow, 4, 4)(v, smfn);
        break;
    case PGC_SH_l2_64_shadow >> PGC_SH_type_shift:
        SHADOW_INTERNAL_NAME(sh_destroy_l2_shadow, 4, 4)(v, smfn);
        break;
    case PGC_SH_l3_64_shadow >> PGC_SH_type_shift:
        SHADOW_INTERNAL_NAME(sh_destroy_l3_shadow, 4, 4)(v, smfn);
        break;
    case PGC_SH_l4_64_shadow >> PGC_SH_type_shift:
        SHADOW_INTERNAL_NAME(sh_destroy_l4_shadow, 4, 4)(v, smfn);
        break;
#endif
    default:
        SHADOW_PRINTK("tried to destroy shadow of bad type %08lx\n", 
                       (unsigned long)t);
        BUG();
    }    
}

/**************************************************************************/
/* Remove all writeable mappings of a guest frame from the shadow tables 
 * Returns non-zero if we need to flush TLBs. 
 * level and fault_addr desribe how we found this to be a pagetable;
 * level==0 means we have some other reason for revoking write access.*/

int shadow_remove_write_access(struct vcpu *v, mfn_t gmfn, 
                                unsigned int level,
                                unsigned long fault_addr)
{
    /* Dispatch table for getting per-type functions */
    static hash_callback_t callbacks[16] = {
        NULL, /* none    */
#if CONFIG_PAGING_LEVELS == 2
        SHADOW_INTERNAL_NAME(sh_remove_write_access,2,2), /* l1_32   */
        SHADOW_INTERNAL_NAME(sh_remove_write_access,2,2), /* fl1_32  */
#else 
        SHADOW_INTERNAL_NAME(sh_remove_write_access,3,2), /* l1_32   */
        SHADOW_INTERNAL_NAME(sh_remove_write_access,3,2), /* fl1_32  */
#endif
        NULL, /* l2_32   */
#if CONFIG_PAGING_LEVELS >= 3
        SHADOW_INTERNAL_NAME(sh_remove_write_access,3,3), /* l1_pae  */
        SHADOW_INTERNAL_NAME(sh_remove_write_access,3,3), /* fl1_pae */
#else 
        NULL, /* l1_pae  */
        NULL, /* fl1_pae */
#endif
        NULL, /* l2_pae  */
        NULL, /* l2h_pae */
        NULL, /* l3_pae  */
#if CONFIG_PAGING_LEVELS >= 4
        SHADOW_INTERNAL_NAME(sh_remove_write_access,4,4), /* l1_64   */
        SHADOW_INTERNAL_NAME(sh_remove_write_access,4,4), /* fl1_64  */
#else
        NULL, /* l1_64   */
        NULL, /* fl1_64  */
#endif
        NULL, /* l2_64   */
        NULL, /* l3_64   */
        NULL, /* l4_64   */
        NULL, /* p2m     */
        NULL  /* unused  */
    };

    static unsigned int callback_mask = 
          1 << (PGC_SH_l1_32_shadow >> PGC_SH_type_shift)
        | 1 << (PGC_SH_fl1_32_shadow >> PGC_SH_type_shift)
        | 1 << (PGC_SH_l1_pae_shadow >> PGC_SH_type_shift)
        | 1 << (PGC_SH_fl1_pae_shadow >> PGC_SH_type_shift)
        | 1 << (PGC_SH_l1_64_shadow >> PGC_SH_type_shift)
        | 1 << (PGC_SH_fl1_64_shadow >> PGC_SH_type_shift)
        ;
    struct page_info *pg = mfn_to_page(gmfn);

    ASSERT(shadow_lock_is_acquired(v->domain));

    /* Only remove writable mappings if we are doing shadow refcounts.
     * In guest refcounting, we trust Xen to already be restricting
     * all the writes to the guest page tables, so we do not need to
     * do more. */
    if ( !shadow_mode_refcounts(v->domain) )
        return 0;

    /* Early exit if it's already a pagetable, or otherwise not writeable */
    if ( sh_mfn_is_a_page_table(gmfn) 
         || (pg->u.inuse.type_info & PGT_count_mask) == 0 )
        return 0;

    perfc_incrc(shadow_writeable);

    /* If this isn't a "normal" writeable page, the domain is trying to 
     * put pagetables in special memory of some kind.  We can't allow that. */
    if ( (pg->u.inuse.type_info & PGT_type_mask) != PGT_writable_page )
    {
        SHADOW_ERROR("can't remove write access to mfn %lx, type_info is %" 
                      PRtype_info "\n",
                      mfn_x(gmfn), mfn_to_page(gmfn)->u.inuse.type_info);
        domain_crash(v->domain);
    }

#if SHADOW_OPTIMIZATIONS & SHOPT_WRITABLE_HEURISTIC
    if ( v == current && level != 0 )
    {
        unsigned long gfn;
        /* Heuristic: there is likely to be only one writeable mapping,
         * and that mapping is likely to be in the current pagetable,
         * either in the guest's linear map (linux, windows) or in a
         * magic slot used to map high memory regions (linux HIGHTPTE) */

#define GUESS(_a, _h) do {                                              \
            if ( v->arch.shadow.mode->guess_wrmap(v, (_a), gmfn) )          \
                perfc_incrc(shadow_writeable_h_ ## _h);                \
            if ( (pg->u.inuse.type_info & PGT_count_mask) == 0 )        \
                return 1;                                               \
        } while (0)

        
        if ( v->arch.shadow.mode->guest_levels == 2 )
        {
            if ( level == 1 )
                /* 32bit non-PAE w2k3: linear map at 0xC0000000 */
                GUESS(0xC0000000UL + (fault_addr >> 10), 1);

            /* Linux lowmem: first 896MB is mapped 1-to-1 above 0xC0000000 */
            if ((gfn = sh_mfn_to_gfn(v->domain, gmfn)) < 0x38000 ) 
                GUESS(0xC0000000UL + (gfn << PAGE_SHIFT), 4);

        }
#if CONFIG_PAGING_LEVELS >= 3
        else if ( v->arch.shadow.mode->guest_levels == 3 )
        {
            /* 32bit PAE w2k3: linear map at 0xC0000000 */
            switch ( level ) 
            {
            case 1: GUESS(0xC0000000UL + (fault_addr >> 9), 2); break;
            case 2: GUESS(0xC0600000UL + (fault_addr >> 18), 2); break;
            }

            /* Linux lowmem: first 896MB is mapped 1-to-1 above 0xC0000000 */
            if ((gfn = sh_mfn_to_gfn(v->domain, gmfn)) < 0x38000 ) 
                GUESS(0xC0000000UL + (gfn << PAGE_SHIFT), 4);
        }
#if CONFIG_PAGING_LEVELS >= 4
        else if ( v->arch.shadow.mode->guest_levels == 4 )
        {
            /* 64bit w2k3: linear map at 0x0000070000000000 */
            switch ( level ) 
            {
            case 1: GUESS(0x70000000000UL + (fault_addr >> 9), 3); break;
            case 2: GUESS(0x70380000000UL + (fault_addr >> 18), 3); break;
            case 3: GUESS(0x70381C00000UL + (fault_addr >> 27), 3); break;
            }

            /* Linux direct map at 0xffff810000000000 */
            gfn = sh_mfn_to_gfn(v->domain, gmfn); 
            GUESS(0xffff810000000000UL + (gfn << PAGE_SHIFT), 4); 
        }
#endif /* CONFIG_PAGING_LEVELS >= 4 */
#endif /* CONFIG_PAGING_LEVELS >= 3 */

#undef GUESS

    }
#endif
    
    /* Brute-force search of all the shadows, by walking the hash */
    perfc_incrc(shadow_writeable_bf);
    hash_foreach(v, callback_mask, callbacks, gmfn);

    /* If that didn't catch the mapping, something is very wrong */
    if ( (mfn_to_page(gmfn)->u.inuse.type_info & PGT_count_mask) != 0 )
    {
        SHADOW_ERROR("can't find all writeable mappings of mfn %lx: "
                      "%lu left\n", mfn_x(gmfn),
                      (mfn_to_page(gmfn)->u.inuse.type_info&PGT_count_mask));
        domain_crash(v->domain);
    }
    
    /* We killed at least one writeable mapping, so must flush TLBs. */
    return 1;
}



/**************************************************************************/
/* Remove all mappings of a guest frame from the shadow tables.
 * Returns non-zero if we need to flush TLBs. */

int shadow_remove_all_mappings(struct vcpu *v, mfn_t gmfn)
{
    struct page_info *page = mfn_to_page(gmfn);
    int expected_count;

    /* Dispatch table for getting per-type functions */
    static hash_callback_t callbacks[16] = {
        NULL, /* none    */
#if CONFIG_PAGING_LEVELS == 2
        SHADOW_INTERNAL_NAME(sh_remove_all_mappings,2,2), /* l1_32   */
        SHADOW_INTERNAL_NAME(sh_remove_all_mappings,2,2), /* fl1_32  */
#else 
        SHADOW_INTERNAL_NAME(sh_remove_all_mappings,3,2), /* l1_32   */
        SHADOW_INTERNAL_NAME(sh_remove_all_mappings,3,2), /* fl1_32  */
#endif
        NULL, /* l2_32   */
#if CONFIG_PAGING_LEVELS >= 3
        SHADOW_INTERNAL_NAME(sh_remove_all_mappings,3,3), /* l1_pae  */
        SHADOW_INTERNAL_NAME(sh_remove_all_mappings,3,3), /* fl1_pae */
#else 
        NULL, /* l1_pae  */
        NULL, /* fl1_pae */
#endif
        NULL, /* l2_pae  */
        NULL, /* l2h_pae */
        NULL, /* l3_pae  */
#if CONFIG_PAGING_LEVELS >= 4
        SHADOW_INTERNAL_NAME(sh_remove_all_mappings,4,4), /* l1_64   */
        SHADOW_INTERNAL_NAME(sh_remove_all_mappings,4,4), /* fl1_64  */
#else
        NULL, /* l1_64   */
        NULL, /* fl1_64  */
#endif
        NULL, /* l2_64   */
        NULL, /* l3_64   */
        NULL, /* l4_64   */
        NULL, /* p2m     */
        NULL  /* unused  */
    };

    static unsigned int callback_mask = 
          1 << (PGC_SH_l1_32_shadow >> PGC_SH_type_shift)
        | 1 << (PGC_SH_fl1_32_shadow >> PGC_SH_type_shift)
        | 1 << (PGC_SH_l1_pae_shadow >> PGC_SH_type_shift)
        | 1 << (PGC_SH_fl1_pae_shadow >> PGC_SH_type_shift)
        | 1 << (PGC_SH_l1_64_shadow >> PGC_SH_type_shift)
        | 1 << (PGC_SH_fl1_64_shadow >> PGC_SH_type_shift)
        ;

    perfc_incrc(shadow_mappings);
    if ( (page->count_info & PGC_count_mask) == 0 )
        return 0;

    ASSERT(shadow_lock_is_acquired(v->domain));

    /* XXX TODO: 
     * Heuristics for finding the (probably) single mapping of this gmfn */
    
    /* Brute-force search of all the shadows, by walking the hash */
    perfc_incrc(shadow_mappings_bf);
    hash_foreach(v, callback_mask, callbacks, gmfn);

    /* If that didn't catch the mapping, something is very wrong */
    expected_count = (page->count_info & PGC_allocated) ? 1 : 0;
    if ( (page->count_info & PGC_count_mask) != expected_count )
    {
        /* Don't complain if we're in HVM and there's one extra mapping: 
         * The qemu helper process has an untyped mapping of this dom's RAM */
        if ( !(shadow_mode_external(v->domain)
               && (page->count_info & PGC_count_mask) <= 2
               && (page->u.inuse.type_info & PGT_count_mask) == 0) )
        {
            SHADOW_ERROR("can't find all mappings of mfn %lx: "
                          "c=%08x t=%08lx\n", mfn_x(gmfn), 
                          page->count_info, page->u.inuse.type_info);
        }
    }

    /* We killed at least one mapping, so must flush TLBs. */
    return 1;
}


/**************************************************************************/
/* Remove all shadows of a guest frame from the shadow tables */

static int sh_remove_shadow_via_pointer(struct vcpu *v, mfn_t smfn)
/* Follow this shadow's up-pointer, if it has one, and remove the reference
 * found there.  Returns 1 if that was the only reference to this shadow */
{
    struct page_info *pg = mfn_to_page(smfn);
    mfn_t pmfn;
    void *vaddr;
    int rc;

    ASSERT((pg->count_info & PGC_SH_type_mask) > 0);
    ASSERT((pg->count_info & PGC_SH_type_mask) < PGC_SH_max_shadow);
    ASSERT((pg->count_info & PGC_SH_type_mask) != PGC_SH_l2_32_shadow);
    ASSERT((pg->count_info & PGC_SH_type_mask) != PGC_SH_l3_pae_shadow);
    ASSERT((pg->count_info & PGC_SH_type_mask) != PGC_SH_l4_64_shadow);
    
    if (pg->up == 0) return 0;
    pmfn = _mfn(pg->up >> PAGE_SHIFT);
    ASSERT(valid_mfn(pmfn));
    vaddr = sh_map_domain_page(pmfn);
    ASSERT(vaddr);
    vaddr += pg->up & (PAGE_SIZE-1);
    ASSERT(l1e_get_pfn(*(l1_pgentry_t *)vaddr) == mfn_x(smfn));
    
    /* Is this the only reference to this shadow? */
    rc = ((pg->count_info & PGC_SH_count_mask) == 1) ? 1 : 0;

    /* Blank the offending entry */
    switch ((pg->count_info & PGC_SH_type_mask)) 
    {
    case PGC_SH_l1_32_shadow:
    case PGC_SH_l2_32_shadow:
#if CONFIG_PAGING_LEVELS == 2
        SHADOW_INTERNAL_NAME(sh_clear_shadow_entry,2,2)(v, vaddr, pmfn);
#else
        SHADOW_INTERNAL_NAME(sh_clear_shadow_entry,3,2)(v, vaddr, pmfn);
#endif
        break;
#if CONFIG_PAGING_LEVELS >=3
    case PGC_SH_l1_pae_shadow:
    case PGC_SH_l2_pae_shadow:
    case PGC_SH_l2h_pae_shadow:
    case PGC_SH_l3_pae_shadow:
        SHADOW_INTERNAL_NAME(sh_clear_shadow_entry,3,3)(v, vaddr, pmfn);
        break;
#if CONFIG_PAGING_LEVELS >= 4
    case PGC_SH_l1_64_shadow:
    case PGC_SH_l2_64_shadow:
    case PGC_SH_l3_64_shadow:
    case PGC_SH_l4_64_shadow:
        SHADOW_INTERNAL_NAME(sh_clear_shadow_entry,4,4)(v, vaddr, pmfn);
        break;
#endif
#endif
    default: BUG(); /* Some wierd unknown shadow type */
    }
    
    sh_unmap_domain_page(vaddr);
    if ( rc )
        perfc_incrc(shadow_up_pointer);
    else
        perfc_incrc(shadow_unshadow_bf);

    return rc;
}

void sh_remove_shadows(struct vcpu *v, mfn_t gmfn, int all)
/* Remove the shadows of this guest page.  
 * If all != 0, find all shadows, if necessary by walking the tables.
 * Otherwise, just try the (much faster) heuristics, which will remove 
 * at most one reference to each shadow of the page. */
{
    struct page_info *pg;
    mfn_t smfn;
    u32 sh_flags;
    unsigned char t;

    /* Dispatch table for getting per-type functions: each level must
     * be called with the function to remove a lower-level shadow. */
    static hash_callback_t callbacks[16] = {
        NULL, /* none    */
        NULL, /* l1_32   */
        NULL, /* fl1_32  */
#if CONFIG_PAGING_LEVELS == 2
        SHADOW_INTERNAL_NAME(sh_remove_l1_shadow,2,2), /* l2_32   */
#else 
        SHADOW_INTERNAL_NAME(sh_remove_l1_shadow,3,2), /* l2_32   */
#endif
        NULL, /* l1_pae  */
        NULL, /* fl1_pae */
#if CONFIG_PAGING_LEVELS >= 3
        SHADOW_INTERNAL_NAME(sh_remove_l1_shadow,3,3), /* l2_pae  */
        SHADOW_INTERNAL_NAME(sh_remove_l1_shadow,3,3), /* l2h_pae */
        SHADOW_INTERNAL_NAME(sh_remove_l2_shadow,3,3), /* l3_pae  */
#else 
        NULL, /* l2_pae  */
        NULL, /* l2h_pae */
        NULL, /* l3_pae  */
#endif
        NULL, /* l1_64   */
        NULL, /* fl1_64  */
#if CONFIG_PAGING_LEVELS >= 4
        SHADOW_INTERNAL_NAME(sh_remove_l1_shadow,4,4), /* l2_64   */
        SHADOW_INTERNAL_NAME(sh_remove_l2_shadow,4,4), /* l3_64   */
        SHADOW_INTERNAL_NAME(sh_remove_l3_shadow,4,4), /* l4_64   */
#else
        NULL, /* l2_64   */
        NULL, /* l3_64   */
        NULL, /* l4_64   */
#endif
        NULL, /* p2m     */
        NULL  /* unused  */
    };

    /* Another lookup table, for choosing which mask to use */
    static unsigned int masks[16] = {
        0, /* none    */
        1 << (PGC_SH_l2_32_shadow >> PGC_SH_type_shift), /* l1_32   */
        0, /* fl1_32  */
        0, /* l2_32   */
        ((1 << (PGC_SH_l2h_pae_shadow >> PGC_SH_type_shift))
         | (1 << (PGC_SH_l2_pae_shadow >> PGC_SH_type_shift))), /* l1_pae  */
        0, /* fl1_pae */
        1 << (PGC_SH_l3_pae_shadow >> PGC_SH_type_shift), /* l2_pae  */
        1 << (PGC_SH_l3_pae_shadow >> PGC_SH_type_shift), /* l2h_pae  */
        0, /* l3_pae  */
        1 << (PGC_SH_l2_64_shadow >> PGC_SH_type_shift), /* l1_64   */
        0, /* fl1_64  */
        1 << (PGC_SH_l3_64_shadow >> PGC_SH_type_shift), /* l2_64   */
        1 << (PGC_SH_l4_64_shadow >> PGC_SH_type_shift), /* l3_64   */
        0, /* l4_64   */
        0, /* p2m     */
        0  /* unused  */
    };

    ASSERT(shadow_lock_is_acquired(v->domain));

    pg = mfn_to_page(gmfn);

    /* Bail out now if the page is not shadowed */
    if ( (pg->count_info & PGC_page_table) == 0 )
        return;

    SHADOW_PRINTK("d=%d, v=%d, gmfn=%05lx\n",
                   v->domain->domain_id, v->vcpu_id, mfn_x(gmfn));

    /* Search for this shadow in all appropriate shadows */
    perfc_incrc(shadow_unshadow);
    sh_flags = pg->shadow_flags;

    /* Lower-level shadows need to be excised from upper-level shadows.
     * This call to hash_foreach() looks dangerous but is in fact OK: each
     * call will remove at most one shadow, and terminate immediately when
     * it does remove it, so we never walk the hash after doing a deletion.  */
#define DO_UNSHADOW(_type) do {                                 \
    t = (_type) >> PGC_SH_type_shift;                          \
    smfn = shadow_hash_lookup(v, mfn_x(gmfn), t);              \
    if ( !sh_remove_shadow_via_pointer(v, smfn) && all )       \
        hash_foreach(v, masks[t], callbacks, smfn);             \
} while (0)

    /* Top-level shadows need to be unpinned */
#define DO_UNPIN(_type) do {                                             \
    t = (_type) >> PGC_SH_type_shift;                                   \
    smfn = shadow_hash_lookup(v, mfn_x(gmfn), t);                       \
    if ( mfn_to_page(smfn)->count_info & PGC_SH_pinned )                \
        sh_unpin(v, smfn);                                              \
    if ( (_type) == PGC_SH_l3_pae_shadow )                              \
        SHADOW_INTERNAL_NAME(sh_unpin_all_l3_subshadows,3,3)(v, smfn); \
} while (0)

    if ( sh_flags & SHF_L1_32 )   DO_UNSHADOW(PGC_SH_l1_32_shadow);
    if ( sh_flags & SHF_L2_32 )   DO_UNPIN(PGC_SH_l2_32_shadow);
#if CONFIG_PAGING_LEVELS >= 3
    if ( sh_flags & SHF_L1_PAE )  DO_UNSHADOW(PGC_SH_l1_pae_shadow);
    if ( sh_flags & SHF_L2_PAE )  DO_UNSHADOW(PGC_SH_l2_pae_shadow);
    if ( sh_flags & SHF_L2H_PAE ) DO_UNSHADOW(PGC_SH_l2h_pae_shadow);
    if ( sh_flags & SHF_L3_PAE )  DO_UNPIN(PGC_SH_l3_pae_shadow);
#if CONFIG_PAGING_LEVELS >= 4
    if ( sh_flags & SHF_L1_64 )   DO_UNSHADOW(PGC_SH_l1_64_shadow);
    if ( sh_flags & SHF_L2_64 )   DO_UNSHADOW(PGC_SH_l2_64_shadow);
    if ( sh_flags & SHF_L3_64 )   DO_UNSHADOW(PGC_SH_l3_64_shadow);
    if ( sh_flags & SHF_L4_64 )   DO_UNPIN(PGC_SH_l4_64_shadow);
#endif
#endif

#undef DO_UNSHADOW
#undef DO_UNPIN


#if CONFIG_PAGING_LEVELS > 2
    /* We may have caused some PAE l3 entries to change: need to 
     * fix up the copies of them in various places */
    if ( sh_flags & (SHF_L2_PAE|SHF_L2H_PAE) )
        sh_pae_recopy(v->domain);
#endif

    /* If that didn't catch the shadows, something is wrong */
    if ( all && (pg->count_info & PGC_page_table) )
    {
        SHADOW_ERROR("can't find all shadows of mfn %05lx (shadow_flags=%08x)\n",
                      mfn_x(gmfn), pg->shadow_flags);
        domain_crash(v->domain);
    }
}

void
shadow_remove_all_shadows_and_parents(struct vcpu *v, mfn_t gmfn)
/* Even harsher: this is a HVM page that we thing is no longer a pagetable.
 * Unshadow it, and recursively unshadow pages that reference it. */
{
    shadow_remove_all_shadows(v, gmfn);
    /* XXX TODO:
     * Rework this hashtable walker to return a linked-list of all 
     * the shadows it modified, then do breadth-first recursion 
     * to find the way up to higher-level tables and unshadow them too. 
     *
     * The current code (just tearing down each page's shadows as we
     * detect that it is not a pagetable) is correct, but very slow. 
     * It means extra emulated writes and slows down removal of mappings. */
}

/**************************************************************************/

void sh_update_paging_modes(struct vcpu *v)
{
    struct domain *d = v->domain;
    struct shadow_paging_mode *old_mode = v->arch.shadow.mode;
    mfn_t old_guest_table;

    ASSERT(shadow_lock_is_acquired(d));

    // Valid transitions handled by this function:
    // - For PV guests:
    //     - after a shadow mode has been changed
    // - For HVM guests:
    //     - after a shadow mode has been changed
    //     - changes in CR0.PG, CR4.PAE, CR4.PSE, or CR4.PGE
    //

    // Avoid determining the current shadow mode for uninitialized CPUs, as
    // we can not yet determine whether it is an HVM or PV domain.
    //
    if ( !test_bit(_VCPUF_initialised, &v->vcpu_flags) )
    {
        printk("%s: postponing determination of shadow mode\n", __func__);
        return;
    }

    // First, tear down any old shadow tables held by this vcpu.
    //
    shadow_detach_old_tables(v);

    if ( !hvm_guest(v) )
    {
        ///
        /// PV guest
        ///
#if CONFIG_PAGING_LEVELS == 4
        if ( pv_32bit_guest(v) )
            v->arch.shadow.mode = &SHADOW_INTERNAL_NAME(sh_paging_mode,4,3);
        else
            v->arch.shadow.mode = &SHADOW_INTERNAL_NAME(sh_paging_mode,4,4);
#elif CONFIG_PAGING_LEVELS == 3
        v->arch.shadow.mode = &SHADOW_INTERNAL_NAME(sh_paging_mode,3,3);
#elif CONFIG_PAGING_LEVELS == 2
        v->arch.shadow.mode = &SHADOW_INTERNAL_NAME(sh_paging_mode,2,2);
#else
#error unexpected paging mode
#endif
    }
    else
    {
        ///
        /// HVM guest
        ///
        ASSERT(shadow_mode_translate(d));
        ASSERT(shadow_mode_external(d));

        v->arch.shadow.hvm_paging_enabled = !!hvm_paging_enabled(v);
        if ( !v->arch.shadow.hvm_paging_enabled )
        {
            
            /* Set v->arch.guest_table to use the p2m map, and choose
             * the appropriate shadow mode */
            old_guest_table = pagetable_get_mfn(v->arch.guest_table);
#if CONFIG_PAGING_LEVELS == 2
            v->arch.guest_table =
                pagetable_from_pfn(pagetable_get_pfn(d->arch.phys_table));
            v->arch.shadow.mode = &SHADOW_INTERNAL_NAME(sh_paging_mode,2,2);
#elif CONFIG_PAGING_LEVELS == 3 
            v->arch.guest_table =
                pagetable_from_pfn(pagetable_get_pfn(d->arch.phys_table));
            v->arch.shadow.mode = &SHADOW_INTERNAL_NAME(sh_paging_mode,3,3);
#else /* CONFIG_PAGING_LEVELS == 4 */
            { 
                l4_pgentry_t *l4e; 
                /* Use the start of the first l3 table as a PAE l3 */
                ASSERT(pagetable_get_pfn(d->arch.phys_table) != 0);
                l4e = sh_map_domain_page(pagetable_get_mfn(d->arch.phys_table));
                ASSERT(l4e_get_flags(l4e[0]) & _PAGE_PRESENT);
                v->arch.guest_table =
                    pagetable_from_pfn(l4e_get_pfn(l4e[0]));
                sh_unmap_domain_page(l4e);
            }
            v->arch.shadow.mode = &SHADOW_INTERNAL_NAME(sh_paging_mode,3,3);
#endif
            /* Fix up refcounts on guest_table */
            get_page(mfn_to_page(pagetable_get_mfn(v->arch.guest_table)), d);
            if ( mfn_x(old_guest_table) != 0 )
                put_page(mfn_to_page(old_guest_table));
        }
        else
        {
#ifdef __x86_64__
            if ( hvm_long_mode_enabled(v) )
            {
                // long mode guest...
                v->arch.shadow.mode =
                    &SHADOW_INTERNAL_NAME(sh_paging_mode, 4, 4);
            }
            else
#endif
                if ( hvm_get_guest_ctrl_reg(v, 4) & X86_CR4_PAE )
                {
#if CONFIG_PAGING_LEVELS >= 3
                    // 32-bit PAE mode guest...
                    v->arch.shadow.mode =
                        &SHADOW_INTERNAL_NAME(sh_paging_mode, 3, 3);
#else
                    SHADOW_ERROR("PAE not supported in 32-bit Xen\n");
                    domain_crash(d);
                    return;
#endif
                }
                else
                {
                    // 32-bit 2 level guest...
#if CONFIG_PAGING_LEVELS >= 3
                    v->arch.shadow.mode =
                        &SHADOW_INTERNAL_NAME(sh_paging_mode, 3, 2);
#else
                    v->arch.shadow.mode =
                        &SHADOW_INTERNAL_NAME(sh_paging_mode, 2, 2);
#endif
                }
        }

        if ( pagetable_get_pfn(v->arch.monitor_table) == 0 )
        {
            mfn_t mmfn = shadow_make_monitor_table(v);
            v->arch.monitor_table = pagetable_from_mfn(mmfn);
            v->arch.monitor_vtable = sh_map_domain_page(mmfn);
        } 

        if ( v->arch.shadow.mode != old_mode )
        {
            SHADOW_PRINTK("new paging mode: d=%u v=%u g=%u s=%u "
                           "(was g=%u s=%u)\n",
                           d->domain_id, v->vcpu_id, 
                           v->arch.shadow.mode->guest_levels,
                           v->arch.shadow.mode->shadow_levels,
                           old_mode ? old_mode->guest_levels : 0,
                           old_mode ? old_mode->shadow_levels : 0);
            if ( old_mode &&
                 (v->arch.shadow.mode->shadow_levels !=
                  old_mode->shadow_levels) )
            {
                /* Need to make a new monitor table for the new mode */
                mfn_t new_mfn, old_mfn;

                if ( v != current ) 
                {
                    SHADOW_ERROR("Some third party (d=%u v=%u) is changing "
                                  "this HVM vcpu's (d=%u v=%u) paging mode!\n",
                                  current->domain->domain_id, current->vcpu_id,
                                  v->domain->domain_id, v->vcpu_id);
                    domain_crash(v->domain);
                    return;
                }

                sh_unmap_domain_page(v->arch.monitor_vtable);
                old_mfn = pagetable_get_mfn(v->arch.monitor_table);
                v->arch.monitor_table = pagetable_null();
                new_mfn = v->arch.shadow.mode->make_monitor_table(v);            
                v->arch.monitor_table = pagetable_from_mfn(new_mfn);
                v->arch.monitor_vtable = sh_map_domain_page(new_mfn);
                SHADOW_PRINTK("new monitor table %"SH_PRI_mfn "\n",
                               mfn_x(new_mfn));

                /* Don't be running on the old monitor table when we 
                 * pull it down!  Switch CR3, and warn the HVM code that
                 * its host cr3 has changed. */
                make_cr3(v, mfn_x(new_mfn));
                write_ptbase(v);
                hvm_update_host_cr3(v);
                old_mode->destroy_monitor_table(v, old_mfn);
            }
        }

        // XXX -- Need to deal with changes in CR4.PSE and CR4.PGE.
        //        These are HARD: think about the case where two CPU's have
        //        different values for CR4.PSE and CR4.PGE at the same time.
        //        This *does* happen, at least for CR4.PGE...
    }

    v->arch.shadow.mode->update_cr3(v);
}

/**************************************************************************/
/* Turning on and off shadow features */

static void sh_new_mode(struct domain *d, u32 new_mode)
/* Inform all the vcpus that the shadow mode has been changed */
{
    struct vcpu *v;

    ASSERT(shadow_lock_is_acquired(d));
    ASSERT(d != current->domain);
    d->arch.shadow.mode = new_mode;
    if ( new_mode & SHM2_translate ) 
        shadow_audit_p2m(d);
    for_each_vcpu(d, v)
        sh_update_paging_modes(v);
}

static int shadow_enable(struct domain *d, u32 mode)
/* Turn on "permanent" shadow features: external, translate, refcount.
 * Can only be called once on a domain, and these features cannot be
 * disabled. 
 * Returns 0 for success, -errno for failure. */
{    
    unsigned int old_pages;
    int rv = 0;

    mode |= SHM2_enable;

    domain_pause(d);
    shadow_lock(d);

    /* Sanity check the arguments */
    if ( (d == current->domain) ||
         shadow_mode_enabled(d) ||
         ((mode & SHM2_external) && !(mode & SHM2_translate)) )
    {
        rv = -EINVAL;
        goto out;
    }

    // XXX -- eventually would like to require that all memory be allocated
    // *after* shadow_enabled() is called...  So here, we would test to make
    // sure that d->page_list is empty.
#if 0
    spin_lock(&d->page_alloc_lock);
    if ( !list_empty(&d->page_list) )
    {
        spin_unlock(&d->page_alloc_lock);
        rv = -EINVAL;
        goto out;
    }
    spin_unlock(&d->page_alloc_lock);
#endif

    /* Init the shadow memory allocation if the user hasn't done so */
    old_pages = d->arch.shadow.total_pages;
    if ( old_pages == 0 )
        if ( set_sh_allocation(d, 256, NULL) != 0 ) /* Use at least 1MB */
        {
            set_sh_allocation(d, 0, NULL);
            rv = -ENOMEM;
            goto out;
        }

    /* Init the hash table */
    if ( shadow_hash_alloc(d) != 0 )
    {
        set_sh_allocation(d, old_pages, NULL);            
        rv = -ENOMEM;
        goto out;
    }

    /* Init the P2M table */
    if ( mode & SHM2_translate )
        if ( !shadow_alloc_p2m_table(d) )
        {
            shadow_hash_teardown(d);
            set_sh_allocation(d, old_pages, NULL);
            shadow_p2m_teardown(d);
            rv = -ENOMEM;
            goto out;
        }

    /* Update the bits */
    sh_new_mode(d, mode);
    shadow_audit_p2m(d);
 out:
    shadow_unlock(d);
    domain_unpause(d);
    return 0;
}

void shadow_teardown(struct domain *d)
/* Destroy the shadow pagetables of this domain and free its shadow memory.
 * Should only be called for dying domains. */
{
    struct vcpu *v;
    mfn_t mfn;

    ASSERT(test_bit(_DOMF_dying, &d->domain_flags));
    ASSERT(d != current->domain);

    if ( !shadow_lock_is_acquired(d) )
        shadow_lock(d); /* Keep various asserts happy */

    if ( shadow_mode_enabled(d) )
    {
        /* Release the shadow and monitor tables held by each vcpu */
        for_each_vcpu(d, v)
        {
            shadow_detach_old_tables(v);
            if ( shadow_mode_external(d) )
            {
                mfn = pagetable_get_mfn(v->arch.monitor_table);
                if ( valid_mfn(mfn) && (mfn_x(mfn) != 0) )
                    shadow_destroy_monitor_table(v, mfn);
                v->arch.monitor_table = pagetable_null();
            }
        }
    }

    if ( d->arch.shadow.total_pages != 0 )
    {
        SHADOW_PRINTK("teardown of domain %u starts."
                       "  Shadow pages total = %u, free = %u, p2m=%u\n",
                       d->domain_id,
                       d->arch.shadow.total_pages, 
                       d->arch.shadow.free_pages, 
                       d->arch.shadow.p2m_pages);
        /* Destroy all the shadows and release memory to domheap */
        set_sh_allocation(d, 0, NULL);
        /* Release the hash table back to xenheap */
        if (d->arch.shadow.hash_table) 
            shadow_hash_teardown(d);
        /* Release the log-dirty bitmap of dirtied pages */
        sh_free_log_dirty_bitmap(d);
        /* Should not have any more memory held */
        SHADOW_PRINTK("teardown done."
                       "  Shadow pages total = %u, free = %u, p2m=%u\n",
                       d->arch.shadow.total_pages, 
                       d->arch.shadow.free_pages, 
                       d->arch.shadow.p2m_pages);
        ASSERT(d->arch.shadow.total_pages == 0);
    }

    /* We leave the "permanent" shadow modes enabled, but clear the
     * log-dirty mode bit.  We don't want any more mark_dirty()
     * calls now that we've torn down the bitmap */
    d->arch.shadow.mode &= ~SHM2_log_dirty;

    shadow_unlock(d);
}

void shadow_final_teardown(struct domain *d)
/* Called by arch_domain_destroy(), when it's safe to pull down the p2m map. */
{

    SHADOW_PRINTK("dom %u final teardown starts."
                   "  Shadow pages total = %u, free = %u, p2m=%u\n",
                   d->domain_id,
                   d->arch.shadow.total_pages, 
                   d->arch.shadow.free_pages, 
                   d->arch.shadow.p2m_pages);

    /* Double-check that the domain didn't have any shadow memory.  
     * It is possible for a domain that never got domain_kill()ed
     * to get here with its shadow allocation intact. */
    if ( d->arch.shadow.total_pages != 0 )
        shadow_teardown(d);

    /* It is now safe to pull down the p2m map. */
    if ( d->arch.shadow.p2m_pages != 0 )
        shadow_p2m_teardown(d);

    SHADOW_PRINTK("dom %u final teardown done."
                   "  Shadow pages total = %u, free = %u, p2m=%u\n",
                   d->domain_id,
                   d->arch.shadow.total_pages, 
                   d->arch.shadow.free_pages, 
                   d->arch.shadow.p2m_pages);
}

static int shadow_one_bit_enable(struct domain *d, u32 mode)
/* Turn on a single shadow mode feature */
{
    ASSERT(shadow_lock_is_acquired(d));

    /* Sanity check the call */
    if ( d == current->domain || (d->arch.shadow.mode & mode) )
    {
        return -EINVAL;
    }

    if ( d->arch.shadow.mode == 0 )
    {
        /* Init the shadow memory allocation and the hash table */
        if ( set_sh_allocation(d, 1, NULL) != 0 
             || shadow_hash_alloc(d) != 0 )
        {
            set_sh_allocation(d, 0, NULL);
            return -ENOMEM;
        }
    }

    /* Update the bits */
    sh_new_mode(d, d->arch.shadow.mode | mode);

    return 0;
}

static int shadow_one_bit_disable(struct domain *d, u32 mode) 
/* Turn off a single shadow mode feature */
{
    struct vcpu *v;
    ASSERT(shadow_lock_is_acquired(d));

    /* Sanity check the call */
    if ( d == current->domain || !(d->arch.shadow.mode & mode) )
    {
        return -EINVAL;
    }

    /* Update the bits */
    sh_new_mode(d, d->arch.shadow.mode & ~mode);
    if ( d->arch.shadow.mode == 0 )
    {
        /* Get this domain off shadows */
        SHADOW_PRINTK("un-shadowing of domain %u starts."
                       "  Shadow pages total = %u, free = %u, p2m=%u\n",
                       d->domain_id,
                       d->arch.shadow.total_pages, 
                       d->arch.shadow.free_pages, 
                       d->arch.shadow.p2m_pages);
        for_each_vcpu(d, v)
        {
            shadow_detach_old_tables(v);
#if CONFIG_PAGING_LEVELS == 4
            if ( !(v->arch.flags & TF_kernel_mode) )
                make_cr3(v, pagetable_get_pfn(v->arch.guest_table_user));
            else
#endif
                make_cr3(v, pagetable_get_pfn(v->arch.guest_table));

        }

        /* Pull down the memory allocation */
        if ( set_sh_allocation(d, 0, NULL) != 0 )
        {
            // XXX - How can this occur?
            //       Seems like a bug to return an error now that we've
            //       disabled the relevant shadow mode.
            //
            return -ENOMEM;
        }
        shadow_hash_teardown(d);
        SHADOW_PRINTK("un-shadowing of domain %u done."
                       "  Shadow pages total = %u, free = %u, p2m=%u\n",
                       d->domain_id,
                       d->arch.shadow.total_pages, 
                       d->arch.shadow.free_pages, 
                       d->arch.shadow.p2m_pages);
    }

    return 0;
}

/* Enable/disable ops for the "test" and "log-dirty" modes */
int shadow_test_enable(struct domain *d)
{
    int ret;

    domain_pause(d);
    shadow_lock(d);

    if ( shadow_mode_enabled(d) )
    {
        SHADOW_ERROR("Don't support enabling test mode"
                      "on already shadowed doms\n");
        ret = -EINVAL;
        goto out;
    }

    ret = shadow_one_bit_enable(d, SHM2_enable);
 out:
    shadow_unlock(d);
    domain_unpause(d);

    return ret;
}

int shadow_test_disable(struct domain *d)
{
    int ret;

    domain_pause(d);
    shadow_lock(d);
    ret = shadow_one_bit_disable(d, SHM2_enable);
    shadow_unlock(d);
    domain_unpause(d);

    return ret;
}

static int
sh_alloc_log_dirty_bitmap(struct domain *d)
{
    ASSERT(d->arch.shadow.dirty_bitmap == NULL);
    d->arch.shadow.dirty_bitmap_size =
        (d->shared_info->arch.max_pfn + (BITS_PER_LONG - 1)) &
        ~(BITS_PER_LONG - 1);
    d->arch.shadow.dirty_bitmap =
        xmalloc_array(unsigned long,
                      d->arch.shadow.dirty_bitmap_size / BITS_PER_LONG);
    if ( d->arch.shadow.dirty_bitmap == NULL )
    {
        d->arch.shadow.dirty_bitmap_size = 0;
        return -ENOMEM;
    }
    memset(d->arch.shadow.dirty_bitmap, 0, d->arch.shadow.dirty_bitmap_size/8);

    return 0;
}

static void
sh_free_log_dirty_bitmap(struct domain *d)
{
    d->arch.shadow.dirty_bitmap_size = 0;
    if ( d->arch.shadow.dirty_bitmap )
    {
        xfree(d->arch.shadow.dirty_bitmap);
        d->arch.shadow.dirty_bitmap = NULL;
    }
}

static int shadow_log_dirty_enable(struct domain *d)
{
    int ret;

    domain_pause(d);
    shadow_lock(d);

    if ( shadow_mode_log_dirty(d) )
    {
        ret = -EINVAL;
        goto out;
    }

    if ( shadow_mode_enabled(d) )
    {
        SHADOW_ERROR("Don't (yet) support enabling log-dirty"
                      "on already shadowed doms\n");
        ret = -EINVAL;
        goto out;
    }

    ret = sh_alloc_log_dirty_bitmap(d);
    if ( ret != 0 )
    {
        sh_free_log_dirty_bitmap(d);
        goto out;
    }

    ret = shadow_one_bit_enable(d, SHM2_log_dirty);
    if ( ret != 0 )
        sh_free_log_dirty_bitmap(d);

 out:
    shadow_unlock(d);
    domain_unpause(d);
    return ret;
}

static int shadow_log_dirty_disable(struct domain *d)
{
    int ret;

    domain_pause(d);
    shadow_lock(d);
    ret = shadow_one_bit_disable(d, SHM2_log_dirty);
    if ( !shadow_mode_log_dirty(d) )
        sh_free_log_dirty_bitmap(d);
    shadow_unlock(d);
    domain_unpause(d);

    return ret;
}

/**************************************************************************/
/* P2M map manipulations */

static void
sh_p2m_remove_page(struct domain *d, unsigned long gfn, unsigned long mfn)
{
    struct vcpu *v;

    if ( !shadow_mode_translate(d) )
        return;

    v = current;
    if ( v->domain != d )
        v = d->vcpu[0];


    SHADOW_DEBUG(P2M, "removing gfn=%#lx mfn=%#lx\n", gfn, mfn);

    ASSERT(mfn_x(sh_gfn_to_mfn(d, gfn)) == mfn);
    //ASSERT(sh_mfn_to_gfn(d, mfn) == gfn);

    shadow_remove_all_shadows_and_parents(v, _mfn(mfn));
    if ( shadow_remove_all_mappings(v, _mfn(mfn)) )
        flush_tlb_mask(d->domain_dirty_cpumask);
    shadow_set_p2m_entry(d, gfn, _mfn(INVALID_MFN));
    set_gpfn_from_mfn(mfn, INVALID_M2P_ENTRY);
}

void
shadow_guest_physmap_remove_page(struct domain *d, unsigned long gfn,
                                  unsigned long mfn)
{
    shadow_lock(d);
    shadow_audit_p2m(d);
    sh_p2m_remove_page(d, gfn, mfn);
    shadow_audit_p2m(d);
    shadow_unlock(d);    
}

void
shadow_guest_physmap_add_page(struct domain *d, unsigned long gfn,
                               unsigned long mfn)
{
    struct vcpu *v;
    unsigned long ogfn;
    mfn_t omfn;

    if ( !shadow_mode_translate(d) )
        return;

    v = current;
    if ( v->domain != d )
        v = d->vcpu[0];

    shadow_lock(d);
    shadow_audit_p2m(d);

    SHADOW_DEBUG(P2M, "adding gfn=%#lx mfn=%#lx\n", gfn, mfn);

    omfn = sh_gfn_to_mfn(d, gfn);
    if ( valid_mfn(omfn) )
    {
        /* Get rid of the old mapping, especially any shadows */
        shadow_remove_all_shadows_and_parents(v, omfn);
        if ( shadow_remove_all_mappings(v, omfn) )
            flush_tlb_mask(d->domain_dirty_cpumask);
        set_gpfn_from_mfn(mfn_x(omfn), INVALID_M2P_ENTRY);
    }        

    ogfn = sh_mfn_to_gfn(d, _mfn(mfn));
    if (
#ifdef __x86_64__
        (ogfn != 0x5555555555555555L)
#else
        (ogfn != 0x55555555L)
#endif
        && (ogfn != INVALID_M2P_ENTRY)
        && (ogfn != gfn) )
    {
        /* This machine frame is already mapped at another physical address */
        SHADOW_DEBUG(P2M, "aliased! mfn=%#lx, old gfn=%#lx, new gfn=%#lx\n",
                       mfn, ogfn, gfn);
        if ( valid_mfn(omfn = sh_gfn_to_mfn(d, ogfn)) ) 
        {
            SHADOW_DEBUG(P2M, "old gfn=%#lx -> mfn %#lx\n", 
                           ogfn , mfn_x(omfn));
            if ( mfn_x(omfn) == mfn ) 
                sh_p2m_remove_page(d, ogfn, mfn);
        }
    }

    shadow_set_p2m_entry(d, gfn, _mfn(mfn));
    set_gpfn_from_mfn(mfn, gfn);
    shadow_audit_p2m(d);
    shadow_unlock(d);
}

/**************************************************************************/
/* Log-dirty mode support */

/* Convert a shadow to log-dirty mode. */
void shadow_convert_to_log_dirty(struct vcpu *v, mfn_t smfn)
{
    BUG();
}


/* Read a domain's log-dirty bitmap and stats.  
 * If the operation is a CLEAN, clear the bitmap and stats as well. */
static int shadow_log_dirty_op(
    struct domain *d, struct xen_domctl_shadow_op *sc)
{
    int i, rv = 0, clean = 0;

    domain_pause(d);
    shadow_lock(d);

    clean = (sc->op == XEN_DOMCTL_SHADOW_OP_CLEAN);

    SHADOW_DEBUG(LOGDIRTY, "log-dirty %s: dom %u faults=%u dirty=%u\n", 
                  (clean) ? "clean" : "peek",
                  d->domain_id,
                  d->arch.shadow.fault_count, 
                  d->arch.shadow.dirty_count);

    sc->stats.fault_count = d->arch.shadow.fault_count;
    sc->stats.dirty_count = d->arch.shadow.dirty_count;    
        
    if ( clean ) 
    {
        struct list_head *l, *t;
        struct page_info *pg;

        /* Need to revoke write access to the domain's pages again. 
         * In future, we'll have a less heavy-handed approach to this, 
         * but for now, we just unshadow everything except Xen. */
        list_for_each_safe(l, t, &d->arch.shadow.toplevel_shadows)
        {
            pg = list_entry(l, struct page_info, list);
            shadow_unhook_mappings(d->vcpu[0], page_to_mfn(pg));
        }

        d->arch.shadow.fault_count = 0;
        d->arch.shadow.dirty_count = 0;
    }

    if ( guest_handle_is_null(sc->dirty_bitmap) ||
         (d->arch.shadow.dirty_bitmap == NULL) )
    {
        rv = -EINVAL;
        goto out;
    }
 
    if ( sc->pages > d->arch.shadow.dirty_bitmap_size )
        sc->pages = d->arch.shadow.dirty_bitmap_size; 

#define CHUNK (8*1024) /* Transfer and clear in 1kB chunks for L1 cache. */
    for ( i = 0; i < sc->pages; i += CHUNK )
    {
        int bytes = ((((sc->pages - i) > CHUNK) 
                      ? CHUNK 
                      : (sc->pages - i)) + 7) / 8;
     
        if ( copy_to_guest_offset(
                 sc->dirty_bitmap, 
                 i/(8*sizeof(unsigned long)),
                 d->arch.shadow.dirty_bitmap + (i/(8*sizeof(unsigned long))),
                 (bytes + sizeof(unsigned long) - 1) / sizeof(unsigned long)) )
        {
            rv = -EINVAL;
            goto out;
        }

        if ( clean )
            memset(d->arch.shadow.dirty_bitmap + (i/(8*sizeof(unsigned long))),
                   0, bytes);
    }
#undef CHUNK

 out:
    shadow_unlock(d);
    domain_unpause(d);
    return 0;
}


/* Mark a page as dirty */
void sh_do_mark_dirty(struct domain *d, mfn_t gmfn)
{
    unsigned long pfn;

    ASSERT(shadow_lock_is_acquired(d));
    ASSERT(shadow_mode_log_dirty(d));

    if ( !valid_mfn(gmfn) )
        return;

    ASSERT(d->arch.shadow.dirty_bitmap != NULL);

    /* We /really/ mean PFN here, even for non-translated guests. */
    pfn = get_gpfn_from_mfn(mfn_x(gmfn));

    /*
     * Values with the MSB set denote MFNs that aren't really part of the 
     * domain's pseudo-physical memory map (e.g., the shared info frame).
     * Nothing to do here...
     */
    if ( unlikely(!VALID_M2P(pfn)) )
        return;

    /* N.B. Can use non-atomic TAS because protected by shadow_lock. */
    if ( likely(pfn < d->arch.shadow.dirty_bitmap_size) ) 
    { 
        if ( !__test_and_set_bit(pfn, d->arch.shadow.dirty_bitmap) )
        {
            SHADOW_DEBUG(LOGDIRTY, 
                          "marked mfn %" SH_PRI_mfn " (pfn=%lx), dom %d\n",
                          mfn_x(gmfn), pfn, d->domain_id);
            d->arch.shadow.dirty_count++;
        }
    }
    else
    {
        SHADOW_PRINTK("mark_dirty OOR! "
                       "mfn=%" SH_PRI_mfn " pfn=%lx max=%x (dom %d)\n"
                       "owner=%d c=%08x t=%" PRtype_info "\n",
                       mfn_x(gmfn), 
                       pfn, 
                       d->arch.shadow.dirty_bitmap_size,
                       d->domain_id,
                       (page_get_owner(mfn_to_page(gmfn))
                        ? page_get_owner(mfn_to_page(gmfn))->domain_id
                        : -1),
                       mfn_to_page(gmfn)->count_info, 
                       mfn_to_page(gmfn)->u.inuse.type_info);
    }
}


/**************************************************************************/
/* Shadow-control XEN_DOMCTL dispatcher */

int shadow_domctl(struct domain *d, 
                   xen_domctl_shadow_op_t *sc,
                   XEN_GUEST_HANDLE(xen_domctl_t) u_domctl)
{
    int rc, preempted = 0;

    if ( unlikely(d == current->domain) )
    {
        DPRINTK("Don't try to do a shadow op on yourself!\n");
        return -EINVAL;
    }

    switch ( sc->op )
    {
    case XEN_DOMCTL_SHADOW_OP_OFF:
        if ( shadow_mode_log_dirty(d) )
            if ( (rc = shadow_log_dirty_disable(d)) != 0 ) 
                return rc;
        if ( d->arch.shadow.mode & SHM2_enable )
            if ( (rc = shadow_test_disable(d)) != 0 ) 
                return rc;
        return 0;

    case XEN_DOMCTL_SHADOW_OP_ENABLE_TEST:
        return shadow_test_enable(d);

    case XEN_DOMCTL_SHADOW_OP_ENABLE_LOGDIRTY:
        return shadow_log_dirty_enable(d);

    case XEN_DOMCTL_SHADOW_OP_ENABLE_TRANSLATE:
        return shadow_enable(d, SHM2_refcounts|SHM2_translate);

    case XEN_DOMCTL_SHADOW_OP_CLEAN:
    case XEN_DOMCTL_SHADOW_OP_PEEK:
        return shadow_log_dirty_op(d, sc);

    case XEN_DOMCTL_SHADOW_OP_ENABLE:
        if ( sc->mode & XEN_DOMCTL_SHADOW_ENABLE_LOG_DIRTY )
            return shadow_log_dirty_enable(d);
        return shadow_enable(d, sc->mode << SHM2_shift);

    case XEN_DOMCTL_SHADOW_OP_GET_ALLOCATION:
        sc->mb = shadow_get_allocation(d);
        return 0;

    case XEN_DOMCTL_SHADOW_OP_SET_ALLOCATION:
        rc = shadow_set_allocation(d, sc->mb, &preempted);
        if ( preempted )
            /* Not finished.  Set up to re-run the call. */
            rc = hypercall_create_continuation(
                __HYPERVISOR_domctl, "h", u_domctl);
        else 
            /* Finished.  Return the new allocation */
            sc->mb = shadow_get_allocation(d);
        return rc;

    default:
        SHADOW_ERROR("Bad shadow op %u\n", sc->op);
        return -EINVAL;
    }
}


/**************************************************************************/
/* Auditing shadow tables */

#if SHADOW_AUDIT & SHADOW_AUDIT_ENTRIES_FULL

void shadow_audit_tables(struct vcpu *v) 
{
    /* Dispatch table for getting per-type functions */
    static hash_callback_t callbacks[16] = {
        NULL, /* none    */
#if CONFIG_PAGING_LEVELS == 2
        SHADOW_INTERNAL_NAME(sh_audit_l1_table,2,2),  /* l1_32   */
        SHADOW_INTERNAL_NAME(sh_audit_fl1_table,2,2), /* fl1_32  */
        SHADOW_INTERNAL_NAME(sh_audit_l2_table,2,2),  /* l2_32   */
#else 
        SHADOW_INTERNAL_NAME(sh_audit_l1_table,3,2),  /* l1_32   */
        SHADOW_INTERNAL_NAME(sh_audit_fl1_table,3,2), /* fl1_32  */
        SHADOW_INTERNAL_NAME(sh_audit_l2_table,3,2),  /* l2_32   */
        SHADOW_INTERNAL_NAME(sh_audit_l1_table,3,3),  /* l1_pae  */
        SHADOW_INTERNAL_NAME(sh_audit_fl1_table,3,3), /* fl1_pae */
        SHADOW_INTERNAL_NAME(sh_audit_l2_table,3,3),  /* l2_pae  */
        SHADOW_INTERNAL_NAME(sh_audit_l2_table,3,3),  /* l2h_pae */
        SHADOW_INTERNAL_NAME(sh_audit_l3_table,3,3),  /* l3_pae  */
#if CONFIG_PAGING_LEVELS >= 4
        SHADOW_INTERNAL_NAME(sh_audit_l1_table,4,4),  /* l1_64   */
        SHADOW_INTERNAL_NAME(sh_audit_fl1_table,4,4), /* fl1_64  */
        SHADOW_INTERNAL_NAME(sh_audit_l2_table,4,4),  /* l2_64   */
        SHADOW_INTERNAL_NAME(sh_audit_l3_table,4,4),  /* l3_64   */
        SHADOW_INTERNAL_NAME(sh_audit_l4_table,4,4),  /* l4_64   */
#endif /* CONFIG_PAGING_LEVELS >= 4 */
#endif /* CONFIG_PAGING_LEVELS > 2 */
        NULL  /* All the rest */
    };
    unsigned int mask; 

    if ( !(SHADOW_AUDIT_ENABLE) )
        return;
    
    if ( SHADOW_AUDIT & SHADOW_AUDIT_ENTRIES_FULL )
        mask = ~1; /* Audit every table in the system */
    else 
    {
        /* Audit only the current mode's tables */
        switch ( v->arch.shadow.mode->guest_levels )
        {
        case 2: mask = (SHF_L1_32|SHF_FL1_32|SHF_L2_32); break;
        case 3: mask = (SHF_L1_PAE|SHF_FL1_PAE|SHF_L2_PAE
                        |SHF_L2H_PAE|SHF_L3_PAE); break;
        case 4: mask = (SHF_L1_64|SHF_FL1_64|SHF_L2_64  
                        |SHF_L3_64|SHF_L4_64); break;
        default: BUG();
        }
    }

    hash_foreach(v, ~1, callbacks, _mfn(INVALID_MFN));
}

#endif /* Shadow audit */


/**************************************************************************/
/* Auditing p2m tables */

#if SHADOW_AUDIT & SHADOW_AUDIT_P2M

void shadow_audit_p2m(struct domain *d)
{
    struct list_head *entry;
    struct page_info *page;
    struct domain *od;
    unsigned long mfn, gfn, m2pfn, lp2mfn = 0;
    mfn_t p2mfn;
    unsigned long orphans_d = 0, orphans_i = 0, mpbad = 0, pmbad = 0;
    int test_linear;
    
    if ( !(SHADOW_AUDIT_ENABLE) || !shadow_mode_translate(d) )
        return;

    //SHADOW_PRINTK("p2m audit starts\n");

    test_linear = ( (d == current->domain) && current->arch.monitor_vtable );
    if ( test_linear )
        local_flush_tlb(); 

    /* Audit part one: walk the domain's page allocation list, checking 
     * the m2p entries. */
    for ( entry = d->page_list.next;
          entry != &d->page_list;
          entry = entry->next )
    {
        page = list_entry(entry, struct page_info, list);
        mfn = mfn_x(page_to_mfn(page));

        // SHADOW_PRINTK("auditing guest page, mfn=%#lx\n", mfn); 

        od = page_get_owner(page);

        if ( od != d ) 
        {
            SHADOW_PRINTK("wrong owner %#lx -> %p(%u) != %p(%u)\n",
                           mfn, od, (od?od->domain_id:-1), d, d->domain_id);
            continue;
        }

        gfn = get_gpfn_from_mfn(mfn);
        if ( gfn == INVALID_M2P_ENTRY ) 
        {
            orphans_i++;
            //SHADOW_PRINTK("orphaned guest page: mfn=%#lx has invalid gfn\n",
            //               mfn); 
            continue;
        }

        if ( gfn == 0x55555555 ) 
        {
            orphans_d++;
            //SHADOW_PRINTK("orphaned guest page: mfn=%#lx has debug gfn\n", 
            //               mfn); 
            continue;
        }

        p2mfn = sh_gfn_to_mfn_foreign(d, gfn);
        if ( mfn_x(p2mfn) != mfn )
        {
            mpbad++;
            SHADOW_PRINTK("map mismatch mfn %#lx -> gfn %#lx -> mfn %#lx"
                           " (-> gfn %#lx)\n",
                           mfn, gfn, mfn_x(p2mfn),
                           (mfn_valid(p2mfn)
                            ? get_gpfn_from_mfn(mfn_x(p2mfn))
                            : -1u));
            /* This m2p entry is stale: the domain has another frame in
             * this physical slot.  No great disaster, but for neatness,
             * blow away the m2p entry. */ 
            set_gpfn_from_mfn(mfn, INVALID_M2P_ENTRY);
        }

        if ( test_linear )
        {
            lp2mfn = get_mfn_from_gpfn(gfn);
            if ( lp2mfn != mfn_x(p2mfn) )
            {
                SHADOW_PRINTK("linear mismatch gfn %#lx -> mfn %#lx "
                               "(!= mfn %#lx)\n", gfn, lp2mfn, p2mfn);
            }
        }

        // SHADOW_PRINTK("OK: mfn=%#lx, gfn=%#lx, p2mfn=%#lx, lp2mfn=%#lx\n", 
        //                mfn, gfn, p2mfn, lp2mfn); 
    }   

    /* Audit part two: walk the domain's p2m table, checking the entries. */
    if ( pagetable_get_pfn(d->arch.phys_table) != 0 )
    {
        l2_pgentry_t *l2e;
        l1_pgentry_t *l1e;
        int i1, i2;
        
#if CONFIG_PAGING_LEVELS == 4
        l4_pgentry_t *l4e;
        l3_pgentry_t *l3e;
        int i3, i4;
        l4e = sh_map_domain_page(pagetable_get_mfn(d->arch.phys_table));
#elif CONFIG_PAGING_LEVELS == 3
        l3_pgentry_t *l3e;
        int i3;
        l3e = sh_map_domain_page(pagetable_get_mfn(d->arch.phys_table));
#else /* CONFIG_PAGING_LEVELS == 2 */
        l2e = sh_map_domain_page(pagetable_get_mfn(d->arch.phys_table));
#endif

        gfn = 0;
#if CONFIG_PAGING_LEVELS >= 3
#if CONFIG_PAGING_LEVELS >= 4
        for ( i4 = 0; i4 < L4_PAGETABLE_ENTRIES; i4++ )
        {
            if ( !(l4e_get_flags(l4e[i4]) & _PAGE_PRESENT) )
            {
                gfn += 1 << (L4_PAGETABLE_SHIFT - PAGE_SHIFT);
                continue;
            }
            l3e = sh_map_domain_page(_mfn(l4e_get_pfn(l4e[i4])));
#endif /* now at levels 3 or 4... */
            for ( i3 = 0; 
                  i3 < ((CONFIG_PAGING_LEVELS==4) ? L3_PAGETABLE_ENTRIES : 8); 
                  i3++ )
            {
                if ( !(l3e_get_flags(l3e[i3]) & _PAGE_PRESENT) )
                {
                    gfn += 1 << (L3_PAGETABLE_SHIFT - PAGE_SHIFT);
                    continue;
                }
                l2e = sh_map_domain_page(_mfn(l3e_get_pfn(l3e[i3])));
#endif /* all levels... */
                for ( i2 = 0; i2 < L2_PAGETABLE_ENTRIES; i2++ )
                {
                    if ( !(l2e_get_flags(l2e[i2]) & _PAGE_PRESENT) )
                    {
                        gfn += 1 << (L2_PAGETABLE_SHIFT - PAGE_SHIFT);
                        continue;
                    }
                    l1e = sh_map_domain_page(_mfn(l2e_get_pfn(l2e[i2])));
                    
                    for ( i1 = 0; i1 < L1_PAGETABLE_ENTRIES; i1++, gfn++ )
                    {
                        if ( !(l1e_get_flags(l1e[i1]) & _PAGE_PRESENT) )
                            continue;
                        mfn = l1e_get_pfn(l1e[i1]);
                        ASSERT(valid_mfn(_mfn(mfn)));
                        m2pfn = get_gpfn_from_mfn(mfn);
                        if ( m2pfn != gfn )
                        {
                            pmbad++;
                            SHADOW_PRINTK("mismatch: gfn %#lx -> mfn %#lx"
                                           " -> gfn %#lx\n", gfn, mfn, m2pfn);
                            BUG();
                        }
                    }
                    sh_unmap_domain_page(l1e);
                }
#if CONFIG_PAGING_LEVELS >= 3
                sh_unmap_domain_page(l2e);
            }
#if CONFIG_PAGING_LEVELS >= 4
            sh_unmap_domain_page(l3e);
        }
#endif
#endif

#if CONFIG_PAGING_LEVELS == 4
        sh_unmap_domain_page(l4e);
#elif CONFIG_PAGING_LEVELS == 3
        sh_unmap_domain_page(l3e);
#else /* CONFIG_PAGING_LEVELS == 2 */
        sh_unmap_domain_page(l2e);
#endif

    }

    //SHADOW_PRINTK("p2m audit complete\n");
    //if ( orphans_i | orphans_d | mpbad | pmbad ) 
    //    SHADOW_PRINTK("p2m audit found %lu orphans (%lu inval %lu debug)\n",
    //                   orphans_i + orphans_d, orphans_i, orphans_d,
    if ( mpbad | pmbad ) 
        SHADOW_PRINTK("p2m audit found %lu odd p2m, %lu bad m2p entries\n",
                       pmbad, mpbad);
}

#endif /* p2m audit */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End: 
 */
