
/******************************************************************************
 * arch/x86/mm/shadow/hvm.c
 *
 * Shadow code that does not need to be multiply compiled and is HVM only.
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
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/domain_page.h>
#include <xen/guest_access.h>
#include <xen/sched.h>
#include <xen/types.h>
#include <xen/trace.h>

#include <asm/current.h>
#include <asm/shadow.h>

#include "private.h"

/**************************************************************************/
/* x86 emulator support for the shadow code
 */

/*
 * Returns a mapped pointer to write to, or one of the following error
 * indicators.
 */
#define MAPPING_UNHANDLEABLE ERR_PTR(~(long)X86EMUL_UNHANDLEABLE)
#define MAPPING_EXCEPTION    ERR_PTR(~(long)X86EMUL_EXCEPTION)
#define MAPPING_SILENT_FAIL  ERR_PTR(~(long)X86EMUL_OKAY)
static void *sh_emulate_map_dest(struct vcpu *v, unsigned long vaddr,
                                 unsigned int bytes,
                                 struct sh_emulate_ctxt *sh_ctxt);
static void sh_emulate_unmap_dest(struct vcpu *v, void *addr,
                                  unsigned int bytes,
                                  struct sh_emulate_ctxt *sh_ctxt);

/*
 * Callers which pass a known in-range x86_segment can rely on the return
 * pointer being valid.  Other callers must explicitly check for errors.
 */
static struct segment_register *hvm_get_seg_reg(
    enum x86_segment seg, struct sh_emulate_ctxt *sh_ctxt)
{
    unsigned int idx = seg;
    struct segment_register *seg_reg;

    if ( idx >= ARRAY_SIZE(sh_ctxt->seg_reg) )
        return ERR_PTR(-X86EMUL_UNHANDLEABLE);

    seg_reg = &sh_ctxt->seg_reg[idx];
    if ( !__test_and_set_bit(idx, &sh_ctxt->valid_seg_regs) )
        hvm_get_segment_register(current, idx, seg_reg);
    return seg_reg;
}

static int hvm_translate_virtual_addr(
    enum x86_segment seg,
    unsigned long offset,
    unsigned int bytes,
    enum hvm_access_type access_type,
    struct sh_emulate_ctxt *sh_ctxt,
    unsigned long *linear)
{
    const struct segment_register *reg;
    int okay;

    reg = hvm_get_seg_reg(seg, sh_ctxt);
    if ( IS_ERR(reg) )
        return -PTR_ERR(reg);

    okay = hvm_virtual_to_linear_addr(
        seg, reg, offset, bytes, access_type,
        hvm_get_seg_reg(x86_seg_cs, sh_ctxt), linear);

    if ( !okay )
    {
        /*
         * Leave exception injection to the caller for non-user segments: We
         * neither know the exact error code to be used, nor can we easily
         * determine the kind of exception (#GP or #TS) in that case.
         */
        if ( is_x86_user_segment(seg) )
            x86_emul_hw_exception(
                (seg == x86_seg_ss) ? TRAP_stack_error : TRAP_gp_fault,
                0, &sh_ctxt->ctxt);
        return X86EMUL_EXCEPTION;
    }

    return 0;
}

static int
hvm_read(enum x86_segment seg,
         unsigned long offset,
         void *p_data,
         unsigned int bytes,
         enum hvm_access_type access_type,
         struct sh_emulate_ctxt *sh_ctxt)
{
    pagefault_info_t pfinfo;
    unsigned long addr;
    int rc;

    rc = hvm_translate_virtual_addr(
        seg, offset, bytes, access_type, sh_ctxt, &addr);
    if ( rc || !bytes )
        return rc;

    rc = hvm_copy_from_guest_linear(p_data, addr, bytes,
                                    (access_type == hvm_access_insn_fetch
                                     ? PFEC_insn_fetch : 0),
                                    &pfinfo);

    switch ( rc )
    {
    case HVMTRANS_okay:
        return X86EMUL_OKAY;
    case HVMTRANS_bad_linear_to_gfn:
        x86_emul_pagefault(pfinfo.ec, pfinfo.linear, &sh_ctxt->ctxt);
        return X86EMUL_EXCEPTION;
    case HVMTRANS_bad_gfn_to_mfn:
    case HVMTRANS_unhandleable:
        return X86EMUL_UNHANDLEABLE;
    case HVMTRANS_gfn_paged_out:
    case HVMTRANS_gfn_shared:
    case HVMTRANS_need_retry:
        return X86EMUL_RETRY;
    }

    BUG();
    return X86EMUL_UNHANDLEABLE;
}

static int
hvm_emulate_read(enum x86_segment seg,
                 unsigned long offset,
                 void *p_data,
                 unsigned int bytes,
                 struct x86_emulate_ctxt *ctxt)
{
    if ( !is_x86_user_segment(seg) )
        return X86EMUL_UNHANDLEABLE;
    return hvm_read(seg, offset, p_data, bytes, hvm_access_read,
                    container_of(ctxt, struct sh_emulate_ctxt, ctxt));
}

static int
hvm_emulate_insn_fetch(enum x86_segment seg,
                       unsigned long offset,
                       void *p_data,
                       unsigned int bytes,
                       struct x86_emulate_ctxt *ctxt)
{
    struct sh_emulate_ctxt *sh_ctxt =
        container_of(ctxt, struct sh_emulate_ctxt, ctxt);
    unsigned int insn_off = offset - sh_ctxt->insn_buf_eip;

    ASSERT(seg == x86_seg_cs);

    /* Fall back if requested bytes are not in the prefetch cache. */
    if ( unlikely((insn_off + bytes) > sh_ctxt->insn_buf_bytes) )
        return hvm_read(seg, offset, p_data, bytes,
                        hvm_access_insn_fetch, sh_ctxt);

    /* Hit the cache. Simple memcpy. */
    memcpy(p_data, &sh_ctxt->insn_buf[insn_off], bytes);
    return X86EMUL_OKAY;
}

static int
hvm_emulate_write(enum x86_segment seg,
                  unsigned long offset,
                  void *p_data,
                  unsigned int bytes,
                  struct x86_emulate_ctxt *ctxt)
{
    struct sh_emulate_ctxt *sh_ctxt =
        container_of(ctxt, struct sh_emulate_ctxt, ctxt);
    struct vcpu *v = current;
    unsigned long addr;
    void *ptr;
    int rc;

    /* How many emulations could we save if we unshadowed on stack writes? */
    if ( seg == x86_seg_ss )
        perfc_incr(shadow_fault_emulate_stack);

    rc = hvm_translate_virtual_addr(
        seg, offset, bytes, hvm_access_write, sh_ctxt, &addr);
    if ( rc || !bytes )
        return rc;

    /* Unaligned writes are only acceptable on HVM */
    if ( (addr & (bytes - 1)) && !is_hvm_vcpu(v)  )
        return X86EMUL_UNHANDLEABLE;

    ptr = sh_emulate_map_dest(v, addr, bytes, sh_ctxt);
    if ( IS_ERR(ptr) )
        return ~PTR_ERR(ptr);

    paging_lock(v->domain);
    memcpy(ptr, p_data, bytes);

    if ( tb_init_done )
        v->arch.paging.mode->shadow.trace_emul_write_val(ptr, addr,
                                                         p_data, bytes);

    sh_emulate_unmap_dest(v, ptr, bytes, sh_ctxt);
    shadow_audit_tables(v);
    paging_unlock(v->domain);

    return X86EMUL_OKAY;
}

static int
hvm_emulate_cmpxchg(enum x86_segment seg,
                    unsigned long offset,
                    void *p_old,
                    void *p_new,
                    unsigned int bytes,
                    bool lock,
                    struct x86_emulate_ctxt *ctxt)
{
    struct sh_emulate_ctxt *sh_ctxt =
        container_of(ctxt, struct sh_emulate_ctxt, ctxt);
    struct vcpu *v = current;
    unsigned long addr, old, new, prev;
    void *ptr;
    int rc;

    if ( bytes > sizeof(long) )
        return X86EMUL_UNHANDLEABLE;

    rc = hvm_translate_virtual_addr(
        seg, offset, bytes, hvm_access_write, sh_ctxt, &addr);
    if ( rc )
        return rc;

    /* Unaligned writes are only acceptable on HVM */
    if ( (addr & (bytes - 1)) && !is_hvm_vcpu(v)  )
        return X86EMUL_UNHANDLEABLE;

    ptr = sh_emulate_map_dest(v, addr, bytes, sh_ctxt);
    if ( IS_ERR(ptr) )
        return ~PTR_ERR(ptr);

    old = new = 0;
    memcpy(&old, p_old, bytes);
    memcpy(&new, p_new, bytes);

    paging_lock(v->domain);
    switch ( bytes )
    {
    case 1: prev = cmpxchg((uint8_t  *)ptr, old, new); break;
    case 2: prev = cmpxchg((uint16_t *)ptr, old, new); break;
    case 4: prev = cmpxchg((uint32_t *)ptr, old, new); break;
    case 8: prev = cmpxchg((uint64_t *)ptr, old, new); break;
    default:
        SHADOW_PRINTK("cmpxchg size %u is not supported\n", bytes);
        prev = ~old;
    }

    if ( prev != old )
    {
        memcpy(p_old, &prev, bytes);
        rc = X86EMUL_CMPXCHG_FAILED;
    }

    SHADOW_DEBUG(EMULATE,
                 "va %#lx was %#lx expected %#lx wanted %#lx now %#lx bytes %u\n",
                 addr, prev, old, new, *(unsigned long *)ptr, bytes);

    sh_emulate_unmap_dest(v, ptr, bytes, sh_ctxt);
    shadow_audit_tables(v);
    paging_unlock(v->domain);

    return rc;
}

static const struct x86_emulate_ops hvm_shadow_emulator_ops = {
    .read       = hvm_emulate_read,
    .insn_fetch = hvm_emulate_insn_fetch,
    .write      = hvm_emulate_write,
    .cmpxchg    = hvm_emulate_cmpxchg,
};

const struct x86_emulate_ops *shadow_init_emulation(
    struct sh_emulate_ctxt *sh_ctxt, struct cpu_user_regs *regs,
    unsigned int pte_size)
{
    struct segment_register *creg, *sreg;
    const struct vcpu *curr = current;
    unsigned long addr;

    ASSERT(is_hvm_vcpu(curr));

    memset(sh_ctxt, 0, sizeof(*sh_ctxt));

    sh_ctxt->ctxt.regs = regs;
    sh_ctxt->ctxt.cpuid = curr->domain->arch.cpuid;
    sh_ctxt->ctxt.lma = hvm_long_mode_active(curr);

    /* Segment cache initialisation. Primed with CS. */
    creg = hvm_get_seg_reg(x86_seg_cs, sh_ctxt);

    /* Work out the emulation mode. */
    if ( sh_ctxt->ctxt.lma && creg->l )
        sh_ctxt->ctxt.addr_size = sh_ctxt->ctxt.sp_size = 64;
    else
    {
        sreg = hvm_get_seg_reg(x86_seg_ss, sh_ctxt);
        sh_ctxt->ctxt.addr_size = creg->db ? 32 : 16;
        sh_ctxt->ctxt.sp_size   = sreg->db ? 32 : 16;
    }

    sh_ctxt->pte_size = pte_size;

    /* Attempt to prefetch whole instruction. */
    sh_ctxt->insn_buf_eip = regs->rip;
    sh_ctxt->insn_buf_bytes =
        (!hvm_translate_virtual_addr(
            x86_seg_cs, regs->rip, sizeof(sh_ctxt->insn_buf),
            hvm_access_insn_fetch, sh_ctxt, &addr) &&
         !hvm_copy_from_guest_linear(
             sh_ctxt->insn_buf, addr, sizeof(sh_ctxt->insn_buf),
             PFEC_insn_fetch, NULL))
        ? sizeof(sh_ctxt->insn_buf) : 0;

    return &hvm_shadow_emulator_ops;
}

/*
 * Update an initialized emulation context to prepare for the next
 * instruction.
 */
void shadow_continue_emulation(struct sh_emulate_ctxt *sh_ctxt,
                               struct cpu_user_regs *regs)
{
    unsigned long addr, diff;

    ASSERT(is_hvm_vcpu(current));

    /*
     * We don't refetch the segment bases, because we don't emulate
     * writes to segment registers
     */
    diff = regs->rip - sh_ctxt->insn_buf_eip;
    if ( diff > sh_ctxt->insn_buf_bytes )
    {
        /* Prefetch more bytes. */
        sh_ctxt->insn_buf_bytes =
            (!hvm_translate_virtual_addr(
                x86_seg_cs, regs->rip, sizeof(sh_ctxt->insn_buf),
                hvm_access_insn_fetch, sh_ctxt, &addr) &&
             !hvm_copy_from_guest_linear(
                 sh_ctxt->insn_buf, addr, sizeof(sh_ctxt->insn_buf),
                 PFEC_insn_fetch, NULL))
            ? sizeof(sh_ctxt->insn_buf) : 0;
        sh_ctxt->insn_buf_eip = regs->rip;
    }
}

/**************************************************************************/
/* Handling guest writes to pagetables. */

/*
 * Translate a VA to an MFN, injecting a page-fault if we fail.  If the
 * mapping succeeds, a reference will be held on the underlying page.
 */
#define BAD_GVA_TO_GFN (~0UL)
#define BAD_GFN_TO_MFN (~1UL)
#define READONLY_GFN   (~2UL)
static mfn_t emulate_gva_to_mfn(struct vcpu *v, unsigned long vaddr,
                                struct sh_emulate_ctxt *sh_ctxt)
{
    unsigned long gfn;
    struct page_info *page;
    mfn_t mfn;
    p2m_type_t p2mt;
    uint32_t pfec = PFEC_page_present | PFEC_write_access;

    /* Translate the VA to a GFN. */
    gfn = paging_get_hostmode(v)->gva_to_gfn(v, NULL, vaddr, &pfec);
    if ( gfn == gfn_x(INVALID_GFN) )
    {
        x86_emul_pagefault(pfec, vaddr, &sh_ctxt->ctxt);

        return _mfn(BAD_GVA_TO_GFN);
    }

    /* Translate the GFN to an MFN. */
    ASSERT(!paging_locked_by_me(v->domain));

    page = get_page_from_gfn(v->domain, gfn, &p2mt, P2M_ALLOC);

    /* Sanity checking. */
    if ( page == NULL )
    {
        return _mfn(BAD_GFN_TO_MFN);
    }
    if ( p2mt == p2m_ioreq_server )
    {
        put_page(page);
        return _mfn(BAD_GFN_TO_MFN);
    }
    if ( p2m_is_discard_write(p2mt) )
    {
        put_page(page);
        return _mfn(READONLY_GFN);
    }
    if ( !p2m_is_ram(p2mt) )
    {
        put_page(page);
        return _mfn(BAD_GFN_TO_MFN);
    }
    mfn = page_to_mfn(page);
    ASSERT(mfn_valid(mfn));

    v->arch.paging.last_write_was_pt = !!sh_mfn_is_a_page_table(mfn);

    return mfn;
}

/*
 * Check that the user is allowed to perform this write.  If a mapping is
 * returned, page references will be held on sh_ctxt->mfn[0] and
 * sh_ctxt->mfn[1] iff !INVALID_MFN.
 */
static void *sh_emulate_map_dest(struct vcpu *v, unsigned long vaddr,
                                 unsigned int bytes,
                                 struct sh_emulate_ctxt *sh_ctxt)
{
    struct domain *d = v->domain;
    void *map;

#ifndef NDEBUG
    /* We don't emulate user-mode writes to page tables. */
    if ( is_hvm_domain(d) ? hvm_get_cpl(v) == 3
                          : !guest_kernel_mode(v, guest_cpu_user_regs()) )
    {
        gdprintk(XENLOG_DEBUG, "User-mode write to pagetable reached "
                 "emulate_map_dest(). This should never happen!\n");
        return MAPPING_UNHANDLEABLE;
    }
#endif

    sh_ctxt->mfn[0] = emulate_gva_to_mfn(v, vaddr, sh_ctxt);
    if ( !mfn_valid(sh_ctxt->mfn[0]) )
    {
        switch ( mfn_x(sh_ctxt->mfn[0]) )
        {
        case BAD_GVA_TO_GFN: return MAPPING_EXCEPTION;
        case READONLY_GFN:   return MAPPING_SILENT_FAIL;
        default:             return MAPPING_UNHANDLEABLE;
        }
    }

    /* Unaligned writes mean probably this isn't a pagetable. */
    if ( vaddr & (bytes - 1) )
        sh_remove_shadows(d, sh_ctxt->mfn[0], 0, 0 /* Slow, can fail. */ );

    if ( likely(((vaddr + bytes - 1) & PAGE_MASK) == (vaddr & PAGE_MASK)) )
    {
        /* Whole write fits on a single page. */
        sh_ctxt->mfn[1] = INVALID_MFN;
        map = map_domain_page(sh_ctxt->mfn[0]) + (vaddr & ~PAGE_MASK);
    }
    else if ( !is_hvm_domain(d) )
    {
        /*
         * Cross-page emulated writes are only supported for HVM guests;
         * PV guests ought to know better.
         */
        put_page(mfn_to_page(sh_ctxt->mfn[0]));
        return MAPPING_UNHANDLEABLE;
    }
    else
    {
        /* This write crosses a page boundary. Translate the second page. */
        sh_ctxt->mfn[1] = emulate_gva_to_mfn(
            v, (vaddr + bytes - 1) & PAGE_MASK, sh_ctxt);
        if ( !mfn_valid(sh_ctxt->mfn[1]) )
        {
            put_page(mfn_to_page(sh_ctxt->mfn[0]));
            switch ( mfn_x(sh_ctxt->mfn[1]) )
            {
            case BAD_GVA_TO_GFN: return MAPPING_EXCEPTION;
            case READONLY_GFN:   return MAPPING_SILENT_FAIL;
            default:             return MAPPING_UNHANDLEABLE;
            }
        }

        /* Cross-page writes mean probably not a pagetable. */
        sh_remove_shadows(d, sh_ctxt->mfn[1], 0, 0 /* Slow, can fail. */ );

        map = vmap(sh_ctxt->mfn, 2);
        if ( !map )
        {
            put_page(mfn_to_page(sh_ctxt->mfn[0]));
            put_page(mfn_to_page(sh_ctxt->mfn[1]));
            return MAPPING_UNHANDLEABLE;
        }
        map += (vaddr & ~PAGE_MASK);
    }

#if (SHADOW_OPTIMIZATIONS & SHOPT_SKIP_VERIFY)
    /*
     * Remember if the bottom bit was clear, so we can choose not to run
     * the change through the verify code if it's still clear afterwards.
     */
    sh_ctxt->low_bit_was_clear = map != NULL && !(*(u8 *)map & _PAGE_PRESENT);
#endif

    return map;
}

/*
 * Optimization: If we see two emulated writes of zeros to the same
 * page-table without another kind of page fault in between, we guess
 * that this is a batch of changes (for process destruction) and
 * unshadow the page so we don't take a pagefault on every entry.  This
 * should also make finding writeable mappings of pagetables much
 * easier.
 *
 * Look to see if this is the second emulated write in a row to this
 * page, and unshadow if it is.
 */
static inline void check_for_early_unshadow(struct vcpu *v, mfn_t gmfn)
{
#if SHADOW_OPTIMIZATIONS & SHOPT_EARLY_UNSHADOW
    struct domain *d = v->domain;

    /*
     * If the domain has never made a "dying" op, use the two-writes
     * heuristic; otherwise, unshadow as soon as we write a zero for a dying
     * process.
     *
     * Don't bother trying to unshadow if it's not a PT, or if it's > l1.
     */
    if ( ( v->arch.paging.shadow.pagetable_dying
           || ( !d->arch.paging.shadow.pagetable_dying_op
                && v->arch.paging.shadow.last_emulated_mfn_for_unshadow == mfn_x(gmfn) ) )
         && sh_mfn_is_a_page_table(gmfn)
         && (!d->arch.paging.shadow.pagetable_dying_op ||
             !(mfn_to_page(gmfn)->shadow_flags
               & (SHF_L2_32|SHF_L2_PAE|SHF_L2H_PAE|SHF_L4_64))) )
    {
        perfc_incr(shadow_early_unshadow);
        sh_remove_shadows(d, gmfn, 1, 0 /* Fast, can fail to unshadow */ );
        TRACE_SHADOW_PATH_FLAG(TRCE_SFLAG_EARLY_UNSHADOW);
    }
    v->arch.paging.shadow.last_emulated_mfn_for_unshadow = mfn_x(gmfn);
#endif
}

/* This is the entry point for emulated writes to pagetables in HVM guests */
static void validate_guest_pt_write(struct vcpu *v, mfn_t gmfn,
                                    void *entry, unsigned int size)
{
    struct domain *d = v->domain;
    int rc;

    ASSERT(paging_locked_by_me(v->domain));

    rc = sh_validate_guest_entry(v, gmfn, entry, size);

    if ( rc & SHADOW_SET_FLUSH )
        /* Need to flush TLBs to pick up shadow PT changes */
        flush_tlb_mask(d->dirty_cpumask);

    if ( rc & SHADOW_SET_ERROR )
    {
        /*
         * This page is probably not a pagetable any more: tear it out of the
         * shadows, along with any tables that reference it.
         * Since the validate call above will have made a "safe" (i.e. zero)
         * shadow entry, we can let the domain live even if we can't fully
         * unshadow the page.
         */
        sh_remove_shadows(d, gmfn, 0, 0);
    }
}

/*
 * Tidy up after the emulated write: mark pages dirty, verify the new
 * contents, and undo the mapping.
 */
static void sh_emulate_unmap_dest(struct vcpu *v, void *addr,
                                  unsigned int bytes,
                                  struct sh_emulate_ctxt *sh_ctxt)
{
    u32 b1 = bytes, b2 = 0, shflags;

    ASSERT(mfn_valid(sh_ctxt->mfn[0]));

    /* If we are writing lots of PTE-aligned zeros, might want to unshadow */
    if ( likely(bytes >= 4) && (*(u32 *)addr == 0) )
    {
        if ( !((unsigned long)addr & (sh_ctxt->pte_size - 1)) )
            check_for_early_unshadow(v, sh_ctxt->mfn[0]);
        /*
         * Don't reset the heuristic if we're writing zeros at non-aligned
         * addresses, otherwise it doesn't catch REP MOVSD on PAE guests.
         */
    }
    else
        sh_reset_early_unshadow(v);

    /*
     * We can avoid re-verifying the page contents after the write if:
     *  - it was no larger than the PTE type of this pagetable;
     *  - it was aligned to the PTE boundaries; and
     *  - _PAGE_PRESENT was clear before and after the write.
     */
    shflags = mfn_to_page(sh_ctxt->mfn[0])->shadow_flags;
#if (SHADOW_OPTIMIZATIONS & SHOPT_SKIP_VERIFY)
    if ( sh_ctxt->low_bit_was_clear
         && !(*(u8 *)addr & _PAGE_PRESENT)
         && ((!(shflags & SHF_32)
              /*
               * Not shadowed 32-bit: aligned 64-bit writes that leave
               * the present bit unset are safe to ignore.
               */
              && ((unsigned long)addr & 7) == 0
              && bytes <= 8)
             ||
             (!(shflags & (SHF_PAE|SHF_64))
              /*
               * Not shadowed PAE/64-bit: aligned 32-bit writes that
               * leave the present bit unset are safe to ignore.
               */
              && ((unsigned long)addr & 3) == 0
              && bytes <= 4)) )
    {
        /* Writes with this alignment constraint can't possibly cross pages. */
        ASSERT(!mfn_valid(sh_ctxt->mfn[1]));
    }
    else
#endif /* SHADOW_OPTIMIZATIONS & SHOPT_SKIP_VERIFY */
    {
        if ( unlikely(mfn_valid(sh_ctxt->mfn[1])) )
        {
            /* Validate as two writes, one to each page. */
            b1 = PAGE_SIZE - (((unsigned long)addr) & ~PAGE_MASK);
            b2 = bytes - b1;
            ASSERT(b2 < bytes);
        }
        if ( likely(b1 > 0) )
            validate_guest_pt_write(v, sh_ctxt->mfn[0], addr, b1);
        if ( unlikely(b2 > 0) )
            validate_guest_pt_write(v, sh_ctxt->mfn[1], addr + b1, b2);
    }

    paging_mark_dirty(v->domain, sh_ctxt->mfn[0]);
    put_page(mfn_to_page(sh_ctxt->mfn[0]));

    if ( unlikely(mfn_valid(sh_ctxt->mfn[1])) )
    {
        paging_mark_dirty(v->domain, sh_ctxt->mfn[1]);
        put_page(mfn_to_page(sh_ctxt->mfn[1]));
        vunmap((void *)((unsigned long)addr & PAGE_MASK));
    }
    else
        unmap_domain_page(addr);

    atomic_inc(&v->domain->arch.paging.shadow.gtable_dirty_version);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
