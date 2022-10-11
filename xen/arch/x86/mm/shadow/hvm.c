
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
#include <asm/hvm/emulate.h>
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

    /* Where possible use single (and hence generally atomic) MOV insns. */
    switch ( bytes )
    {
    case 2: write_u16_atomic(ptr, *(uint16_t *)p_data); break;
    case 4: write_u32_atomic(ptr, *(uint32_t *)p_data); break;
    case 8: write_u64_atomic(ptr, *(uint64_t *)p_data); break;
    default: memcpy(ptr, p_data, bytes);                break;
    }

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
        guest_flush_tlb_mask(d, d->dirty_cpumask);

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

mfn_t sh_make_monitor_table(const struct vcpu *v, unsigned int shadow_levels)
{
    struct domain *d = v->domain;
    mfn_t m4mfn;
    l4_pgentry_t *l4e;

    ASSERT(!pagetable_get_pfn(v->arch.hvm.monitor_table));

    /* Guarantee we can get the memory we need */
    if ( !shadow_prealloc(d, SH_type_monitor_table, CONFIG_PAGING_LEVELS) )
        return INVALID_MFN;

    m4mfn = shadow_alloc(d, SH_type_monitor_table, 0);
    mfn_to_page(m4mfn)->shadow_flags = 4;

    l4e = map_domain_page(m4mfn);

    /*
     * Create a self-linear mapping, but no shadow-linear mapping.  A
     * shadow-linear mapping will either be inserted below when creating
     * lower level monitor tables, or later in sh_update_cr3().
     */
    init_xen_l4_slots(l4e, m4mfn, d, INVALID_MFN, false);

    if ( shadow_levels < 4 )
    {
        mfn_t m3mfn, m2mfn;
        l3_pgentry_t *l3e;

        /*
         * Install an l3 table and an l2 table that will hold the shadow
         * linear map entries.  This overrides the empty entry that was
         * installed by init_xen_l4_slots().
         */
        m3mfn = shadow_alloc(d, SH_type_monitor_table, 0);
        mfn_to_page(m3mfn)->shadow_flags = 3;
        l4e[l4_table_offset(SH_LINEAR_PT_VIRT_START)]
            = l4e_from_mfn(m3mfn, __PAGE_HYPERVISOR_RW);

        m2mfn = shadow_alloc(d, SH_type_monitor_table, 0);
        mfn_to_page(m2mfn)->shadow_flags = 2;
        l3e = map_domain_page(m3mfn);
        l3e[0] = l3e_from_mfn(m2mfn, __PAGE_HYPERVISOR_RW);
        unmap_domain_page(l3e);
    }

    unmap_domain_page(l4e);

    return m4mfn;
}

void sh_destroy_monitor_table(const struct vcpu *v, mfn_t mmfn,
                              unsigned int shadow_levels)
{
    struct domain *d = v->domain;

    ASSERT(mfn_to_page(mmfn)->u.sh.type == SH_type_monitor_table);

    if ( shadow_levels < 4 )
    {
        mfn_t m3mfn;
        l4_pgentry_t *l4e = map_domain_page(mmfn);
        l3_pgentry_t *l3e;
        unsigned int linear_slot = l4_table_offset(SH_LINEAR_PT_VIRT_START);

        /*
         * Need to destroy the l3 and l2 monitor pages used
         * for the linear map.
         */
        ASSERT(l4e_get_flags(l4e[linear_slot]) & _PAGE_PRESENT);
        m3mfn = l4e_get_mfn(l4e[linear_slot]);
        l3e = map_domain_page(m3mfn);
        ASSERT(l3e_get_flags(l3e[0]) & _PAGE_PRESENT);
        shadow_free(d, l3e_get_mfn(l3e[0]));
        unmap_domain_page(l3e);
        shadow_free(d, m3mfn);

        unmap_domain_page(l4e);
    }

    /* Put the memory back in the pool */
    shadow_free(d, mmfn);
}

/**************************************************************************/
/* VRAM dirty tracking support */
int shadow_track_dirty_vram(struct domain *d,
                            unsigned long begin_pfn,
                            unsigned int nr_frames,
                            XEN_GUEST_HANDLE(void) guest_dirty_bitmap)
{
    int rc = 0;
    unsigned long end_pfn = begin_pfn + nr_frames;
    unsigned int dirty_size = DIV_ROUND_UP(nr_frames, BITS_PER_BYTE);
    int flush_tlb = 0;
    unsigned long i;
    p2m_type_t t;
    struct sh_dirty_vram *dirty_vram;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    uint8_t *dirty_bitmap = NULL;

    if ( end_pfn < begin_pfn || end_pfn > p2m->max_mapped_pfn + 1 )
        return -EINVAL;

    /* We perform p2m lookups, so lock the p2m upfront to avoid deadlock */
    p2m_lock(p2m_get_hostp2m(d));
    paging_lock(d);

    dirty_vram = d->arch.hvm.dirty_vram;

    if ( dirty_vram && (!nr_frames ||
             ( begin_pfn != dirty_vram->begin_pfn
            || end_pfn   != dirty_vram->end_pfn )) )
    {
        /* Different tracking, tear the previous down. */
        gdprintk(XENLOG_INFO, "stopping tracking VRAM %lx - %lx\n", dirty_vram->begin_pfn, dirty_vram->end_pfn);
        xfree(dirty_vram->sl1ma);
        xfree(dirty_vram->dirty_bitmap);
        xfree(dirty_vram);
        dirty_vram = d->arch.hvm.dirty_vram = NULL;
    }

    if ( !nr_frames )
        goto out;

    dirty_bitmap = vzalloc(dirty_size);
    if ( dirty_bitmap == NULL )
    {
        rc = -ENOMEM;
        goto out;
    }
    /*
     * This should happen seldomly (Video mode change),
     * no need to be careful.
     */
    if ( !dirty_vram )
    {
        /*
         * Throw away all the shadows rather than walking through them
         * up to nr times getting rid of mappings of each pfn.
         */
        shadow_blow_tables(d);

        gdprintk(XENLOG_INFO, "tracking VRAM %lx - %lx\n", begin_pfn, end_pfn);

        rc = -ENOMEM;
        if ( (dirty_vram = xmalloc(struct sh_dirty_vram)) == NULL )
            goto out;
        dirty_vram->begin_pfn = begin_pfn;
        dirty_vram->end_pfn = end_pfn;
        d->arch.hvm.dirty_vram = dirty_vram;

        if ( (dirty_vram->sl1ma = xmalloc_array(paddr_t, nr_frames)) == NULL )
            goto out_dirty_vram;
        memset(dirty_vram->sl1ma, ~0, sizeof(paddr_t) * nr_frames);

        if ( (dirty_vram->dirty_bitmap = xzalloc_array(uint8_t, dirty_size)) == NULL )
            goto out_sl1ma;

        dirty_vram->last_dirty = NOW();

        /* Tell the caller that this time we could not track dirty bits. */
        rc = -ENODATA;
    }
    else if ( dirty_vram->last_dirty == -1 )
        /* still completely clean, just copy our empty bitmap */
        memcpy(dirty_bitmap, dirty_vram->dirty_bitmap, dirty_size);
    else
    {
        mfn_t map_mfn = INVALID_MFN;
        void *map_sl1p = NULL;

        /* Iterate over VRAM to track dirty bits. */
        for ( i = 0; i < nr_frames; i++ )
        {
            mfn_t mfn = get_gfn_query_unlocked(d, begin_pfn + i, &t);
            struct page_info *page;
            int dirty = 0;
            paddr_t sl1ma = dirty_vram->sl1ma[i];

            if ( mfn_eq(mfn, INVALID_MFN) )
                dirty = 1;
            else
            {
                page = mfn_to_page(mfn);
                switch ( page->u.inuse.type_info & PGT_count_mask )
                {
                case 0:
                    /* No guest reference, nothing to track. */
                    break;

                case 1:
                    /* One guest reference. */
                    if ( sl1ma == INVALID_PADDR )
                    {
                        /* We don't know which sl1e points to this, too bad. */
                        dirty = 1;
                        /*
                         * TODO: Heuristics for finding the single mapping of
                         * this gmfn
                         */
                        flush_tlb |= sh_remove_all_mappings(d, mfn,
                                                            _gfn(begin_pfn + i));
                    }
                    else
                    {
                        /*
                         * Hopefully the most common case: only one mapping,
                         * whose dirty bit we can use.
                         */
                        l1_pgentry_t *sl1e;
                        mfn_t sl1mfn = maddr_to_mfn(sl1ma);

                        if ( !mfn_eq(sl1mfn, map_mfn) )
                        {
                            if ( map_sl1p )
                                unmap_domain_page(map_sl1p);
                            map_sl1p = map_domain_page(sl1mfn);
                            map_mfn = sl1mfn;
                        }
                        sl1e = map_sl1p + (sl1ma & ~PAGE_MASK);

                        if ( l1e_get_flags(*sl1e) & _PAGE_DIRTY )
                        {
                            dirty = 1;
                            /*
                             * Note: this is atomic, so we may clear a
                             * _PAGE_ACCESSED set by another processor.
                             */
                            l1e_remove_flags(*sl1e, _PAGE_DIRTY);
                            flush_tlb = 1;
                        }
                    }
                    break;

                default:
                    /* More than one guest reference,
                     * we don't afford tracking that. */
                    dirty = 1;
                    break;
                }
            }

            if ( dirty )
            {
                dirty_vram->dirty_bitmap[i / 8] |= 1 << (i % 8);
                dirty_vram->last_dirty = NOW();
            }
        }

        if ( map_sl1p )
            unmap_domain_page(map_sl1p);

        memcpy(dirty_bitmap, dirty_vram->dirty_bitmap, dirty_size);
        memset(dirty_vram->dirty_bitmap, 0, dirty_size);
        if ( dirty_vram->last_dirty + SECONDS(2) < NOW() )
        {
            /*
             * Was clean for more than two seconds, try to disable guest
             * write access.
             */
            for ( i = begin_pfn; i < end_pfn; i++ )
            {
                mfn_t mfn = get_gfn_query_unlocked(d, i, &t);
                if ( !mfn_eq(mfn, INVALID_MFN) )
                    flush_tlb |= sh_remove_write_access(d, mfn, 1, 0);
            }
            dirty_vram->last_dirty = -1;
        }
    }
    if ( flush_tlb )
        guest_flush_tlb_mask(d, d->dirty_cpumask);
    goto out;

 out_sl1ma:
    xfree(dirty_vram->sl1ma);
 out_dirty_vram:
    xfree(dirty_vram);
    dirty_vram = d->arch.hvm.dirty_vram = NULL;

 out:
    paging_unlock(d);
    if ( rc == 0 && dirty_bitmap != NULL &&
         copy_to_guest(guest_dirty_bitmap, dirty_bitmap, dirty_size) )
    {
        paging_lock(d);
        for ( i = 0; i < dirty_size; i++ )
            dirty_vram->dirty_bitmap[i] |= dirty_bitmap[i];
        paging_unlock(d);
        rc = -EFAULT;
    }
    vfree(dirty_bitmap);
    p2m_unlock(p2m_get_hostp2m(d));
    return rc;
}

void shadow_vram_get_mfn(mfn_t mfn, unsigned int l1f,
                         mfn_t sl1mfn, const void *sl1e,
                         const struct domain *d)
{
    unsigned long gfn;
    struct sh_dirty_vram *dirty_vram = d->arch.hvm.dirty_vram;

    ASSERT(is_hvm_domain(d));

    if ( !dirty_vram /* tracking disabled? */ ||
         !(l1f & _PAGE_RW) /* read-only mapping? */ ||
         !mfn_valid(mfn) /* mfn can be invalid in mmio_direct */)
        return;

    gfn = gfn_x(mfn_to_gfn(d, mfn));
    /* Page sharing not supported on shadow PTs */
    BUG_ON(SHARED_M2P(gfn));

    if ( (gfn >= dirty_vram->begin_pfn) && (gfn < dirty_vram->end_pfn) )
    {
        unsigned long i = gfn - dirty_vram->begin_pfn;
        const struct page_info *page = mfn_to_page(mfn);

        if ( (page->u.inuse.type_info & PGT_count_mask) == 1 )
            /* Initial guest reference, record it */
            dirty_vram->sl1ma[i] = mfn_to_maddr(sl1mfn) |
                                   PAGE_OFFSET(sl1e);
    }
}

void shadow_vram_put_mfn(mfn_t mfn, unsigned int l1f,
                         mfn_t sl1mfn, const void *sl1e,
                         const struct domain *d)
{
    unsigned long gfn;
    struct sh_dirty_vram *dirty_vram = d->arch.hvm.dirty_vram;

    ASSERT(is_hvm_domain(d));

    if ( !dirty_vram /* tracking disabled? */ ||
         !(l1f & _PAGE_RW) /* read-only mapping? */ ||
         !mfn_valid(mfn) /* mfn can be invalid in mmio_direct */)
        return;

    gfn = gfn_x(mfn_to_gfn(d, mfn));
    /* Page sharing not supported on shadow PTs */
    BUG_ON(SHARED_M2P(gfn));

    if ( (gfn >= dirty_vram->begin_pfn) && (gfn < dirty_vram->end_pfn) )
    {
        unsigned long i = gfn - dirty_vram->begin_pfn;
        const struct page_info *page = mfn_to_page(mfn);
        bool dirty = false;
        paddr_t sl1ma = mfn_to_maddr(sl1mfn) | PAGE_OFFSET(sl1e);

        if ( (page->u.inuse.type_info & PGT_count_mask) == 1 )
        {
            /* Last reference */
            if ( dirty_vram->sl1ma[i] == INVALID_PADDR )
            {
                /* We didn't know it was that one, let's say it is dirty */
                dirty = true;
            }
            else
            {
                ASSERT(dirty_vram->sl1ma[i] == sl1ma);
                dirty_vram->sl1ma[i] = INVALID_PADDR;
                if ( l1f & _PAGE_DIRTY )
                    dirty = true;
            }
        }
        else
        {
            /* We had more than one reference, just consider the page dirty. */
            dirty = true;
            /* Check that it's not the one we recorded. */
            if ( dirty_vram->sl1ma[i] == sl1ma )
            {
                /* Too bad, we remembered the wrong one... */
                dirty_vram->sl1ma[i] = INVALID_PADDR;
            }
            else
            {
                /*
                 * Ok, our recorded sl1e is still pointing to this page, let's
                 * just hope it will remain.
                 */
            }
        }

        if ( dirty )
        {
            dirty_vram->dirty_bitmap[i / 8] |= 1 << (i % 8);
            dirty_vram->last_dirty = NOW();
        }
    }
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
