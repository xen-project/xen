/*
 * HVM domain specific functions.
 *
 * Copyright (C) 2017 Citrix Systems R&D
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/domain_page.h>
#include <xen/errno.h>
#include <xen/lib.h>
#include <xen/paging.h>
#include <xen/sched.h>

#include <public/hvm/hvm_vcpu.h>

static int check_segment(struct segment_register *reg, enum x86_segment seg)
{

    if ( reg->pad != 0 )
    {
        gprintk(XENLOG_ERR, "Segment attribute bits 12-15 are not zero\n");
        return -EINVAL;
    }

    if ( reg->attr == 0 )
    {
        if ( seg != x86_seg_ds && seg != x86_seg_es )
        {
            gprintk(XENLOG_ERR, "Null selector provided for CS, SS or TR\n");
            return -EINVAL;
        }
        return 0;
    }

    if ( seg == x86_seg_tr )
    {
        if ( reg->s )
        {
            gprintk(XENLOG_ERR, "Code or data segment provided for TR\n");
            return -EINVAL;
        }

        if ( reg->type != SYS_DESC_tss_busy )
        {
            gprintk(XENLOG_ERR, "Non-32-bit-TSS segment provided for TR\n");
            return -EINVAL;
        }
    }
    else if ( !reg->s )
    {
        gprintk(XENLOG_ERR,
                "System segment provided for a code or data segment\n");
        return -EINVAL;
    }

    if ( !reg->p )
    {
        gprintk(XENLOG_ERR, "Non-present segment provided\n");
        return -EINVAL;
    }

    switch ( seg )
    {
    case x86_seg_cs:
        if ( !(reg->type & 0x8) )
        {
            gprintk(XENLOG_ERR, "Non-code segment provided for CS\n");
            return -EINVAL;
        }
        break;

    case x86_seg_ss:
        if ( (reg->type & 0x8) || !(reg->type & 0x2) )
        {
            gprintk(XENLOG_ERR, "Non-writeable segment provided for SS\n");
            return -EINVAL;
        }
        break;

    case x86_seg_ds:
    case x86_seg_es:
        if ( (reg->type & 0x8) && !(reg->type & 0x2) )
        {
            gprintk(XENLOG_ERR, "Non-readable segment provided for DS or ES\n");
            return -EINVAL;
        }
        break;

    case x86_seg_tr:
        break;

    default:
        ASSERT_UNREACHABLE();
        return -EINVAL;
    }

    return 0;
}

/* Called by VCPUOP_initialise for HVM guests. */
int arch_set_info_hvm_guest(struct vcpu *v, const vcpu_hvm_context_t *ctx)
{
    struct cpu_user_regs *uregs = &v->arch.user_regs;
    struct segment_register cs, ds, ss, es, tr;
    const char *errstr;
    int rc;

    if ( ctx->pad != 0 )
        return -EINVAL;

    switch ( ctx->mode )
    {
    default:
        return -EINVAL;

    case VCPU_HVM_MODE_32B:
    {
        const struct vcpu_hvm_x86_32 *regs = &ctx->cpu_regs.x86_32;
        uint32_t limit;

        if ( ctx->cpu_regs.x86_32.pad1 != 0 ||
             ctx->cpu_regs.x86_32.pad2[0] != 0 ||
             ctx->cpu_regs.x86_32.pad2[1] != 0 ||
             ctx->cpu_regs.x86_32.pad2[2] != 0 )
            return -EINVAL;

#define SEG(s, r) ({                                                        \
    s = (struct segment_register)                                           \
        { 0, { (r)->s ## _ar }, (r)->s ## _limit, (r)->s ## _base };        \
    /* Set accessed / busy bit for present segments. */                     \
    if ( s.p )                                                              \
        s.type |= (x86_seg_##s != x86_seg_tr ? 1 : 2);                      \
    check_segment(&s, x86_seg_ ## s); })

        rc = SEG(cs, regs);
        rc |= SEG(ds, regs);
        rc |= SEG(ss, regs);
        rc |= SEG(es, regs);
        rc |= SEG(tr, regs);
#undef SEG

        if ( rc != 0 )
            return rc;

        /* Basic sanity checks. */
        limit = cs.limit;
        if ( cs.g )
            limit = (limit << 12) | 0xfff;
        if ( regs->eip > limit )
        {
            gprintk(XENLOG_ERR, "EIP (%#08x) outside CS limit (%#08x)\n",
                    regs->eip, limit);
            return -EINVAL;
        }

        if ( ss.dpl != cs.dpl )
        {
            gprintk(XENLOG_ERR, "SS.DPL (%u) is different than CS.DPL (%u)\n",
                    ss.dpl, cs.dpl);
            return -EINVAL;
        }

        if ( ds.p && ds.dpl > cs.dpl )
        {
            gprintk(XENLOG_ERR, "DS.DPL (%u) is greater than CS.DPL (%u)\n",
                    ds.dpl, cs.dpl);
            return -EINVAL;
        }

        if ( es.p && es.dpl > cs.dpl )
        {
            gprintk(XENLOG_ERR, "ES.DPL (%u) is greater than CS.DPL (%u)\n",
                    es.dpl, cs.dpl);
            return -EINVAL;
        }

        if ( (regs->efer & EFER_LMA) && !(regs->efer & EFER_LME) )
        {
            gprintk(XENLOG_ERR, "EFER.LMA set without EFER.LME (%#016lx)\n",
                    regs->efer);
            return -EINVAL;
        }

        uregs->rax    = regs->eax;
        uregs->rcx    = regs->ecx;
        uregs->rdx    = regs->edx;
        uregs->rbx    = regs->ebx;
        uregs->rsp    = regs->esp;
        uregs->rbp    = regs->ebp;
        uregs->rsi    = regs->esi;
        uregs->rdi    = regs->edi;
        uregs->rip    = regs->eip;
        uregs->rflags = regs->eflags;

        v->arch.hvm_vcpu.guest_cr[0] = regs->cr0;
        v->arch.hvm_vcpu.guest_cr[3] = regs->cr3;
        v->arch.hvm_vcpu.guest_cr[4] = regs->cr4;
        v->arch.hvm_vcpu.guest_efer  = regs->efer;
    }
    break;

    case VCPU_HVM_MODE_64B:
    {
        const struct vcpu_hvm_x86_64 *regs = &ctx->cpu_regs.x86_64;

        /* Basic sanity checks. */
        if ( !is_canonical_address(regs->rip) )
        {
            gprintk(XENLOG_ERR, "RIP contains a non-canonical address (%#lx)\n",
                    regs->rip);
            return -EINVAL;
        }

        if ( !(regs->cr0 & X86_CR0_PG) )
        {
            gprintk(XENLOG_ERR, "CR0 doesn't have paging enabled (%#016lx)\n",
                    regs->cr0);
            return -EINVAL;
        }

        if ( !(regs->cr4 & X86_CR4_PAE) )
        {
            gprintk(XENLOG_ERR, "CR4 doesn't have PAE enabled (%#016lx)\n",
                    regs->cr4);
            return -EINVAL;
        }

        if ( !(regs->efer & EFER_LME) )
        {
            gprintk(XENLOG_ERR, "EFER doesn't have LME enabled (%#016lx)\n",
                    regs->efer);
            return -EINVAL;
        }

        uregs->rax    = regs->rax;
        uregs->rcx    = regs->rcx;
        uregs->rdx    = regs->rdx;
        uregs->rbx    = regs->rbx;
        uregs->rsp    = regs->rsp;
        uregs->rbp    = regs->rbp;
        uregs->rsi    = regs->rsi;
        uregs->rdi    = regs->rdi;
        uregs->rip    = regs->rip;
        uregs->rflags = regs->rflags;

        v->arch.hvm_vcpu.guest_cr[0] = regs->cr0;
        v->arch.hvm_vcpu.guest_cr[3] = regs->cr3;
        v->arch.hvm_vcpu.guest_cr[4] = regs->cr4;
        v->arch.hvm_vcpu.guest_efer  = regs->efer;

#define SEG(l, a) (struct segment_register){ 0, { a }, l, 0 }
        cs = SEG(~0u, 0xa9b); /* 64bit code segment. */
        ds = ss = es = SEG(~0u, 0xc93);
        tr = SEG(0x67, 0x8b); /* 64bit TSS (busy). */
#undef SEG
    }
    break;

    }

    if ( v->arch.hvm_vcpu.guest_efer & EFER_LME )
        v->arch.hvm_vcpu.guest_efer |= EFER_LMA;

    if ( v->arch.hvm_vcpu.guest_cr[4] & ~hvm_cr4_guest_valid_bits(v, 0) )
    {
        gprintk(XENLOG_ERR, "Bad CR4 value: %#016lx\n",
                v->arch.hvm_vcpu.guest_cr[4]);
        return -EINVAL;
    }

    errstr = hvm_efer_valid(v, v->arch.hvm_vcpu.guest_efer, -1);
    if ( errstr )
    {
        gprintk(XENLOG_ERR, "Bad EFER value (%#016lx): %s\n",
               v->arch.hvm_vcpu.guest_efer, errstr);
        return -EINVAL;
    }

    hvm_update_guest_cr(v, 0);
    hvm_update_guest_cr(v, 3);
    hvm_update_guest_cr(v, 4);
    hvm_update_guest_efer(v);

    if ( hvm_paging_enabled(v) && !paging_mode_hap(v->domain) )
    {
        /* Shadow-mode CR3 change. Check PDBR and update refcounts. */
        struct page_info *page = get_page_from_gfn(v->domain,
                                 v->arch.hvm_vcpu.guest_cr[3] >> PAGE_SHIFT,
                                 NULL, P2M_ALLOC);
        if ( !page )
        {
            gprintk(XENLOG_ERR, "Invalid CR3: %#lx\n",
                    v->arch.hvm_vcpu.guest_cr[3]);
            return -EINVAL;
        }

        v->arch.guest_table = pagetable_from_page(page);
    }

    hvm_set_segment_register(v, x86_seg_cs, &cs);
    hvm_set_segment_register(v, x86_seg_ds, &ds);
    hvm_set_segment_register(v, x86_seg_ss, &ss);
    hvm_set_segment_register(v, x86_seg_es, &es);
    hvm_set_segment_register(v, x86_seg_tr, &tr);

    /* Sync AP's TSC with BSP's. */
    v->arch.hvm_vcpu.cache_tsc_offset =
        v->domain->vcpu[0]->arch.hvm_vcpu.cache_tsc_offset;
    hvm_funcs.set_tsc_offset(v, v->arch.hvm_vcpu.cache_tsc_offset,
                             v->domain->arch.hvm_domain.sync_tsc);

    paging_update_paging_modes(v);

    v->is_initialised = 1;
    set_bit(_VPF_down, &v->pause_flags);

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
