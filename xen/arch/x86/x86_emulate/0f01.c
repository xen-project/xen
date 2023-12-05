/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * 0f01.c - helper for x86_emulate.c
 *
 * Generic x86 (32-bit and 64-bit) instruction decoder and emulator.
 *
 * Copyright (c) 2005-2007 Keir Fraser
 * Copyright (c) 2005-2007 XenSource Inc.
 */

#include "private.h"

#ifdef __XEN__
#include <asm/prot-key.h>
#endif

#define ad_bytes (s->ad_bytes) /* for truncate_ea() */

int x86emul_0f01(struct x86_emulate_state *s,
                 struct cpu_user_regs *regs,
                 struct operand *dst,
                 struct x86_emulate_ctxt *ctxt,
                 const struct x86_emulate_ops *ops)
{
    enum x86_segment seg = (s->modrm_reg & 1) ? x86_seg_idtr : x86_seg_gdtr;
    int rc;

    switch ( s->modrm )
    {
        unsigned long base, limit, cr0, cr0w, cr4;
        struct segment_register sreg;
        uint64_t msr_val;

    case 0xc6:
        switch ( s->vex.pfx )
        {
        case vex_none: /* wrmsrns */
            vcpu_must_have(wrmsrns);
            generate_exception_if(!mode_ring0(), X86_EXC_GP, 0);
            fail_if(!ops->write_msr);
            rc = ops->write_msr(regs->ecx,
                                ((uint64_t)regs->r(dx) << 32) | regs->eax,
                                ctxt);
            goto done;
        }
        generate_exception(X86_EXC_UD);

    case 0xca: /* clac */
    case 0xcb: /* stac */
        vcpu_must_have(smap);
        generate_exception_if(s->vex.pfx || !mode_ring0(), X86_EXC_UD);

        regs->eflags &= ~X86_EFLAGS_AC;
        if ( s->modrm == 0xcb )
            regs->eflags |= X86_EFLAGS_AC;
        break;

    case 0xd0: /* xgetbv */
        generate_exception_if(s->vex.pfx, X86_EXC_UD);
        if ( !ops->read_cr || !ops->read_xcr ||
             ops->read_cr(4, &cr4, ctxt) != X86EMUL_OKAY )
            cr4 = 0;
        generate_exception_if(!(cr4 & X86_CR4_OSXSAVE), X86_EXC_UD);
        rc = ops->read_xcr(regs->ecx, &msr_val, ctxt);
        if ( rc != X86EMUL_OKAY )
            goto done;
        regs->r(ax) = (uint32_t)msr_val;
        regs->r(dx) = msr_val >> 32;
        break;

    case 0xd1: /* xsetbv */
        generate_exception_if(s->vex.pfx, X86_EXC_UD);
        if ( !ops->read_cr || !ops->write_xcr ||
             ops->read_cr(4, &cr4, ctxt) != X86EMUL_OKAY )
            cr4 = 0;
        generate_exception_if(!(cr4 & X86_CR4_OSXSAVE), X86_EXC_UD);
        generate_exception_if(!mode_ring0(), X86_EXC_GP, 0);
        rc = ops->write_xcr(regs->ecx,
                            regs->eax | ((uint64_t)regs->edx << 32), ctxt);
        if ( rc != X86EMUL_OKAY )
            goto done;
        break;

    case 0xd4: /* vmfunc */
        generate_exception_if(s->vex.pfx, X86_EXC_UD);
        fail_if(!ops->vmfunc);
        if ( (rc = ops->vmfunc(ctxt)) != X86EMUL_OKAY )
            goto done;
        break;

    case 0xd5: /* xend */
        generate_exception_if(s->vex.pfx, X86_EXC_UD);
        generate_exception_if(!vcpu_has_rtm(), X86_EXC_UD);
        generate_exception_if(vcpu_has_rtm(), X86_EXC_GP, 0);
        break;

    case 0xd6: /* xtest */
        generate_exception_if(s->vex.pfx, X86_EXC_UD);
        generate_exception_if(!vcpu_has_rtm() && !vcpu_has_hle(),
                              X86_EXC_UD);
        /* Neither HLE nor RTM can be active when we get here. */
        regs->eflags |= X86_EFLAGS_ZF;
        break;

    case 0xdf: /* invlpga */
        fail_if(!ops->read_msr);
        if ( (rc = ops->read_msr(MSR_EFER,
                                 &msr_val, ctxt)) != X86EMUL_OKAY )
            goto done;
        /* Finding SVME set implies vcpu_has_svm(). */
        generate_exception_if(!(msr_val & EFER_SVME) ||
                              !in_protmode(ctxt, ops), X86_EXC_UD);
        generate_exception_if(!mode_ring0(), X86_EXC_GP, 0);
        fail_if(!ops->tlb_op);
        if ( (rc = ops->tlb_op(x86emul_invlpga, truncate_ea(regs->r(ax)),
                               regs->ecx, ctxt)) != X86EMUL_OKAY )
            goto done;
        break;

    case 0xe8:
        switch ( s->vex.pfx )
        {
        case vex_none: /* serialize */
            host_and_vcpu_must_have(serialize);
            asm volatile ( ".byte 0x0f, 0x01, 0xe8" );
            break;
        case vex_f2: /* xsusldtrk */
            vcpu_must_have(tsxldtrk);
            /*
             * We're never in a transactional region when coming here
             * - nothing else to do.
             */
            break;
        default:
            return X86EMUL_UNIMPLEMENTED;
        }
        break;

    case 0xe9:
        switch ( s->vex.pfx )
        {
        case vex_f2: /* xresldtrk */
            vcpu_must_have(tsxldtrk);
            /*
             * We're never in a transactional region when coming here
             * - nothing else to do.
             */
            break;
        default:
            return X86EMUL_UNIMPLEMENTED;
        }
        break;

    case 0xee:
        switch ( s->vex.pfx )
        {
        case vex_none: /* rdpkru */
            if ( !ops->read_cr ||
                 ops->read_cr(4, &cr4, ctxt) != X86EMUL_OKAY )
                cr4 = 0;
            generate_exception_if(!(cr4 & X86_CR4_PKE), X86_EXC_UD);
            generate_exception_if(regs->ecx, X86_EXC_GP, 0);
            regs->r(ax) = rdpkru();
            regs->r(dx) = 0;
            break;
        default:
            return X86EMUL_UNIMPLEMENTED;
        }
        break;

    case 0xef:
        switch ( s->vex.pfx )
        {
        case vex_none: /* wrpkru */
            if ( !ops->read_cr ||
                 ops->read_cr(4, &cr4, ctxt) != X86EMUL_OKAY )
                cr4 = 0;
            generate_exception_if(!(cr4 & X86_CR4_PKE), X86_EXC_UD);
            generate_exception_if(regs->ecx | regs->edx, X86_EXC_GP, 0);
            wrpkru(regs->eax);
            break;
        default:
            return X86EMUL_UNIMPLEMENTED;
        }
        break;

    case 0xf8: /* swapgs */
        generate_exception_if(!mode_64bit(), X86_EXC_UD);
        generate_exception_if(!mode_ring0(), X86_EXC_GP, 0);
        fail_if(!ops->read_segment || !ops->read_msr ||
                !ops->write_segment || !ops->write_msr);
        if ( (rc = ops->read_segment(x86_seg_gs, &sreg,
                                     ctxt)) != X86EMUL_OKAY ||
             (rc = ops->read_msr(MSR_SHADOW_GS_BASE, &msr_val,
                                 ctxt)) != X86EMUL_OKAY ||
             (rc = ops->write_msr(MSR_SHADOW_GS_BASE, sreg.base,
                                  ctxt)) != X86EMUL_OKAY )
            goto done;
        sreg.base = msr_val;
        if ( (rc = ops->write_segment(x86_seg_gs, &sreg,
                                      ctxt)) != X86EMUL_OKAY )
        {
            /* Best effort unwind (i.e. no real error checking). */
            if ( ops->write_msr(MSR_SHADOW_GS_BASE, msr_val,
                                ctxt) == X86EMUL_EXCEPTION )
                x86_emul_reset_event(ctxt);
            goto done;
        }
        break;

    case 0xf9: /* rdtscp */
        fail_if(ops->read_msr == NULL);
        if ( (rc = ops->read_msr(MSR_TSC_AUX,
                                 &msr_val, ctxt)) != X86EMUL_OKAY )
            goto done;
        regs->r(cx) = (uint32_t)msr_val;
        return X86EMUL_rdtsc;

    case 0xfc: /* clzero */
    {
        unsigned long zero = 0;

        vcpu_must_have(clzero);

        base = ad_bytes == 8 ? regs->r(ax) :
               ad_bytes == 4 ? regs->eax : regs->ax;
        limit = ctxt->cpuid->basic.clflush_size * 8;
        generate_exception_if(limit < sizeof(long) ||
                              (limit & (limit - 1)), X86_EXC_UD);
        base &= ~(limit - 1);
        if ( ops->rep_stos )
        {
            unsigned long nr_reps = limit / sizeof(zero);

            rc = ops->rep_stos(&zero, s->ea.mem.seg, base, sizeof(zero),
                               &nr_reps, ctxt);
            if ( rc == X86EMUL_OKAY )
            {
                base += nr_reps * sizeof(zero);
                limit -= nr_reps * sizeof(zero);
            }
            else if ( rc != X86EMUL_UNHANDLEABLE )
                goto done;
        }
        fail_if(limit && !ops->write);
        while ( limit )
        {
            rc = ops->write(s->ea.mem.seg, base, &zero, sizeof(zero), ctxt);
            if ( rc != X86EMUL_OKAY )
                goto done;
            base += sizeof(zero);
            limit -= sizeof(zero);
        }
        break;
    }

#define _GRP7(mod, reg) \
        (((mod) << 6) | ((reg) << 3)) ... (((mod) << 6) | ((reg) << 3) | 7)
#define GRP7_MEM(reg) _GRP7(0, reg): case _GRP7(1, reg): case _GRP7(2, reg)
#define GRP7_ALL(reg) GRP7_MEM(reg): case _GRP7(3, reg)

    case GRP7_MEM(0): /* sgdt */
    case GRP7_MEM(1): /* sidt */
        ASSERT(s->ea.type == OP_MEM);
        generate_exception_if(umip_active(ctxt, ops), X86_EXC_GP, 0);
        fail_if(!ops->read_segment || !ops->write);
        if ( (rc = ops->read_segment(seg, &sreg, ctxt)) )
            goto done;
        if ( mode_64bit() )
            s->op_bytes = 8;
        else if ( s->op_bytes == 2 )
        {
            sreg.base &= 0xffffff;
            s->op_bytes = 4;
        }
        if ( (rc = ops->write(s->ea.mem.seg, s->ea.mem.off, &sreg.limit,
                              2, ctxt)) != X86EMUL_OKAY ||
             (rc = ops->write(s->ea.mem.seg, truncate_ea(s->ea.mem.off + 2),
                              &sreg.base, s->op_bytes, ctxt)) != X86EMUL_OKAY )
            goto done;
        break;

    case GRP7_MEM(2): /* lgdt */
    case GRP7_MEM(3): /* lidt */
        ASSERT(s->ea.type == OP_MEM);
        generate_exception_if(!mode_ring0(), X86_EXC_GP, 0);
        fail_if(ops->write_segment == NULL);
        memset(&sreg, 0, sizeof(sreg));
        if ( (rc = read_ulong(s->ea.mem.seg, s->ea.mem.off,
                              &limit, 2, ctxt, ops)) ||
             (rc = read_ulong(s->ea.mem.seg, truncate_ea(s->ea.mem.off + 2),
                              &base, mode_64bit() ? 8 : 4, ctxt, ops)) )
            goto done;
        generate_exception_if(!is_canonical_address(base), X86_EXC_GP, 0);
        sreg.base = base;
        sreg.limit = limit;
        if ( !mode_64bit() && s->op_bytes == 2 )
            sreg.base &= 0xffffff;
        if ( (rc = ops->write_segment(seg, &sreg, ctxt)) )
            goto done;
        break;

    case GRP7_ALL(4): /* smsw */
        generate_exception_if(umip_active(ctxt, ops), X86_EXC_GP, 0);
        if ( s->ea.type == OP_MEM )
        {
            fail_if(!ops->write);
            s->desc |= Mov; /* force writeback */
            s->ea.bytes = 2;
        }
        else
            s->ea.bytes = s->op_bytes;
        *dst = s->ea;
        fail_if(ops->read_cr == NULL);
        if ( (rc = ops->read_cr(0, &dst->val, ctxt)) )
            goto done;
        break;

    case GRP7_ALL(6): /* lmsw */
        fail_if(ops->read_cr == NULL);
        fail_if(ops->write_cr == NULL);
        generate_exception_if(!mode_ring0(), X86_EXC_GP, 0);
        if ( (rc = ops->read_cr(0, &cr0, ctxt)) )
            goto done;
        if ( s->ea.type == OP_REG )
            cr0w = *s->ea.reg;
        else if ( (rc = read_ulong(s->ea.mem.seg, s->ea.mem.off,
                                   &cr0w, 2, ctxt, ops)) )
            goto done;
        /* LMSW can: (1) set bits 0-3; (2) clear bits 1-3. */
        cr0 = (cr0 & ~0xe) | (cr0w & 0xf);
        if ( (rc = ops->write_cr(0, cr0, ctxt)) )
            goto done;
        break;

    case GRP7_MEM(7): /* invlpg */
        ASSERT(s->ea.type == OP_MEM);
        generate_exception_if(!mode_ring0(), X86_EXC_GP, 0);
        fail_if(!ops->tlb_op);
        if ( (rc = ops->tlb_op(x86emul_invlpg, s->ea.mem.off, s->ea.mem.seg,
                               ctxt)) != X86EMUL_OKAY )
            goto done;
        break;

#undef GRP7_ALL
#undef GRP7_MEM
#undef _GRP7

    default:
        return X86EMUL_UNIMPLEMENTED;
    }

    rc = X86EMUL_OKAY;

 done:
    return rc;
}
