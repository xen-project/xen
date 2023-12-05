/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * 0fae.c - helper for x86_emulate.c
 *
 * Generic x86 (32-bit and 64-bit) instruction decoder and emulator.
 */

#include "private.h"

#if defined(__XEN__) && \
    (!defined(X86EMUL_NO_FPU) || !defined(X86EMUL_NO_MMX) || \
     !defined(X86EMUL_NO_SIMD))
# include <asm/xstate.h>
#endif

int x86emul_0fae(struct x86_emulate_state *s,
                 struct cpu_user_regs *regs,
                 struct operand *dst,
                 const struct operand *src,
                 struct x86_emulate_ctxt *ctxt,
                 const struct x86_emulate_ops *ops,
                 enum x86_emulate_fpu_type *fpu_type)
#define fpu_type (*fpu_type) /* for get_fpu() */
{
    unsigned long cr4;
    int rc;

    if ( !s->vex.opcx && (!s->vex.pfx || s->vex.pfx == vex_66) )
    {
        switch ( s->modrm_reg & 7 )
        {
#if !defined(X86EMUL_NO_FPU) || !defined(X86EMUL_NO_MMX) || \
    !defined(X86EMUL_NO_SIMD)
        case 0: /* fxsave */
        case 1: /* fxrstor */
            generate_exception_if(s->vex.pfx, X86_EXC_UD);
            vcpu_must_have(fxsr);
            generate_exception_if(s->ea.type != OP_MEM, X86_EXC_UD);
            generate_exception_if(!is_aligned(s->ea.mem.seg, s->ea.mem.off, 16,
                                              ctxt, ops),
                                  X86_EXC_GP, 0);
            fail_if(!ops->blk);
            s->op_bytes =
#ifdef __x86_64__
                !mode_64bit() ? offsetof(struct x86_fxsr, xmm[8]) :
#endif
                sizeof(struct x86_fxsr);
            if ( amd_like(ctxt) )
            {
                uint64_t msr_val;

                /* Assume "normal" operation in case of missing hooks. */
                if ( !ops->read_cr ||
                     ops->read_cr(4, &cr4, ctxt) != X86EMUL_OKAY )
                    cr4 = X86_CR4_OSFXSR;
                if ( !ops->read_msr ||
                     ops->read_msr(MSR_EFER, &msr_val, ctxt) != X86EMUL_OKAY )
                {
                    x86_emul_reset_event(ctxt);
                    msr_val = 0;
                }
                if ( !(cr4 & X86_CR4_OSFXSR) ||
                     (mode_64bit() && mode_ring0() && (msr_val & EFER_FFXSE)) )
                    s->op_bytes = offsetof(struct x86_fxsr, xmm[0]);
            }
            /*
             * This could also be X86EMUL_FPU_mmx, but it shouldn't be
             * X86EMUL_FPU_xmm, as we don't want CR4.OSFXSR checked.
             */
            get_fpu(X86EMUL_FPU_fpu);
            s->fpu_ctrl = true;
            s->blk = s->modrm_reg & 1 ? blk_fxrstor : blk_fxsave;
            if ( (rc = ops->blk(s->ea.mem.seg, s->ea.mem.off, NULL,
                                sizeof(struct x86_fxsr), &regs->eflags,
                                s, ctxt)) != X86EMUL_OKAY )
                goto done;
            break;
#endif /* X86EMUL_NO_{FPU,MMX,SIMD} */

#ifndef X86EMUL_NO_SIMD
        case 2: /* ldmxcsr */
            generate_exception_if(s->vex.pfx, X86_EXC_UD);
            vcpu_must_have(sse);
        ldmxcsr:
            generate_exception_if(src->type != OP_MEM, X86_EXC_UD);
            get_fpu(s->vex.opcx ? X86EMUL_FPU_ymm : X86EMUL_FPU_xmm);
            generate_exception_if(src->val & ~mxcsr_mask, X86_EXC_GP, 0);
            asm volatile ( "ldmxcsr %0" :: "m" (src->val) );
            break;

        case 3: /* stmxcsr */
            generate_exception_if(s->vex.pfx, X86_EXC_UD);
            vcpu_must_have(sse);
        stmxcsr:
            generate_exception_if(dst->type != OP_MEM, X86_EXC_UD);
            get_fpu(s->vex.opcx ? X86EMUL_FPU_ymm : X86EMUL_FPU_xmm);
            asm volatile ( "stmxcsr %0" : "=m" (dst->val) );
            break;
#endif /* X86EMUL_NO_SIMD */

        case 5: /* lfence */
            fail_if(s->modrm_mod != 3);
            generate_exception_if(s->vex.pfx, X86_EXC_UD);
            vcpu_must_have(sse2);
            asm volatile ( "lfence" ::: "memory" );
            break;
        case 6:
            if ( s->modrm_mod == 3 ) /* mfence */
            {
                generate_exception_if(s->vex.pfx, X86_EXC_UD);
                vcpu_must_have(sse2);
                asm volatile ( "mfence" ::: "memory" );
                break;
            }
            /* else clwb */
            fail_if(!s->vex.pfx);
            vcpu_must_have(clwb);
            fail_if(!ops->cache_op);
            if ( (rc = ops->cache_op(x86emul_clwb, s->ea.mem.seg, s->ea.mem.off,
                                     ctxt)) != X86EMUL_OKAY )
                goto done;
            break;
        case 7:
            if ( s->modrm_mod == 3 ) /* sfence */
            {
                generate_exception_if(s->vex.pfx, X86_EXC_UD);
                vcpu_must_have(mmxext);
                asm volatile ( "sfence" ::: "memory" );
                break;
            }
            /* else clflush{,opt} */
            if ( !s->vex.pfx )
                vcpu_must_have(clflush);
            else
                vcpu_must_have(clflushopt);
            fail_if(!ops->cache_op);
            if ( (rc = ops->cache_op(s->vex.pfx ? x86emul_clflushopt
                                                : x86emul_clflush,
                                     s->ea.mem.seg, s->ea.mem.off,
                                     ctxt)) != X86EMUL_OKAY )
                goto done;
            break;
        default:
            return X86EMUL_UNIMPLEMENTED;
        }
    }
#ifndef X86EMUL_NO_SIMD
    else if ( s->vex.opcx && !s->vex.pfx )
    {
        switch ( s->modrm_reg & 7 )
        {
        case 2: /* vldmxcsr */
            generate_exception_if(s->vex.l || s->vex.reg != 0xf, X86_EXC_UD);
            vcpu_must_have(avx);
            goto ldmxcsr;
        case 3: /* vstmxcsr */
            generate_exception_if(s->vex.l || s->vex.reg != 0xf, X86_EXC_UD);
            vcpu_must_have(avx);
            goto stmxcsr;
        }
        return X86EMUL_UNRECOGNIZED;
    }
#endif /* !X86EMUL_NO_SIMD */
    else if ( !s->vex.opcx && s->vex.pfx == vex_f3 )
    {
        enum x86_segment seg;
        struct segment_register sreg;

        fail_if(s->modrm_mod != 3);
        generate_exception_if((s->modrm_reg & 4) || !mode_64bit(), X86_EXC_UD);
        fail_if(!ops->read_cr);
        if ( (rc = ops->read_cr(4, &cr4, ctxt)) != X86EMUL_OKAY )
            goto done;
        generate_exception_if(!(cr4 & X86_CR4_FSGSBASE), X86_EXC_UD);
        seg = s->modrm_reg & 1 ? x86_seg_gs : x86_seg_fs;
        fail_if(!ops->read_segment);
        if ( (rc = ops->read_segment(seg, &sreg, ctxt)) != X86EMUL_OKAY )
            goto done;
        dst->reg = decode_gpr(regs, s->modrm_rm);
        if ( !(s->modrm_reg & 2) )
        {
            /* rd{f,g}sbase */
            dst->type = OP_REG;
            dst->bytes = (s->op_bytes == 8) ? 8 : 4;
            dst->val = sreg.base;
        }
        else
        {
            /* wr{f,g}sbase */
            if ( s->op_bytes == 8 )
            {
                sreg.base = *dst->reg;
                generate_exception_if(!is_canonical_address(sreg.base),
                                      X86_EXC_GP, 0);
            }
            else
                sreg.base = (uint32_t)*dst->reg;
            fail_if(!ops->write_segment);
            if ( (rc = ops->write_segment(seg, &sreg, ctxt)) != X86EMUL_OKAY )
                goto done;
        }
    }
    else
    {
        ASSERT_UNREACHABLE();
        return X86EMUL_UNRECOGNIZED;
    }

    rc = X86EMUL_OKAY;

 done:
    return rc;
}
