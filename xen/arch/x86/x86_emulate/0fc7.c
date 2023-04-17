/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * 0fc7.c - helper for x86_emulate.c
 *
 * Generic x86 (32-bit and 64-bit) instruction decoder and emulator.
 *
 * Copyright (c) 2005-2007 Keir Fraser
 * Copyright (c) 2005-2007 XenSource Inc.
 */

#include "private.h"

/* Avoid namespace pollution. */
#undef cmpxchg

int x86emul_0fc7(struct x86_emulate_state *s,
                 struct cpu_user_regs *regs,
                 struct operand *dst,
                 struct x86_emulate_ctxt *ctxt,
                 const struct x86_emulate_ops *ops,
                 mmval_t *mmvalp)
{
    int rc;

    if ( s->ea.type == OP_REG )
    {
        bool __maybe_unused carry;

        switch ( s->modrm_reg & 7 )
        {
        default:
            return X86EMUL_UNRECOGNIZED;

        case 6: /* rdrand */
#ifdef HAVE_AS_RDRAND
            generate_exception_if(s->vex.pfx >= vex_f3, X86_EXC_UD);
            host_and_vcpu_must_have(rdrand);
            *dst = s->ea;
            switch ( s->op_bytes )
            {
            case 2:
                asm ( "rdrand %w0" ASM_FLAG_OUT(, "; setc %1")
                      : "=r" (dst->val), ASM_FLAG_OUT("=@ccc", "=qm") (carry) );
                break;
            default:
# ifdef __x86_64__
                asm ( "rdrand %k0" ASM_FLAG_OUT(, "; setc %1")
                      : "=r" (dst->val), ASM_FLAG_OUT("=@ccc", "=qm") (carry) );
                break;
            case 8:
# endif
                asm ( "rdrand %0" ASM_FLAG_OUT(, "; setc %1")
                      : "=r" (dst->val), ASM_FLAG_OUT("=@ccc", "=qm") (carry) );
                break;
            }
            regs->eflags &= ~EFLAGS_MASK;
            if ( carry )
                regs->eflags |= X86_EFLAGS_CF;
            break;
#else
            return X86EMUL_UNIMPLEMENTED;
#endif

        case 7: /* rdseed / rdpid */
            if ( s->vex.pfx == vex_f3 ) /* rdpid */
            {
                uint64_t msr_val;

                generate_exception_if(s->ea.type != OP_REG, X86_EXC_UD);
                vcpu_must_have(rdpid);
                fail_if(!ops->read_msr);
                if ( (rc = ops->read_msr(MSR_TSC_AUX, &msr_val,
                                         ctxt)) != X86EMUL_OKAY )
                    goto done;
                *dst = s->ea;
                dst->val = msr_val;
                dst->bytes = 4;
                break;
            }
#ifdef HAVE_AS_RDSEED
            generate_exception_if(s->vex.pfx >= vex_f3, X86_EXC_UD);
            host_and_vcpu_must_have(rdseed);
            *dst = s->ea;
            switch ( s->op_bytes )
            {
            case 2:
                asm ( "rdseed %w0" ASM_FLAG_OUT(, "; setc %1")
                      : "=r" (dst->val), ASM_FLAG_OUT("=@ccc", "=qm") (carry) );
                break;
            default:
# ifdef __x86_64__
                asm ( "rdseed %k0" ASM_FLAG_OUT(, "; setc %1")
                      : "=r" (dst->val), ASM_FLAG_OUT("=@ccc", "=qm") (carry) );
                break;
            case 8:
# endif
                asm ( "rdseed %0" ASM_FLAG_OUT(, "; setc %1")
                      : "=r" (dst->val), ASM_FLAG_OUT("=@ccc", "=qm") (carry) );
                break;
            }
            regs->eflags &= ~EFLAGS_MASK;
            if ( carry )
                regs->eflags |= X86_EFLAGS_CF;
            break;
#endif
        }
    }
    else
    {
        union {
            uint32_t u32[2];
            uint64_t u64[2];
        } *old, *aux;

        /* cmpxchg8b/cmpxchg16b */
        generate_exception_if((s->modrm_reg & 7) != 1, X86_EXC_UD);
        fail_if(!ops->cmpxchg);
        if ( s->rex_prefix & REX_W )
        {
            host_and_vcpu_must_have(cx16);
            generate_exception_if(!is_aligned(s->ea.mem.seg, s->ea.mem.off, 16,
                                              ctxt, ops),
                                  X86_EXC_GP, 0);
            s->op_bytes = 16;
        }
        else
        {
            vcpu_must_have(cx8);
            s->op_bytes = 8;
        }

        old = container_of(&mmvalp->ymm[0], typeof(*old), u64[0]);
        aux = container_of(&mmvalp->ymm[2], typeof(*aux), u64[0]);

        /* Get actual old value. */
        if ( (rc = ops->read(s->ea.mem.seg, s->ea.mem.off, old, s->op_bytes,
                             ctxt)) != X86EMUL_OKAY )
            goto done;

        /* Get expected value. */
        if ( s->op_bytes == 8 )
        {
            aux->u32[0] = regs->eax;
            aux->u32[1] = regs->edx;
        }
        else
        {
            aux->u64[0] = regs->r(ax);
            aux->u64[1] = regs->r(dx);
        }

        if ( memcmp(old, aux, s->op_bytes) )
        {
        cmpxchgNb_failed:
            /* Expected != actual: store actual to rDX:rAX and clear ZF. */
            regs->r(ax) = s->op_bytes == 8 ? old->u32[0] : old->u64[0];
            regs->r(dx) = s->op_bytes == 8 ? old->u32[1] : old->u64[1];
            regs->eflags &= ~X86_EFLAGS_ZF;
        }
        else
        {
            /*
             * Expected == actual: Get proposed value, attempt atomic cmpxchg
             * and set ZF if successful.
             */
            if ( s->op_bytes == 8 )
            {
                aux->u32[0] = regs->ebx;
                aux->u32[1] = regs->ecx;
            }
            else
            {
                aux->u64[0] = regs->r(bx);
                aux->u64[1] = regs->r(cx);
            }

            switch ( rc = ops->cmpxchg(s->ea.mem.seg, s->ea.mem.off, old, aux,
                                       s->op_bytes, s->lock_prefix, ctxt) )
            {
            case X86EMUL_OKAY:
                regs->eflags |= X86_EFLAGS_ZF;
                break;

            case X86EMUL_CMPXCHG_FAILED:
                rc = X86EMUL_OKAY;
                goto cmpxchgNb_failed;

            default:
                goto done;
            }
        }
    }

    rc = X86EMUL_OKAY;

 done:
    return rc;
}
