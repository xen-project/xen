/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * fpu.c
 *
 * Generic x86 (32-bit and 64-bit) instruction decoder and emulator.
 *
 * Copyright (c) 2005-2007 Keir Fraser
 * Copyright (c) 2005-2007 XenSource Inc.
 */

#include "private.h"

#ifdef __XEN__
# include <asm/amd.h>
# define cpu_has_amd_erratum(nr) \
         cpu_has_amd_erratum(&current_cpu_data, AMD_ERRATUM_##nr)
#else
# define cpu_has_amd_erratum(nr) 0
#endif

/* Floating point status word definitions. */
#define FSW_ES    (1U << 7)

static inline bool fpu_check_write(void)
{
    uint16_t fsw;

    asm ( "fnstsw %0" : "=am" (fsw) );

    return !(fsw & FSW_ES);
}

#define emulate_fpu_insn_memdst(opc, ext, arg)                          \
do {                                                                    \
    /* ModRM: mod=0, reg=ext, rm=0, i.e. a (%rax) operand */            \
    *insn_bytes = 2;                                                    \
    memcpy(get_stub(stub),                                              \
           ((uint8_t[]){ opc, ((ext) & 7) << 3, 0xc3 }), 3);            \
    invoke_stub("", "", "+m" (arg) : "a" (&(arg)));                     \
    put_stub(stub);                                                     \
} while (0)

#define emulate_fpu_insn_memsrc(opc, ext, arg)                          \
do {                                                                    \
    /* ModRM: mod=0, reg=ext, rm=0, i.e. a (%rax) operand */            \
    memcpy(get_stub(stub),                                              \
           ((uint8_t[]){ opc, ((ext) & 7) << 3, 0xc3 }), 3);            \
    invoke_stub("", "", "=m" (dummy) : "m" (arg), "a" (&(arg)));        \
    put_stub(stub);                                                     \
} while (0)

#define emulate_fpu_insn_stub(bytes...)                                 \
do {                                                                    \
    unsigned int nr_ = sizeof((uint8_t[]){ bytes });                    \
    memcpy(get_stub(stub), ((uint8_t[]){ bytes, 0xc3 }), nr_ + 1);      \
    invoke_stub("", "", "=m" (dummy) : "i" (0));                        \
    put_stub(stub);                                                     \
} while (0)

#define emulate_fpu_insn_stub_eflags(bytes...)                          \
do {                                                                    \
    unsigned int nr_ = sizeof((uint8_t[]){ bytes });                    \
    unsigned long tmp_;                                                 \
    memcpy(get_stub(stub), ((uint8_t[]){ bytes, 0xc3 }), nr_ + 1);      \
    invoke_stub(_PRE_EFLAGS("[eflags]", "[mask]", "[tmp]"),             \
                _POST_EFLAGS("[eflags]", "[mask]", "[tmp]"),            \
                [eflags] "+g" (regs->eflags), [tmp] "=&r" (tmp_)        \
                : [mask] "i" (X86_EFLAGS_ZF|X86_EFLAGS_PF|X86_EFLAGS_CF)); \
    put_stub(stub);                                                     \
} while (0)

int x86emul_fpu(struct x86_emulate_state *s,
                struct cpu_user_regs *regs,
                struct operand *dst,
                struct operand *src,
                struct x86_emulate_ctxt *ctxt,
                const struct x86_emulate_ops *ops,
                unsigned int *insn_bytes,
                enum x86_emulate_fpu_type *fpu_type,
#define fpu_type (*fpu_type) /* for get_fpu() */
                mmval_t *mmvalp)
#define stub_exn (*s->stub_exn) /* for invoke_stub() */
{
    uint8_t b;
    int rc;
    struct x86_emulate_stub stub = {};

    switch ( b = ctxt->opcode )
    {
        unsigned long dummy;

    case 0x9b:  /* wait/fwait */
        host_and_vcpu_must_have(fpu);
        get_fpu(X86EMUL_FPU_wait);
        emulate_fpu_insn_stub(b);
        break;

    case 0xd8: /* FPU 0xd8 */
        host_and_vcpu_must_have(fpu);
        get_fpu(X86EMUL_FPU_fpu);
        switch ( s->modrm )
        {
        case 0xc0 ... 0xc7: /* fadd %stN,%st */
        case 0xc8 ... 0xcf: /* fmul %stN,%st */
        case 0xd0 ... 0xd7: /* fcom %stN,%st */
        case 0xd8 ... 0xdf: /* fcomp %stN,%st */
        case 0xe0 ... 0xe7: /* fsub %stN,%st */
        case 0xe8 ... 0xef: /* fsubr %stN,%st */
        case 0xf0 ... 0xf7: /* fdiv %stN,%st */
        case 0xf8 ... 0xff: /* fdivr %stN,%st */
            emulate_fpu_insn_stub(0xd8, s->modrm);
            break;
        default:
        fpu_memsrc32:
            ASSERT(s->ea.type == OP_MEM);
            if ( (rc = ops->read(s->ea.mem.seg, s->ea.mem.off, &src->val,
                                 4, ctxt)) != X86EMUL_OKAY )
                goto done;
            emulate_fpu_insn_memsrc(b, s->modrm_reg & 7, src->val);
            break;
        }
        break;

    case 0xd9: /* FPU 0xd9 */
        host_and_vcpu_must_have(fpu);
        get_fpu(X86EMUL_FPU_fpu);
        switch ( s->modrm )
        {
        case 0xfb: /* fsincos */
            fail_if(cpu_has_amd_erratum(573));
            /* fall through */
        case 0xc0 ... 0xc7: /* fld %stN */
        case 0xc8 ... 0xcf: /* fxch %stN */
        case 0xd0: /* fnop */
        case 0xd8 ... 0xdf: /* fstp %stN (alternative encoding) */
        case 0xe0: /* fchs */
        case 0xe1: /* fabs */
        case 0xe4: /* ftst */
        case 0xe5: /* fxam */
        case 0xe8: /* fld1 */
        case 0xe9: /* fldl2t */
        case 0xea: /* fldl2e */
        case 0xeb: /* fldpi */
        case 0xec: /* fldlg2 */
        case 0xed: /* fldln2 */
        case 0xee: /* fldz */
        case 0xf0: /* f2xm1 */
        case 0xf1: /* fyl2x */
        case 0xf2: /* fptan */
        case 0xf3: /* fpatan */
        case 0xf4: /* fxtract */
        case 0xf5: /* fprem1 */
        case 0xf6: /* fdecstp */
        case 0xf7: /* fincstp */
        case 0xf8: /* fprem */
        case 0xf9: /* fyl2xp1 */
        case 0xfa: /* fsqrt */
        case 0xfc: /* frndint */
        case 0xfd: /* fscale */
        case 0xfe: /* fsin */
        case 0xff: /* fcos */
            emulate_fpu_insn_stub(0xd9, s->modrm);
            break;
        default:
            generate_exception_if(s->ea.type != OP_MEM, X86_EXC_UD);
            switch ( s->modrm_reg & 7 )
            {
            case 0: /* fld m32fp */
                goto fpu_memsrc32;
            case 2: /* fst m32fp */
            case 3: /* fstp m32fp */
            fpu_memdst32:
                *dst = s->ea;
                dst->bytes = 4;
                emulate_fpu_insn_memdst(b, s->modrm_reg & 7, dst->val);
                break;
            case 4: /* fldenv */
                /* Raise #MF now if there are pending unmasked exceptions. */
                emulate_fpu_insn_stub(0xd9, 0xd0 /* fnop */);
                /* fall through */
            case 6: /* fnstenv */
                fail_if(!ops->blk);
                s->blk = s->modrm_reg & 2 ? blk_fst : blk_fld;
                /*
                 * REX is meaningless for these insns by this point - (ab)use
                 * the field to communicate real vs protected mode to ->blk().
                 */
                s->rex_prefix = in_protmode(ctxt, ops);
                if ( (rc = ops->blk(s->ea.mem.seg, s->ea.mem.off, NULL,
                                    s->op_bytes > 2 ? sizeof(struct x87_env32)
                                                    : sizeof(struct x87_env16),
                                    &regs->eflags,
                                    s, ctxt)) != X86EMUL_OKAY )
                    goto done;
                s->fpu_ctrl = true;
                break;
            case 5: /* fldcw m2byte */
                s->fpu_ctrl = true;
            fpu_memsrc16:
                if ( (rc = ops->read(s->ea.mem.seg, s->ea.mem.off, &src->val,
                                     2, ctxt)) != X86EMUL_OKAY )
                    goto done;
                emulate_fpu_insn_memsrc(b, s->modrm_reg & 7, src->val);
                break;
            case 7: /* fnstcw m2byte */
                s->fpu_ctrl = true;
            fpu_memdst16:
                *dst = s->ea;
                dst->bytes = 2;
                emulate_fpu_insn_memdst(b, s->modrm_reg & 7, dst->val);
                break;
            default:
                generate_exception(X86_EXC_UD);
            }
            /*
             * Control instructions can't raise FPU exceptions, so we need
             * to consider suppressing writes only for non-control ones.
             */
            if ( dst->type == OP_MEM && !s->fpu_ctrl && !fpu_check_write() )
                dst->type = OP_NONE;
            break;
        }
        break;

    case 0xda: /* FPU 0xda */
        host_and_vcpu_must_have(fpu);
        get_fpu(X86EMUL_FPU_fpu);
        switch ( s->modrm )
        {
        case 0xc0 ... 0xc7: /* fcmovb %stN */
        case 0xc8 ... 0xcf: /* fcmove %stN */
        case 0xd0 ... 0xd7: /* fcmovbe %stN */
        case 0xd8 ... 0xdf: /* fcmovu %stN */
            vcpu_must_have(cmov);
            emulate_fpu_insn_stub_eflags(0xda, s->modrm);
            break;
        case 0xe9:          /* fucompp */
            emulate_fpu_insn_stub(0xda, s->modrm);
            break;
        default:
            generate_exception_if(s->ea.type != OP_MEM, X86_EXC_UD);
            goto fpu_memsrc32;
        }
        break;

    case 0xdb: /* FPU 0xdb */
        host_and_vcpu_must_have(fpu);
        get_fpu(X86EMUL_FPU_fpu);
        switch ( s->modrm )
        {
        case 0xc0 ... 0xc7: /* fcmovnb %stN */
        case 0xc8 ... 0xcf: /* fcmovne %stN */
        case 0xd0 ... 0xd7: /* fcmovnbe %stN */
        case 0xd8 ... 0xdf: /* fcmovnu %stN */
        case 0xe8 ... 0xef: /* fucomi %stN */
        case 0xf0 ... 0xf7: /* fcomi %stN */
            vcpu_must_have(cmov);
            emulate_fpu_insn_stub_eflags(0xdb, s->modrm);
            break;
        case 0xe0: /* fneni - 8087 only, ignored by 287 */
        case 0xe1: /* fndisi - 8087 only, ignored by 287 */
        case 0xe2: /* fnclex */
        case 0xe3: /* fninit */
        case 0xe4: /* fnsetpm - 287 only, ignored by 387 */
        /* case 0xe5: frstpm - 287 only, #UD on 387 */
            s->fpu_ctrl = true;
            emulate_fpu_insn_stub(0xdb, s->modrm);
            break;
        default:
            generate_exception_if(s->ea.type != OP_MEM, X86_EXC_UD);
            switch ( s->modrm_reg & 7 )
            {
            case 0: /* fild m32i */
                goto fpu_memsrc32;
            case 1: /* fisttp m32i */
                host_and_vcpu_must_have(sse3);
                /* fall through */
            case 2: /* fist m32i */
            case 3: /* fistp m32i */
                goto fpu_memdst32;
            case 5: /* fld m80fp */
            fpu_memsrc80:
                if ( (rc = ops->read(s->ea.mem.seg, s->ea.mem.off, mmvalp,
                                     10, ctxt)) != X86EMUL_OKAY )
                    goto done;
                emulate_fpu_insn_memsrc(b, s->modrm_reg & 7, *mmvalp);
                break;
            case 7: /* fstp m80fp */
            fpu_memdst80:
                fail_if(!ops->write);
                emulate_fpu_insn_memdst(b, s->modrm_reg & 7, *mmvalp);
                if ( fpu_check_write() &&
                     (rc = ops->write(s->ea.mem.seg, s->ea.mem.off, mmvalp,
                                      10, ctxt)) != X86EMUL_OKAY )
                    goto done;
                break;
            default:
                generate_exception(X86_EXC_UD);
            }
            break;
        }
        break;

    case 0xdc: /* FPU 0xdc */
        host_and_vcpu_must_have(fpu);
        get_fpu(X86EMUL_FPU_fpu);
        switch ( s->modrm )
        {
        case 0xc0 ... 0xc7: /* fadd %st,%stN */
        case 0xc8 ... 0xcf: /* fmul %st,%stN */
        case 0xd0 ... 0xd7: /* fcom %stN,%st (alternative encoding) */
        case 0xd8 ... 0xdf: /* fcomp %stN,%st (alternative encoding) */
        case 0xe0 ... 0xe7: /* fsubr %st,%stN */
        case 0xe8 ... 0xef: /* fsub %st,%stN */
        case 0xf0 ... 0xf7: /* fdivr %st,%stN */
        case 0xf8 ... 0xff: /* fdiv %st,%stN */
            emulate_fpu_insn_stub(0xdc, s->modrm);
            break;
        default:
        fpu_memsrc64:
            ASSERT(s->ea.type == OP_MEM);
            if ( (rc = ops->read(s->ea.mem.seg, s->ea.mem.off, &src->val,
                                 8, ctxt)) != X86EMUL_OKAY )
                goto done;
            emulate_fpu_insn_memsrc(b, s->modrm_reg & 7, src->val);
            break;
        }
        break;

    case 0xdd: /* FPU 0xdd */
        host_and_vcpu_must_have(fpu);
        get_fpu(X86EMUL_FPU_fpu);
        switch ( s->modrm )
        {
        case 0xc0 ... 0xc7: /* ffree %stN */
        case 0xc8 ... 0xcf: /* fxch %stN (alternative encoding) */
        case 0xd0 ... 0xd7: /* fst %stN */
        case 0xd8 ... 0xdf: /* fstp %stN */
        case 0xe0 ... 0xe7: /* fucom %stN */
        case 0xe8 ... 0xef: /* fucomp %stN */
            emulate_fpu_insn_stub(0xdd, s->modrm);
            break;
        default:
            generate_exception_if(s->ea.type != OP_MEM, X86_EXC_UD);
            switch ( s->modrm_reg & 7 )
            {
            case 0: /* fld m64fp */;
                goto fpu_memsrc64;
            case 1: /* fisttp m64i */
                host_and_vcpu_must_have(sse3);
                /* fall through */
            case 2: /* fst m64fp */
            case 3: /* fstp m64fp */
            fpu_memdst64:
                *dst = s->ea;
                dst->bytes = 8;
                emulate_fpu_insn_memdst(b, s->modrm_reg & 7, dst->val);
                break;
            case 4: /* frstor */
                /* Raise #MF now if there are pending unmasked exceptions. */
                emulate_fpu_insn_stub(0xd9, 0xd0 /* fnop */);
                /* fall through */
            case 6: /* fnsave */
                fail_if(!ops->blk);
                s->blk = s->modrm_reg & 2 ? blk_fst : blk_fld;
                /*
                 * REX is meaningless for these insns by this point - (ab)use
                 * the field to communicate real vs protected mode to ->blk().
                 */
                s->rex_prefix = in_protmode(ctxt, ops);
                if ( (rc = ops->blk(s->ea.mem.seg, s->ea.mem.off, NULL,
                                    s->op_bytes > 2 ? sizeof(struct x87_env32) + 80
                                                    : sizeof(struct x87_env16) + 80,
                                    &regs->eflags,
                                    s, ctxt)) != X86EMUL_OKAY )
                    goto done;
                s->fpu_ctrl = true;
                break;
            case 7: /* fnstsw m2byte */
                s->fpu_ctrl = true;
                goto fpu_memdst16;
            default:
                generate_exception(X86_EXC_UD);
            }
            /*
             * Control instructions can't raise FPU exceptions, so we need
             * to consider suppressing writes only for non-control ones.
             */
            if ( dst->type == OP_MEM && !s->fpu_ctrl && !fpu_check_write() )
                dst->type = OP_NONE;
            break;
        }
        break;

    case 0xde: /* FPU 0xde */
        host_and_vcpu_must_have(fpu);
        get_fpu(X86EMUL_FPU_fpu);
        switch ( s->modrm )
        {
        case 0xc0 ... 0xc7: /* faddp %stN */
        case 0xc8 ... 0xcf: /* fmulp %stN */
        case 0xd0 ... 0xd7: /* fcomp %stN (alternative encoding) */
        case 0xd9: /* fcompp */
        case 0xe0 ... 0xe7: /* fsubrp %stN */
        case 0xe8 ... 0xef: /* fsubp %stN */
        case 0xf0 ... 0xf7: /* fdivrp %stN */
        case 0xf8 ... 0xff: /* fdivp %stN */
            emulate_fpu_insn_stub(0xde, s->modrm);
            break;
        default:
            generate_exception_if(s->ea.type != OP_MEM, X86_EXC_UD);
            emulate_fpu_insn_memsrc(b, s->modrm_reg & 7, src->val);
            break;
        }
        break;

    case 0xdf: /* FPU 0xdf */
        host_and_vcpu_must_have(fpu);
        get_fpu(X86EMUL_FPU_fpu);
        switch ( s->modrm )
        {
        case 0xe0:
            /* fnstsw %ax */
            s->fpu_ctrl = true;
            dst->bytes = 2;
            dst->type = OP_REG;
            dst->reg = (void *)&regs->ax;
            emulate_fpu_insn_memdst(b, s->modrm_reg & 7, dst->val);
            break;
        case 0xe8 ... 0xef: /* fucomip %stN */
        case 0xf0 ... 0xf7: /* fcomip %stN */
            vcpu_must_have(cmov);
            emulate_fpu_insn_stub_eflags(0xdf, s->modrm);
            break;
        case 0xc0 ... 0xc7: /* ffreep %stN */
        case 0xc8 ... 0xcf: /* fxch %stN (alternative encoding) */
        case 0xd0 ... 0xd7: /* fstp %stN (alternative encoding) */
        case 0xd8 ... 0xdf: /* fstp %stN (alternative encoding) */
            emulate_fpu_insn_stub(0xdf, s->modrm);
            break;
        default:
            generate_exception_if(s->ea.type != OP_MEM, X86_EXC_UD);
            switch ( s->modrm_reg & 7 )
            {
            case 0: /* fild m16i */
                goto fpu_memsrc16;
            case 1: /* fisttp m16i */
                host_and_vcpu_must_have(sse3);
                /* fall through */
            case 2: /* fist m16i */
            case 3: /* fistp m16i */
                goto fpu_memdst16;
            case 4: /* fbld m80dec */
                goto fpu_memsrc80;
            case 5: /* fild m64i */
                dst->type = OP_NONE;
                goto fpu_memsrc64;
            case 6: /* fbstp packed bcd */
                goto fpu_memdst80;
            case 7: /* fistp m64i */
                goto fpu_memdst64;
            }
            ASSERT_UNREACHABLE();
            return X86EMUL_UNHANDLEABLE;
        }
        break;

    default:
        ASSERT_UNREACHABLE();
        return X86EMUL_UNHANDLEABLE;
    }

    rc = X86EMUL_OKAY;

 done:
    put_stub(stub);
    return rc;

#ifdef __XEN__
 emulation_stub_failure:
    return X86EMUL_stub_failure;
#endif
}
