/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * blk.c - helper for x86_emulate.c
 *
 * Generic x86 (32-bit and 64-bit) instruction decoder and emulator.
 */

#include "private.h"

#if !defined(X86EMUL_NO_FPU) || !defined(X86EMUL_NO_MMX) || \
    !defined(X86EMUL_NO_SIMD)
# ifdef __XEN__
#  include <asm/xstate.h>
#  define FXSAVE_AREA ((void *)&current->arch.xsave_area->fpu_sse)
# else
#  define FXSAVE_AREA get_fpu_save_area()
# endif
#endif

int x86_emul_blk(
    void *ptr,
    void *data,
    unsigned int bytes,
    uint32_t *eflags,
    struct x86_emulate_state *s,
    struct x86_emulate_ctxt *ctxt)
{
    int rc = X86EMUL_OKAY;

    switch ( s->blk )
    {
        bool zf;
#ifndef X86EMUL_NO_FPU
        struct {
            struct x87_env32 env;
            struct {
               uint8_t bytes[10];
            } freg[8];
        } fpstate;
#endif

        /*
         * Throughout this switch(), memory clobbers are used to compensate
         * that other operands may not properly express the (full) memory
         * ranges covered.
         */
    case blk_enqcmd:
        ASSERT(bytes == 64);
        if ( ((unsigned long)ptr & 0x3f) )
        {
            ASSERT_UNREACHABLE();
            return X86EMUL_UNHANDLEABLE;
        }
        *eflags &= ~EFLAGS_MASK;
#ifdef HAVE_AS_ENQCMD
        asm ( "enqcmds (%[src]), %[dst]" ASM_FLAG_OUT(, "; setz %[zf]")
              : [zf] ASM_FLAG_OUT("=@ccz", "=qm") (zf)
              : [src] "r" (data), [dst] "r" (ptr) : "memory" );
#else
        /* enqcmds (%rsi), %rdi */
        asm ( ".byte 0xf3, 0x0f, 0x38, 0xf8, 0x3e"
              ASM_FLAG_OUT(, "; setz %[zf]")
              : [zf] ASM_FLAG_OUT("=@ccz", "=qm") (zf)
              : "S" (data), "D" (ptr) : "memory" );
#endif
        if ( zf )
            *eflags |= X86_EFLAGS_ZF;
        break;

#ifndef X86EMUL_NO_FPU

    case blk_fld:
        ASSERT(!data);

        /* s->rex_prefix carries CR0.PE && !EFLAGS.VM setting */
        switch ( bytes )
        {
        case sizeof(fpstate.env): /* 32-bit FLDENV */
        case sizeof(fpstate):     /* 32-bit FRSTOR */
            memcpy(&fpstate.env, ptr, sizeof(fpstate.env));
            if ( !s->rex_prefix )
            {
                /* Convert 32-bit real/vm86 to 32-bit prot format. */
                unsigned int fip = fpstate.env.mode.real.fip_lo +
                                   (fpstate.env.mode.real.fip_hi << 16);
                unsigned int fdp = fpstate.env.mode.real.fdp_lo +
                                   (fpstate.env.mode.real.fdp_hi << 16);
                unsigned int fop = fpstate.env.mode.real.fop;

                fpstate.env.mode.prot.fip = fip & 0xf;
                fpstate.env.mode.prot.fcs = fip >> 4;
                fpstate.env.mode.prot.fop = fop;
                fpstate.env.mode.prot.fdp = fdp & 0xf;
                fpstate.env.mode.prot.fds = fdp >> 4;
            }

            if ( bytes == sizeof(fpstate.env) )
                ptr = NULL;
            else
                ptr += sizeof(fpstate.env);
            break;

        case sizeof(struct x87_env16):                        /* 16-bit FLDENV */
        case sizeof(struct x87_env16) + sizeof(fpstate.freg): /* 16-bit FRSTOR */
        {
            const struct x87_env16 *env = ptr;

            fpstate.env.fcw = env->fcw;
            fpstate.env.fsw = env->fsw;
            fpstate.env.ftw = env->ftw;

            if ( s->rex_prefix )
            {
                /* Convert 16-bit prot to 32-bit prot format. */
                fpstate.env.mode.prot.fip = env->mode.prot.fip;
                fpstate.env.mode.prot.fcs = env->mode.prot.fcs;
                fpstate.env.mode.prot.fdp = env->mode.prot.fdp;
                fpstate.env.mode.prot.fds = env->mode.prot.fds;
                fpstate.env.mode.prot.fop = 0; /* unknown */
            }
            else
            {
                /* Convert 16-bit real/vm86 to 32-bit prot format. */
                unsigned int fip = env->mode.real.fip_lo +
                                   (env->mode.real.fip_hi << 16);
                unsigned int fdp = env->mode.real.fdp_lo +
                                   (env->mode.real.fdp_hi << 16);
                unsigned int fop = env->mode.real.fop;

                fpstate.env.mode.prot.fip = fip & 0xf;
                fpstate.env.mode.prot.fcs = fip >> 4;
                fpstate.env.mode.prot.fop = fop;
                fpstate.env.mode.prot.fdp = fdp & 0xf;
                fpstate.env.mode.prot.fds = fdp >> 4;
            }

            if ( bytes == sizeof(*env) )
                ptr = NULL;
            else
                ptr += sizeof(*env);
            break;
        }

        default:
            ASSERT_UNREACHABLE();
            return X86EMUL_UNHANDLEABLE;
        }

        if ( ptr )
        {
            memcpy(fpstate.freg, ptr, sizeof(fpstate.freg));
            asm volatile ( "frstor %0" :: "m" (fpstate) );
        }
        else
            asm volatile ( "fldenv %0" :: "m" (fpstate.env) );
        break;

    case blk_fst:
        ASSERT(!data);

        /* Don't chance consuming uninitialized data. */
        memset(&fpstate, 0, sizeof(fpstate));
        if ( bytes > sizeof(fpstate.env) )
            asm ( "fnsave %0" : "+m" (fpstate) );
        else
            asm ( "fnstenv %0" : "+m" (fpstate.env) );

        /* s->rex_prefix carries CR0.PE && !EFLAGS.VM setting */
        switch ( bytes )
        {
        case sizeof(fpstate.env): /* 32-bit FNSTENV */
        case sizeof(fpstate):     /* 32-bit FNSAVE */
            if ( !s->rex_prefix )
            {
                /* Convert 32-bit prot to 32-bit real/vm86 format. */
                unsigned int fip = fpstate.env.mode.prot.fip +
                                   (fpstate.env.mode.prot.fcs << 4);
                unsigned int fdp = fpstate.env.mode.prot.fdp +
                                   (fpstate.env.mode.prot.fds << 4);
                unsigned int fop = fpstate.env.mode.prot.fop;

                memset(&fpstate.env.mode, 0, sizeof(fpstate.env.mode));
                fpstate.env.mode.real.fip_lo = fip;
                fpstate.env.mode.real.fip_hi = fip >> 16;
                fpstate.env.mode.real.fop = fop;
                fpstate.env.mode.real.fdp_lo = fdp;
                fpstate.env.mode.real.fdp_hi = fdp >> 16;
            }
            memcpy(ptr, &fpstate.env, sizeof(fpstate.env));
            if ( bytes == sizeof(fpstate.env) )
                ptr = NULL;
            else
                ptr += sizeof(fpstate.env);
            break;

        case sizeof(struct x87_env16):                        /* 16-bit FNSTENV */
        case sizeof(struct x87_env16) + sizeof(fpstate.freg): /* 16-bit FNSAVE */
            if ( s->rex_prefix )
            {
                /* Convert 32-bit prot to 16-bit prot format. */
                struct x87_env16 *env = ptr;

                env->fcw = fpstate.env.fcw;
                env->fsw = fpstate.env.fsw;
                env->ftw = fpstate.env.ftw;
                env->mode.prot.fip = fpstate.env.mode.prot.fip;
                env->mode.prot.fcs = fpstate.env.mode.prot.fcs;
                env->mode.prot.fdp = fpstate.env.mode.prot.fdp;
                env->mode.prot.fds = fpstate.env.mode.prot.fds;
            }
            else
            {
                /* Convert 32-bit prot to 16-bit real/vm86 format. */
                unsigned int fip = fpstate.env.mode.prot.fip +
                                   (fpstate.env.mode.prot.fcs << 4);
                unsigned int fdp = fpstate.env.mode.prot.fdp +
                                   (fpstate.env.mode.prot.fds << 4);
                struct x87_env16 env = {
                    .fcw = fpstate.env.fcw,
                    .fsw = fpstate.env.fsw,
                    .ftw = fpstate.env.ftw,
                    .mode.real.fip_lo = fip,
                    .mode.real.fip_hi = fip >> 16,
                    .mode.real.fop = fpstate.env.mode.prot.fop,
                    .mode.real.fdp_lo = fdp,
                    .mode.real.fdp_hi = fdp >> 16
                };

                memcpy(ptr, &env, sizeof(env));
            }
            if ( bytes == sizeof(struct x87_env16) )
                ptr = NULL;
            else
                ptr += sizeof(struct x87_env16);
            break;

        default:
            ASSERT_UNREACHABLE();
            return X86EMUL_UNHANDLEABLE;
        }

        if ( ptr )
            memcpy(ptr, fpstate.freg, sizeof(fpstate.freg));
        break;

#endif /* X86EMUL_NO_FPU */

#if !defined(X86EMUL_NO_FPU) || !defined(X86EMUL_NO_MMX) || \
    !defined(X86EMUL_NO_SIMD)

    case blk_fxrstor:
    {
        struct x86_fxsr *fxsr = FXSAVE_AREA;

        ASSERT(!data);
        ASSERT(bytes == sizeof(*fxsr));
        ASSERT(s->op_bytes <= bytes);

        if ( s->op_bytes < sizeof(*fxsr) )
        {
            if ( s->rex_prefix & REX_W )
            {
                /*
                 * The only way to force fxsaveq on a wide range of gas
                 * versions. On older versions the rex64 prefix works only if
                 * we force an addressing mode that doesn't require extended
                 * registers.
                 */
                asm volatile ( ".byte 0x48; fxsave (%1)"
                               : "=m" (*fxsr) : "R" (fxsr) );
            }
            else
                asm volatile ( "fxsave %0" : "=m" (*fxsr) );
        }

        /*
         * Don't chance the reserved or available ranges to contain any
         * data FXRSTOR may actually consume in some way: Copy only the
         * defined portion, and zero the rest.
         */
        memcpy(fxsr, ptr, min(s->op_bytes,
                              (unsigned int)offsetof(struct x86_fxsr, rsvd)));
        memset(fxsr->rsvd, 0, sizeof(*fxsr) - offsetof(struct x86_fxsr, rsvd));

        generate_exception_if(fxsr->mxcsr & ~mxcsr_mask, X86_EXC_GP, 0);

        if ( s->rex_prefix & REX_W )
        {
            /* See above for why operand/constraints are this way. */
            asm volatile ( ".byte 0x48; fxrstor (%1)"
                           :: "m" (*fxsr), "R" (fxsr) );
        }
        else
            asm volatile ( "fxrstor %0" :: "m" (*fxsr) );
        break;
    }

    case blk_fxsave:
    {
        struct x86_fxsr *fxsr = FXSAVE_AREA;

        ASSERT(!data);
        ASSERT(bytes == sizeof(*fxsr));
        ASSERT(s->op_bytes <= bytes);

        if ( s->op_bytes < sizeof(*fxsr) )
            /* Don't chance consuming uninitialized data. */
            memset(fxsr, 0, s->op_bytes);
        else
            fxsr = ptr;

        if ( s->rex_prefix & REX_W )
        {
            /* See above for why operand/constraints are this way. */
            asm volatile ( ".byte 0x48; fxsave (%1)"
                           : "=m" (*fxsr) : "R" (fxsr) );
        }
        else
            asm volatile ( "fxsave %0" : "=m" (*fxsr) );

        if ( fxsr != ptr ) /* i.e. s->op_bytes < sizeof(*fxsr) */
            memcpy(ptr, fxsr, s->op_bytes);
        break;
    }

#endif /* X86EMUL_NO_{FPU,MMX,SIMD} */

    case blk_movdir:
        switch ( bytes )
        {
#ifdef __x86_64__
        case sizeof(uint32_t):
# ifdef HAVE_AS_MOVDIR
            asm ( "movdiri %0, (%1)"
                  :: "r" (*(uint32_t *)data), "r" (ptr) : "memory" );
# else
            /* movdiri %esi, (%rdi) */
            asm ( ".byte 0x0f, 0x38, 0xf9, 0x37"
                  :: "S" (*(uint32_t *)data), "D" (ptr) : "memory" );
# endif
            break;
#endif

        case sizeof(unsigned long):
#ifdef HAVE_AS_MOVDIR
            asm ( "movdiri %0, (%1)"
                  :: "r" (*(unsigned long *)data), "r" (ptr) : "memory" );
#else
            /* movdiri %rsi, (%rdi) */
            asm ( ".byte 0x48, 0x0f, 0x38, 0xf9, 0x37"
                  :: "S" (*(unsigned long *)data), "D" (ptr) : "memory" );
#endif
            break;

        case 64:
            if ( ((unsigned long)ptr & 0x3f) )
            {
                ASSERT_UNREACHABLE();
                return X86EMUL_UNHANDLEABLE;
            }
#ifdef HAVE_AS_MOVDIR
            asm ( "movdir64b (%0), %1" :: "r" (data), "r" (ptr) : "memory" );
#else
            /* movdir64b (%rsi), %rdi */
            asm ( ".byte 0x66, 0x0f, 0x38, 0xf8, 0x3e"
                  :: "S" (data), "D" (ptr) : "memory" );
#endif
            break;

        default:
            ASSERT_UNREACHABLE();
            return X86EMUL_UNHANDLEABLE;
        }
        break;

    default:
        ASSERT_UNREACHABLE();
        return X86EMUL_UNHANDLEABLE;
    }

 done: __maybe_unused;
    return rc;

}
