/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * util.c
 *
 * Generic x86 (32-bit and 64-bit) instruction decoder and emulator utility
 * functions.
 */

#include "private.h"

unsigned int x86_insn_length(const struct x86_emulate_state *s,
                             const struct x86_emulate_ctxt *ctxt)
{
    check_state(s);

    return s->ip - ctxt->regs->r(ip);
}

/*
 * This function means to return 'true' for all supported insns with explicit
 * accesses to memory.  This means also insns which don't have an explicit
 * memory operand (like POP), but it does not mean e.g. segment selector
 * loads, where the descriptor table access is considered an implicit one.
 */
bool cf_check x86_insn_is_mem_access(const struct x86_emulate_state *s,
                                     const struct x86_emulate_ctxt *ctxt)
{
    if ( mode_64bit() && s->not_64bit )
        return false;

    if ( s->ea.type == OP_MEM )
    {
        switch ( ctxt->opcode )
        {
        case 0x8d: /* LEA */
        case X86EMUL_OPC(0x0f, 0x0d): /* PREFETCH */
        case X86EMUL_OPC(0x0f, 0x18)
         ... X86EMUL_OPC(0x0f, 0x1f): /* NOP space */
        case X86EMUL_OPC_66(0x0f, 0x18)
         ... X86EMUL_OPC_66(0x0f, 0x1f): /* NOP space */
        case X86EMUL_OPC_F3(0x0f, 0x18)
         ... X86EMUL_OPC_F3(0x0f, 0x1f): /* NOP space */
        case X86EMUL_OPC_F2(0x0f, 0x18)
         ... X86EMUL_OPC_F2(0x0f, 0x1f): /* NOP space */
        case X86EMUL_OPC(0x0f, 0xb9): /* UD1 */
        case X86EMUL_OPC(0x0f, 0xff): /* UD0 */
        case X86EMUL_OPC_EVEX_66(0x0f38, 0xc6): /* V{GATH,SCATT}ERPF*D* */
        case X86EMUL_OPC_EVEX_66(0x0f38, 0xc7): /* V{GATH,SCATT}ERPF*Q* */
            return false;

        case X86EMUL_OPC(0x0f, 0x01):
            return (s->modrm_reg & 7) != 7; /* INVLPG */

        case X86EMUL_OPC(0x0f, 0xae):
            return (s->modrm_reg & 7) != 7; /* CLFLUSH */

        case X86EMUL_OPC_66(0x0f, 0xae):
            return (s->modrm_reg & 7) < 6; /* CLWB, CLFLUSHOPT */
        }

        return true;
    }

    switch ( ctxt->opcode )
    {
    case 0x06 ... 0x07:                  /* PUSH / POP %es */
    case 0x0e:                           /* PUSH %cs */
    case 0x16 ... 0x17:                  /* PUSH / POP %ss */
    case 0x1e ... 0x1f:                  /* PUSH / POP %ds */
    case 0x50 ... 0x5f:                  /* PUSH / POP reg */
    case 0x60 ... 0x61:                  /* PUSHA / POPA */
    case 0x68: case 0x6a:                /* PUSH imm */
    case 0x6c ... 0x6f:                  /* INS / OUTS */
    case 0x8f:                           /* POP r/m */
    case 0x9a:                           /* CALL (far, direct) */
    case 0x9c ... 0x9d:                  /* PUSHF / POPF */
    case 0xa4 ... 0xa7:                  /* MOVS / CMPS */
    case 0xaa ... 0xaf:                  /* STOS / LODS / SCAS */
    case 0xc2 ... 0xc3:                  /* RET (near) */
    case 0xc8 ... 0xc9:                  /* ENTER / LEAVE */
    case 0xca ... 0xcb:                  /* RET (far) */
    case 0xd7:                           /* XLAT */
    case 0xe8:                           /* CALL (near, direct) */
    case X86EMUL_OPC(0x0f, 0xa0):        /* PUSH %fs */
    case X86EMUL_OPC(0x0f, 0xa1):        /* POP %fs */
    case X86EMUL_OPC(0x0f, 0xa8):        /* PUSH %gs */
    case X86EMUL_OPC(0x0f, 0xa9):        /* POP %gs */
    case X86EMUL_OPC(0x0f, 0xf7):        /* MASKMOVQ */
    case X86EMUL_OPC_66(0x0f, 0xf7):     /* MASKMOVDQU */
    case X86EMUL_OPC_VEX_66(0x0f, 0xf7): /* VMASKMOVDQU */
        return true;

    case 0xff:
        switch ( s->modrm_reg & 7 )
        {
        case 2: /* CALL (near, indirect) */
        case 6: /* PUSH r/m */
            return true;
        }
        break;

    case X86EMUL_OPC(0x0f, 0x01):
        /* Cover CLZERO. */
        return (s->modrm_rm & 7) == 4 && (s->modrm_reg & 7) == 7;
    }

    return false;
}

/*
 * This function means to return 'true' for all supported insns with explicit
 * writes to memory.  This means also insns which don't have an explicit
 * memory operand (like PUSH), but it does not mean e.g. segment selector
 * loads, where the (possible) descriptor table write is considered an
 * implicit access.
 */
bool cf_check x86_insn_is_mem_write(const struct x86_emulate_state *s,
                                    const struct x86_emulate_ctxt *ctxt)
{
    if ( mode_64bit() && s->not_64bit )
        return false;

    switch ( s->desc & DstMask )
    {
    case DstMem:
        /* The SrcMem check is to cover {,V}MASKMOV{Q,DQU}. */
        return s->modrm_mod != 3 || (s->desc & SrcMask) == SrcMem;

    case DstBitBase:
    case DstImplicit:
        break;

    default:
        switch ( ctxt->opcode )
        {
        case 0x63:                         /* ARPL */
            return !mode_64bit();

        case X86EMUL_OPC_66(0x0f38, 0xf8): /* MOVDIR64B */
        case X86EMUL_OPC_F2(0x0f38, 0xf8): /* ENQCMD */
        case X86EMUL_OPC_F3(0x0f38, 0xf8): /* ENQCMDS */
            return true;

        case X86EMUL_OPC_EVEX_F3(0x0f38, 0x10) ...
             X86EMUL_OPC_EVEX_F3(0x0f38, 0x15): /* VPMOVUS* */
        case X86EMUL_OPC_EVEX_F3(0x0f38, 0x20) ...
             X86EMUL_OPC_EVEX_F3(0x0f38, 0x25): /* VPMOVS* */
        case X86EMUL_OPC_EVEX_F3(0x0f38, 0x30) ...
             X86EMUL_OPC_EVEX_F3(0x0f38, 0x35): /* VPMOV{D,Q,W}* */
            return s->modrm_mod != 3;
        }

        return false;
    }

    if ( s->modrm_mod == 3 )
    {
        switch ( ctxt->opcode )
        {
        case 0xff: /* Grp5 */
            break;

        case X86EMUL_OPC(0x0f, 0x01): /* CLZERO is the odd one. */
            return (s->modrm_rm & 7) == 4 && (s->modrm_reg & 7) == 7;

        default:
            return false;
        }
    }

    switch ( ctxt->opcode )
    {
    case 0x06:                           /* PUSH %es */
    case 0x0e:                           /* PUSH %cs */
    case 0x16:                           /* PUSH %ss */
    case 0x1e:                           /* PUSH %ds */
    case 0x50 ... 0x57:                  /* PUSH reg */
    case 0x60:                           /* PUSHA */
    case 0x68: case 0x6a:                /* PUSH imm */
    case 0x6c: case 0x6d:                /* INS */
    case 0x9a:                           /* CALL (far, direct) */
    case 0x9c:                           /* PUSHF */
    case 0xa4: case 0xa5:                /* MOVS */
    case 0xaa: case 0xab:                /* STOS */
    case 0xc8:                           /* ENTER */
    case 0xe8:                           /* CALL (near, direct) */
    case X86EMUL_OPC(0x0f, 0xa0):        /* PUSH %fs */
    case X86EMUL_OPC(0x0f, 0xa8):        /* PUSH %gs */
    case X86EMUL_OPC(0x0f, 0xab):        /* BTS */
    case X86EMUL_OPC(0x0f, 0xb3):        /* BTR */
    case X86EMUL_OPC(0x0f, 0xbb):        /* BTC */
        return true;

    case 0xd9:
        switch ( s->modrm_reg & 7 )
        {
        case 2: /* FST m32fp */
        case 3: /* FSTP m32fp */
        case 6: /* FNSTENV */
        case 7: /* FNSTCW */
            return true;
        }
        break;

    case 0xdb:
        switch ( s->modrm_reg & 7 )
        {
        case 1: /* FISTTP m32i */
        case 2: /* FIST m32i */
        case 3: /* FISTP m32i */
        case 7: /* FSTP m80fp */
            return true;
        }
        break;

    case 0xdd:
        switch ( s->modrm_reg & 7 )
        {
        case 1: /* FISTTP m64i */
        case 2: /* FST m64fp */
        case 3: /* FSTP m64fp */
        case 6: /* FNSAVE */
        case 7: /* FNSTSW */
            return true;
        }
        break;

    case 0xdf:
        switch ( s->modrm_reg & 7 )
        {
        case 1: /* FISTTP m16i */
        case 2: /* FIST m16i */
        case 3: /* FISTP m16i */
        case 6: /* FBSTP */
        case 7: /* FISTP m64i */
            return true;
        }
        break;

    case 0xff:
        switch ( s->modrm_reg & 7 )
        {
        case 2: /* CALL (near, indirect) */
        case 3: /* CALL (far, indirect) */
        case 6: /* PUSH r/m */
            return true;
        }
        break;

    case X86EMUL_OPC(0x0f, 0x01):
        switch ( s->modrm_reg & 7 )
        {
        case 0: /* SGDT */
        case 1: /* SIDT */
        case 4: /* SMSW */
            return true;
        }
        break;

    case X86EMUL_OPC(0x0f, 0xae):
        switch ( s->modrm_reg & 7 )
        {
        case 0: /* FXSAVE */
        /* case 3: STMXCSR - handled above */
        case 4: /* XSAVE */
        case 6: /* XSAVEOPT */
            return true;
        }
        break;

    case X86EMUL_OPC(0x0f, 0xba):
        return (s->modrm_reg & 7) > 4; /* BTS / BTR / BTC */

    case X86EMUL_OPC(0x0f, 0xc7):
        switch ( s->modrm_reg & 7 )
        {
        case 1: /* CMPXCHG{8,16}B */
        case 4: /* XSAVEC */
        case 5: /* XSAVES */
            return true;
        }
        break;
    }

    return false;
}
