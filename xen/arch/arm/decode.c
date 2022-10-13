/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * xen/arch/arm/decode.c
 *
 * Instruction decoder
 *
 * Julien Grall <julien.grall@linaro.org>
 * Copyright (C) 2013 Linaro Limited.
 */

#include <xen/guest_access.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/types.h>

#include <asm/current.h>

#include "decode.h"

static void update_dabt(struct hsr_dabt *dabt, int reg,
                        uint8_t size, bool sign)
{
    dabt->reg = reg;
    dabt->size = size;
    dabt->sign = sign;
}

static int decode_thumb2(register_t pc, struct hsr_dabt *dabt, uint16_t hw1)
{
    uint16_t hw2;
    uint16_t rt;

    if ( raw_copy_from_guest(&hw2, (void *__user)(pc + 2), sizeof (hw2)) )
        return -EFAULT;

    rt = (hw2 >> 12) & 0xf;

    switch ( (hw1 >> 9) & 0xf )
    {
    case 12:
    {
        bool sign = (hw1 & (1u << 8));
        bool load = (hw1 & (1u << 4));

        if ( (hw1 & 0x0110) == 0x0100 )
            /* NEON instruction */
            goto bad_thumb2;

        if ( (hw1 & 0x0070) == 0x0070 )
            /* Undefined opcodes */
            goto bad_thumb2;

        /* Store/Load single data item */
        if ( rt == 15 )
            /* XXX: Rt == 15 is only invalid for store instruction */
            goto bad_thumb2;

        if ( !load && sign )
            /* Store instruction doesn't support sign extension */
            goto bad_thumb2;

        update_dabt(dabt, rt, (hw1 >> 5) & 3, sign);

        break;
    }
    default:
        goto bad_thumb2;
    }

    return 0;

bad_thumb2:
    gprintk(XENLOG_ERR, "unhandled THUMB2 instruction 0x%x%x\n", hw1, hw2);

    return 1;
}

static int decode_arm64(register_t pc, mmio_info_t *info)
{
    union instr opcode = {0};
    struct hsr_dabt *dabt = &info->dabt;
    struct instr_details *dabt_instr = &info->dabt_instr;

    if ( raw_copy_from_guest(&opcode.value, (void * __user)pc, sizeof (opcode)) )
    {
        gprintk(XENLOG_ERR, "Could not copy the instruction from PC\n");
        return 1;
    }

    /*
     * Refer Arm v8 ARM DDI 0487G.b, Page - C6-1107
     * "Shared decode for all encodings" (under ldr immediate)
     * If n == t && n != 31, then the return value is implementation defined
     * (can be WBSUPPRESS, UNKNOWN, UNDEFINED or NOP). Thus, we do not support
     * this. This holds true for ldrb/ldrh immediate as well.
     *
     * Also refer, Page - C6-1384, the above described behaviour is same for
     * str immediate. This holds true for strb/strh immediate as well
     */
    if ( (opcode.ldr_str.rn == opcode.ldr_str.rt) && (opcode.ldr_str.rn != 31) )
    {
        gprintk(XENLOG_ERR, "Rn should not be equal to Rt except for r31\n");
        goto bad_loadstore;
    }

    /* First, let's check for the fixed values */
    if ( (opcode.value & POST_INDEX_FIXED_MASK) != POST_INDEX_FIXED_VALUE )
    {
        gprintk(XENLOG_ERR,
                "Decoding instruction 0x%x is not supported\n", opcode.value);
        goto bad_loadstore;
    }

    if ( opcode.ldr_str.v != 0 )
    {
        gprintk(XENLOG_ERR,
                "ldr/str post indexing for vector types are not supported\n");
        goto bad_loadstore;
    }

    /* Check for STR (immediate) */
    if ( opcode.ldr_str.opc == 0 )
        dabt->write = 1;
    /* Check for LDR (immediate) */
    else if ( opcode.ldr_str.opc == 1 )
        dabt->write = 0;
    else
    {
        gprintk(XENLOG_ERR,
                "Decoding ldr/str post indexing is not supported for this variant\n");
        goto bad_loadstore;
    }

    gprintk(XENLOG_INFO,
            "opcode->ldr_str.rt = 0x%x, opcode->ldr_str.size = 0x%x, opcode->ldr_str.imm9 = %d\n",
            opcode.ldr_str.rt, opcode.ldr_str.size, opcode.ldr_str.imm9);

    update_dabt(dabt, opcode.ldr_str.rt, opcode.ldr_str.size, false);

    dabt_instr->state = INSTR_LDR_STR_POSTINDEXING;
    dabt_instr->rn = opcode.ldr_str.rn;
    dabt_instr->imm9 = opcode.ldr_str.imm9;
    dabt->valid = 1;

    return 0;

 bad_loadstore:
    gprintk(XENLOG_ERR, "unhandled Arm instruction 0x%x\n", opcode.value);
    return 1;
}

static int decode_thumb(register_t pc, struct hsr_dabt *dabt)
{
    uint16_t instr;

    if ( raw_copy_from_guest(&instr, (void * __user)pc, sizeof (instr)) )
        return -EFAULT;

    switch ( instr >> 12 )
    {
    case 5:
    {
        /* Load/Store register */
        uint16_t opB = (instr >> 9) & 0x7;
        int reg = instr & 7;

        switch ( opB & 0x3 )
        {
        case 0: /* Non-signed word */
            update_dabt(dabt, reg, 2, false);
            break;
        case 1: /* Non-signed halfword */
            update_dabt(dabt, reg, 1, false);
            break;
        case 2: /* Non-signed byte */
            update_dabt(dabt, reg, 0, false);
            break;
        case 3: /* Signed byte */
            update_dabt(dabt, reg, 0, true);
            break;
        }

        break;
    }
    case 6:
        /* Load/Store word immediate offset */
        update_dabt(dabt, instr & 7, 2, false);
        break;
    case 7:
        /* Load/Store byte immediate offset */
        update_dabt(dabt, instr & 7, 0, false);
        break;
    case 8:
        /* Load/Store halfword immediate offset */
        update_dabt(dabt, instr & 7, 1, false);
        break;
    case 9:
        /* Load/Store word sp offset */
        update_dabt(dabt, (instr >> 8) & 7, 2, false);
        break;
    case 14:
        if ( instr & (1 << 11) )
            return decode_thumb2(pc, dabt, instr);
        goto bad_thumb;
    case 15:
        return decode_thumb2(pc, dabt, instr);
    default:
        goto bad_thumb;
    }

    return 0;

bad_thumb:
    gprintk(XENLOG_ERR, "unhandled THUMB instruction 0x%x\n", instr);
    return 1;
}

int decode_instruction(const struct cpu_user_regs *regs, mmio_info_t *info)
{
    if ( is_32bit_domain(current->domain) && regs->cpsr & PSR_THUMB )
        return decode_thumb(regs->pc, &info->dabt);

    if ( !regs_mode_is_32bit(regs) )
        return decode_arm64(regs->pc, info);

    /* TODO: Handle ARM instruction */
    gprintk(XENLOG_ERR, "unhandled ARM instruction\n");

    return 1;
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
