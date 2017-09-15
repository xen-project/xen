/*
 * xen/arch/arm/decode.c
 *
 * Instruction decoder
 *
 * Julien Grall <julien.grall@linaro.org>
 * Copyright (C) 2013 Linaro Limited.
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
 */

#include <xen/types.h>
#include <xen/sched.h>
#include <asm/current.h>
#include <asm/guest_access.h>
#include <xen/lib.h>

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

int decode_instruction(const struct cpu_user_regs *regs, struct hsr_dabt *dabt)
{
    if ( is_32bit_domain(current->domain) && regs->cpsr & PSR_THUMB )
        return decode_thumb(regs->pc, dabt);

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
