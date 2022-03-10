/*
 * xen/arch/arm/decode.h
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

#ifndef __ARCH_ARM_DECODE_H_
#define __ARCH_ARM_DECODE_H_

#include <asm/regs.h>
#include <asm/processor.h>

/*
 * Refer to the ARMv8 ARM (DDI 0487G.b), Section C4.1.4 Loads and Stores
 * Page 318 specifies the following bit pattern for
 * "load/store register (immediate post-indexed)".
 *
 * 31 30 29  27 26 25  23   21 20              11   9         4       0
 * ___________________________________________________________________
 * |size|1 1 1 |V |0 0 |opc |0 |      imm9     |0 1 |  Rn     |  Rt   |
 * |____|______|__|____|____|__|_______________|____|_________|_______|
 */
union instr {
    uint32_t value;
    struct {
        unsigned int rt:5;     /* Rt register */
        unsigned int rn:5;     /* Rn register */
        unsigned int fixed1:2; /* value == 01b */
        signed int imm9:9;     /* imm9 */
        unsigned int fixed2:1; /* value == 0b */
        unsigned int opc:2;    /* opc */
        unsigned int fixed3:2; /* value == 00b */
        unsigned int v:1;      /* vector */
        unsigned int fixed4:3; /* value == 111b */
        unsigned int size:2;   /* size */
    } ldr_str;
};

#define POST_INDEX_FIXED_MASK   0x3B200C00
#define POST_INDEX_FIXED_VALUE  0x38000400

/*
 * Decode an instruction from pc
 * /!\ This function is intended to decode an instruction. It considers that the
 * instruction is valid.
 *
 * In case of thumb mode, this function will get:
 *  - The transfer register (ie Rt)
 *  - Sign bit
 *  - Size
 *
 * In case of arm64 mode, this function will get:
 * - The transfer register (ie Rt)
 * - The source register (ie Rn)
 * - Size
 * - Immediate offset
 * - Read or write
 */

int decode_instruction(const struct cpu_user_regs *regs,
                       mmio_info_t *info);

#endif /* __ARCH_ARM_DECODE_H_ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
