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

/**
 * Decode an instruction from pc
 * /!\ This function is not intended to fully decode an instruction. It
 * considers that the instruction is valid.
 *
 * This function will get:
 *  - The transfer register
 *  - Sign bit
 *  - Size
 */

int decode_instruction(const struct cpu_user_regs *regs,
                       struct hsr_dabt *dabt);

#endif /* __ARCH_ARM_DECODE_H_ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
