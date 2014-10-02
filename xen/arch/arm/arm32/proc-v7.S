/*
 * xen/arch/arm/proc-v7.S
 *
 * rename from xen/arch/arm/proc-ca15.S
 * arm v7 specific initializations
 *
 * Copyright (c) 2011 Citrix Systems.
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

#include <asm/asm_defns.h>
#include <asm/arm32/processor.h>

ca15mp_init:
ca7mp_init:
brahma15mp_init:
        /* Set up the SMP bit in ACTLR */
        mrc   CP32(r0, ACTLR)
        orr   r0, r0, #(ACTLR_CAXX_SMP) /* enable SMP bit */
        mcr   CP32(r0, ACTLR)
        mov   pc, lr

        .section ".init.proc.info", #alloc, #execinstr
        .type __v7_ca15mp_proc_info, #object
__v7_ca15mp_proc_info:
        .long 0x410FC0F0             /* Cortex-A15 */
        .long 0xFF0FFFF0             /* Mask */
        .long ca15mp_init
        .long caxx_processor
        .size __v7_ca15mp_proc_info, . - __v7_ca15mp_proc_info

        .section ".init.proc.info", #alloc, #execinstr
        .type __v7_ca7mp_proc_info, #object
__v7_ca7mp_proc_info:
        .long 0x410FC070             /* Cortex-A7 */
        .long 0xFF0FFFF0             /* Mask */
        .long ca7mp_init
        .long caxx_processor
        .size __v7_ca7mp_proc_info, . - __v7_ca7mp_proc_info

        .section ".init.proc.info", #alloc, #execinstr
        .type __v7_brahma15mp_proc_info, #object
__v7_brahma15mp_proc_info:
        .long 0x420F00F0             /* Broadcom Brahma-B15 */
        .long 0xFF0FFFF0             /* Mask */
        .long brahma15mp_init
        .long caxx_processor
        .size __v7_brahma15mp_proc_info, . - __v7_brahma15mp_proc_info

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
