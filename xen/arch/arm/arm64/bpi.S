/*
 * Contains CPU specific branch predictor invalidation sequences
 *
 * Copyright (C) 2018 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <asm/smccc.h>

.macro ventry target
    .rept 31
    nop
    .endr
    b	\target
.endm

.macro vectors target
    ventry \target + 0x000
    ventry \target + 0x080
    ventry \target + 0x100
    ventry \target + 0x180

    ventry \target + 0x200
    ventry \target + 0x280
    ventry \target + 0x300
    ventry \target + 0x380

    ventry \target + 0x400
    ventry \target + 0x480
    ventry \target + 0x500
    ventry \target + 0x580

    ventry \target + 0x600
    ventry \target + 0x680
    ventry \target + 0x700
    ventry \target + 0x780
.endm

/*
 * Populate 4 vector tables. This will cover up to 4 different
 * micro-architectures in a system.
 */
    .align	11
ENTRY(__bp_harden_hyp_vecs_start)
    .rept 4
    vectors hyp_traps_vector
    .endr
ENTRY(__bp_harden_hyp_vecs_end)

.macro mitigate_spectre_bhb_loop count
ENTRY(__mitigate_spectre_bhb_loop_start_\count)
    stp     x0, x1, [sp, #-16]!
    mov     x0, \count
.Lspectre_bhb_loop\@:
    b   . + 4
    subs    x0, x0, #1
    b.ne    .Lspectre_bhb_loop\@
    sb
    ldp     x0, x1, [sp], #16
ENTRY(__mitigate_spectre_bhb_loop_end_\count)
.endm

.macro smccc_workaround num smcc_id
ENTRY(__smccc_workaround_smc_start_\num)
    sub     sp, sp, #(8 * 4)
    stp     x0, x1, [sp, #(8 * 2)]
    stp     x2, x3, [sp, #(8 * 0)]
    mov     w0, \smcc_id
    smc     #0
    ldp     x2, x3, [sp, #(8 * 0)]
    ldp     x0, x1, [sp, #(8 * 2)]
    add     sp, sp, #(8 * 4)
ENTRY(__smccc_workaround_smc_end_\num)
.endm

ENTRY(__mitigate_spectre_bhb_clear_insn_start)
    clearbhb
    isb
ENTRY(__mitigate_spectre_bhb_clear_insn_end)

mitigate_spectre_bhb_loop 8
mitigate_spectre_bhb_loop 24
mitigate_spectre_bhb_loop 32
smccc_workaround 1, #ARM_SMCCC_ARCH_WORKAROUND_1_FID
smccc_workaround 3, #ARM_SMCCC_ARCH_WORKAROUND_3_FID

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
