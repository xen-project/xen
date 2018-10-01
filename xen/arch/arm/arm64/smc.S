/*
 * xen/arch/arm/arm64/smc.S
 *
 * Wrapper for Secure Monitors Calls
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <asm/asm_defns.h>
#include <asm/macros.h>

/*
 * void __arm_smccc_1_0_smc(register_t a0, register_t a1, register_t a2,
 *                          register_t a3, register_t a4, register_t a5,
 *                          register_t a6, register_t a7,
 *                          struct arm_smccc_res *res)
 */
ENTRY(__arm_smccc_1_0_smc)
        smc     #0
        ldr     x4, [sp]
        cbz     x4, 1f          /* No need to store the result */
        stp     x0, x1, [x4, #SMCCC_RES_a0]
        stp     x2, x3, [x4, #SMCCC_RES_a2]
1:
        ret
