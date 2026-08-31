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

/*
 * void arm_smccc_1_2_smc(const struct arm_smccc_1_2_regs *args,
 *                        struct arm_smccc_1_2_regs *res)
 */
FUNC(arm_smccc_1_2_smc)
    /* Save `res` and free a GPR that won't be clobbered by SMC call */
    stp     x1, x19, [sp, #-16]!

    /* Ensure `args` won't be clobbered while loading regs in next step */
    mov	x19, x0

    /* Load the registers x0 - x17 from the struct arm_smccc_1_2_regs */
    ldp	x0, x1, [x19, #ARM_SMCCC_1_2_REGS_X0_OFFS]
    ldp	x2, x3, [x19, #ARM_SMCCC_1_2_REGS_X2_OFFS]
    ldp	x4, x5, [x19, #ARM_SMCCC_1_2_REGS_X4_OFFS]
    ldp	x6, x7, [x19, #ARM_SMCCC_1_2_REGS_X6_OFFS]
    ldp	x8, x9, [x19, #ARM_SMCCC_1_2_REGS_X8_OFFS]
    ldp	x10, x11, [x19, #ARM_SMCCC_1_2_REGS_X10_OFFS]
    ldp	x12, x13, [x19, #ARM_SMCCC_1_2_REGS_X12_OFFS]
    ldp	x14, x15, [x19, #ARM_SMCCC_1_2_REGS_X14_OFFS]
    ldp	x16, x17, [x19, #ARM_SMCCC_1_2_REGS_X16_OFFS]

    smc #0

    /* Load the `res` from the stack */
    ldr	x19, [sp]

    /* Store the registers x0 - x17 into the result structure */
    stp	x0, x1, [x19, #ARM_SMCCC_1_2_REGS_X0_OFFS]
    stp	x2, x3, [x19, #ARM_SMCCC_1_2_REGS_X2_OFFS]
    stp	x4, x5, [x19, #ARM_SMCCC_1_2_REGS_X4_OFFS]
    stp	x6, x7, [x19, #ARM_SMCCC_1_2_REGS_X6_OFFS]
    stp	x8, x9, [x19, #ARM_SMCCC_1_2_REGS_X8_OFFS]
    stp	x10, x11, [x19, #ARM_SMCCC_1_2_REGS_X10_OFFS]
    stp	x12, x13, [x19, #ARM_SMCCC_1_2_REGS_X12_OFFS]
    stp	x14, x15, [x19, #ARM_SMCCC_1_2_REGS_X14_OFFS]
    stp	x16, x17, [x19, #ARM_SMCCC_1_2_REGS_X16_OFFS]

    /* Restore original x19 */
    ldp     xzr, x19, [sp], #16
    ret
END(arm_smccc_1_2_smc)
