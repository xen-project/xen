/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Start-of-day code for an Armv8-R MPU system.
 */

#include <asm/mpu/regions.inc>

/*
 * Enable EL2 MPU and data cache
 * If the Background region is enabled, then the MPU uses the default memory
 * map as the Background region for generating the memory
 * attributes when MPU is disabled.
 * Since the default memory map of the Armv8-R AArch64 architecture is
 * IMPLEMENTATION DEFINED, we intend to turn off the Background region here.
 *
 * Clobbers x0
 *
 */
FUNC_LOCAL(enable_mpu)
    mrs   x0, SCTLR_EL2
    bic   x0, x0, #SCTLR_ELx_BR       /* Disable Background region */
    orr   x0, x0, #SCTLR_Axx_ELx_M    /* Enable MPU */
    orr   x0, x0, #SCTLR_Axx_ELx_C    /* Enable D-cache */
    orr   x0, x0, #SCTLR_Axx_ELx_WXN  /* Enable WXN */
    msr   SCTLR_EL2, x0
    isb

    ret
END(enable_mpu)

/*
 * Maps the various sections of Xen (described in xen.lds.S) as different MPU
 * regions.
 *
 * Clobbers x0 - x5
 *
 */
FUNC(enable_boot_cpu_mm)
    /* Get the number of regions specified in MPUIR_EL2 */
    mrs   x5, MPUIR_EL2
    and   x5, x5, #NUM_MPU_REGIONS_MASK

    ldr   x0, =max_mpu_regions
    strb  w5, [x0]
    dc ivac, x0                 /* Invalidate cache for max_mpu_regions addr */

    /* x0: region sel */
    mov   x0, xzr
    /* Xen text section. */
    ldr   x1, =_stext
    ldr   x2, =_etext
    prepare_xen_region x0, x1, x2, x3, x4, x5, attr_prbar=REGION_TEXT_PRBAR

    /* Xen read-only data section. */
    ldr   x1, =_srodata
    ldr   x2, =_erodata
    prepare_xen_region x0, x1, x2, x3, x4, x5, attr_prbar=REGION_RO_PRBAR

    /* Xen read-only after init and data section. (RW data) */
    ldr   x1, =__ro_after_init_start
    ldr   x2, =__init_begin
    prepare_xen_region x0, x1, x2, x3, x4, x5

    /* Xen code section. */
    ldr   x1, =__init_begin
    ldr   x2, =__init_data_begin
    prepare_xen_region x0, x1, x2, x3, x4, x5, attr_prbar=REGION_TEXT_PRBAR

    /* Xen data and BSS section. */
    ldr   x1, =__init_data_begin
    ldr   x2, =__bss_end
    prepare_xen_region x0, x1, x2, x3, x4, x5

#ifdef CONFIG_EARLY_PRINTK
    /* Xen early UART section. */
    ldr   x1, =CONFIG_EARLY_UART_BASE_ADDRESS
    ldr   x2, =(CONFIG_EARLY_UART_BASE_ADDRESS + CONFIG_EARLY_UART_SIZE)
    prepare_xen_region x0, x1, x2, x3, x4, x5, attr_prbar=REGION_DEVICE_PRBAR, attr_prlar=REGION_DEVICE_PRLAR
#endif

zero_mpu:
    /* Reset remaining MPU regions */
    cmp   x0, x5
    beq   out_zero_mpu
    mov   x1, #0
    mov   x2, #1
    prepare_xen_region x0, x1, x2, x3, x4, x5, attr_prlar=REGION_DISABLED_PRLAR
    b     zero_mpu

out_zero_mpu:
    /* Invalidate data cache for MPU data structures */
    mov x4, lr
    ldr x0, =xen_mpumap_mask
    mov x1, #XEN_MPUMAP_MASK_sizeof
    bl __invalidate_dcache_area

    ldr x0, =xen_mpumap
    mov x1, #XEN_MPUMAP_sizeof
    bl __invalidate_dcache_area
    mov lr, x4

    b    enable_mpu
    ret
END(enable_boot_cpu_mm)

/*
 * We don't yet support secondary CPUs bring-up. Implement a dummy helper to
 * please the common code.
 */
FUNC(enable_secondary_cpu_mm)
    PRINT("- SMP not enabled yet -\r\n")
1:  wfe
    b 1b
END(enable_secondary_cpu_mm)

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
