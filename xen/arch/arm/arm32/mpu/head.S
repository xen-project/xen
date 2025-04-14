/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Start-of-day code for an Armv8-R-AArch32 MPU system.
 */

#include <asm/arm32/macros.h>
#include <asm/arm32/sysregs.h>
#include <asm/cpregs.h>
#include <asm/mpu.h>
#include <asm/mpu/regions.inc>
#include <asm/page.h>

/*
 * Set up the memory attribute type tables and enable EL2 MPU and data cache.
 * If the Background region is enabled, then the MPU uses the default memory
 * map as the Background region for generating the memory
 * attributes when MPU is disabled.
 * Since the default memory map of the Armv8-R AArch32 architecture is
 * IMPLEMENTATION DEFINED, we intend to turn off the Background region here.
 *
 * Clobbers r0
 */
FUNC_LOCAL(enable_mpu)
    /* Set up memory attribute type tables */
    mov_w r0, MAIR0VAL
    mcr   CP32(r0, HMAIR0)
    mov_w r0, MAIR1VAL
    mcr   CP32(r0, HMAIR1)

    mrc   CP32(r0, HSCTLR)
    bic   r0, r0, #SCTLR_ELx_BR       /* Disable Background region */
    orr   r0, r0, #SCTLR_Axx_ELx_M    /* Enable MPU */
    orr   r0, r0, #SCTLR_Axx_ELx_C    /* Enable D-cache */
    mcr   CP32(r0, HSCTLR)
    isb

    ret
END(enable_mpu)

/*
 * Maps the various sections of Xen (described in xen.lds.S) as different MPU
 * regions.
 *
 * Clobbers r0 - r5
 *
 */
FUNC(enable_boot_cpu_mm)
    /* Get the number of regions specified in MPUIR_EL2 */
    mrc   CP32(r5, MPUIR_EL2)
    and   r5, r5, #NUM_MPU_REGIONS_MASK

    /* x0: region sel */
    mov   r0, #0
    /* Xen text section. */
    mov_w   r1, _stext
    mov_w   r2, _etext
    prepare_xen_region r0, r1, r2, r3, r4, r5, attr_prbar=REGION_TEXT_PRBAR

    /* Xen read-only data section. */
    mov_w   r1, _srodata
    mov_w   r2, _erodata
    prepare_xen_region r0, r1, r2, r3, r4, r5, attr_prbar=REGION_RO_PRBAR

    /* Xen read-only after init and data section. (RW data) */
    mov_w   r1, __ro_after_init_start
    mov_w   r2, __init_begin
    prepare_xen_region r0, r1, r2, r3, r4, r5

    /* Xen code section. */
    mov_w   r1, __init_begin
    mov_w   r2, __init_data_begin
    prepare_xen_region r0, r1, r2, r3, r4, r5, attr_prbar=REGION_TEXT_PRBAR

    /* Xen data and BSS section. */
    mov_w   r1, __init_data_begin
    mov_w   r2, __bss_end
    prepare_xen_region r0, r1, r2, r3, r4, r5

#ifdef CONFIG_EARLY_PRINTK
    /* Xen early UART section. */
    mov_w   r1, CONFIG_EARLY_UART_BASE_ADDRESS
    mov_w   r2, (CONFIG_EARLY_UART_BASE_ADDRESS + CONFIG_EARLY_UART_SIZE)
    prepare_xen_region r0, r1, r2, r3, r4, r5, attr_prbar=REGION_DEVICE_PRBAR, attr_prlar=REGION_DEVICE_PRLAR
#endif

    b    enable_mpu
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
