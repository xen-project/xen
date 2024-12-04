/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Start-of-day code for an Armv8-R MPU system.
 */

#include <asm/arm64/mpu.h>
#include <asm/early_printk.h>

/* Backgroud region enable/disable */
#define SCTLR_ELx_BR    BIT(17, UL)

#define REGION_TEXT_PRBAR       0x38    /* SH=11 AP=10 XN=00 */
#define REGION_RO_PRBAR         0x3A    /* SH=11 AP=10 XN=10 */
#define REGION_DATA_PRBAR       0x32    /* SH=11 AP=00 XN=10 */
#define REGION_DEVICE_PRBAR     0x22    /* SH=10 AP=00 XN=10 */

#define REGION_NORMAL_PRLAR     0x0f    /* NS=0 ATTR=111 EN=1 */
#define REGION_DEVICE_PRLAR     0x09    /* NS=0 ATTR=100 EN=1 */

/*
 * Macro to prepare and set a EL2 MPU memory region.
 * We will also create an according MPU memory region entry, which
 * is a structure of pr_t,  in table \prmap.
 *
 * sel:         region selector
 * base:        reg storing base address
 * limit:       reg storing limit address
 * prbar:       store computed PRBAR_EL2 value
 * prlar:       store computed PRLAR_EL2 value
 * maxcount:    maximum number of EL2 regions supported
 * attr_prbar:  PRBAR_EL2-related memory attributes. If not specified it will be
 *              REGION_DATA_PRBAR
 * attr_prlar:  PRLAR_EL2-related memory attributes. If not specified it will be
 *              REGION_NORMAL_PRLAR
 *
 * Preserves \maxcount
 * Output:
 *  \sel: Next available region selector index.
 * Clobbers \base, \limit, \prbar, \prlar
 *
 * Note that all parameters using registers should be distinct.
 */
.macro prepare_xen_region, sel, base, limit, prbar, prlar, maxcount, attr_prbar=REGION_DATA_PRBAR, attr_prlar=REGION_NORMAL_PRLAR
    /* Check if the region is empty */
    cmp   \base, \limit
    beq   1f

    /* Check if the number of regions exceeded the count specified in MPUIR_EL2 */
    cmp   \sel, \maxcount
    bge   fail_insufficient_regions

    /* Prepare value for PRBAR_EL2 reg and preserve it in \prbar.*/
    and   \base, \base, #MPU_REGION_MASK
    mov   \prbar, #\attr_prbar
    orr   \prbar, \prbar, \base

    /* Limit address should be inclusive */
    sub   \limit, \limit, #1
    and   \limit, \limit, #MPU_REGION_MASK
    mov   \prlar, #\attr_prlar
    orr   \prlar, \prlar, \limit

    msr   PRSELR_EL2, \sel
    isb
    msr   PRBAR_EL2, \prbar
    msr   PRLAR_EL2, \prlar
    dsb   sy
    isb

    add   \sel, \sel, #1

1:
.endm

/*
 * Failure caused due to insufficient MPU regions.
 */
FUNC_LOCAL(fail_insufficient_regions)
    PRINT("- Selected MPU region is above the implemented number in MPUIR_EL2 -\r\n")
1:  wfe
    b   1b
END(fail_insufficient_regions)

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

    b    enable_mpu
    ret
END(enable_boot_cpu_mm)

/*
 * We don't yet support secondary CPUs bring-up. Implement a dummy helper to
 * please the common code.
 */
ENTRY(enable_secondary_cpu_mm)
    PRINT("- SMP not enabled yet -\r\n")
1:  wfe
    b 1b
ENDPROC(enable_secondary_cpu_mm)

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
