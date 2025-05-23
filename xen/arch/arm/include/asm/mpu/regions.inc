/* SPDX-License-Identifier: GPL-2.0-only */

#include <asm/bitmap-op.inc>
#include <asm/mpu.h>
#include <asm/sysregs.h>

/* Backgroud region enable/disable */
#define SCTLR_ELx_BR    BIT(17, UL)

#define REGION_DISABLED_PRLAR   0x00    /* NS=0 ATTR=000 EN=0 */
#define REGION_NORMAL_PRLAR     0x0f    /* NS=0 ATTR=111 EN=1 */
#define REGION_DEVICE_PRLAR     0x09    /* NS=0 ATTR=100 EN=1 */

#define PRLAR_ELx_EN            0x1

#ifdef CONFIG_ARM_64
#define XEN_MPUMAP_ENTRY_SHIFT  0x4     /* 16 byte structure */

.macro store_pair reg1, reg2, dst
    stp \reg1, \reg2, [\dst]
.endm

#else
#define XEN_MPUMAP_ENTRY_SHIFT  0x3     /* 8 byte structure */

.macro store_pair reg1, reg2, dst
    .word 0xe7f000f0                    /* unimplemented */
.endm

#endif

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
 * Preserves maxcount
 * Output:
 *  sel: Next available region selector index.
 * Clobbers base, limit, prbar, prlar
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

    WRITE_SYSREG_ASM(\sel, PRSELR_EL2)
    isb
    WRITE_SYSREG_ASM(\prbar, PRBAR_EL2)
    WRITE_SYSREG_ASM(\prlar, PRLAR_EL2)
    dsb   sy
    isb

    /* Load pair into xen_mpumap */
    adr_l \base, xen_mpumap
    add   \base, \base, \sel, LSL #XEN_MPUMAP_ENTRY_SHIFT
    store_pair \prbar, \prlar, \base

    /* Set/clear xen_mpumap_mask bitmap */
    tst   \prlar, #PRLAR_ELx_EN
    bne   2f
    /* Region is disabled, clear the bit in the bitmap */
    bitmap_clear_bit xen_mpumap_mask, \sel, \base, \limit, \prbar, \prlar
    b     3f

2:
    /* Region is enabled, set the bit in the bitmap */
    bitmap_set_bit xen_mpumap_mask, \sel, \base, \limit, \prbar, \prlar

3:

    add   \sel, \sel, #1

1:
.endm

/* Failure caused due to insufficient MPU regions. */
FUNC_LOCAL(fail_insufficient_regions)
    PRINT("- Selected MPU region is above the implemented number in MPUIR_EL2 -\r\n")
1:  wfe
    b   1b
END(fail_insufficient_regions)

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
