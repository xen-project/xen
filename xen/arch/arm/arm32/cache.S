/* SPDX-License-Identifier: GPL-2.0-only */
/* Cache maintenance */

#include <asm/arm32/sysregs.h>

/* dcache_line_size - get the minimum D-cache line size from the CTR register */
    .macro  dcache_line_size, reg, tmp
    mrc CP32(\tmp, CTR)             /* read ctr */
    lsr \tmp, \tmp, #16
    and \tmp, \tmp, #0xf            /* cache line size encoding */
    mov \reg, #4                    /* bytes per word */
    mov \reg, \reg, lsl \tmp        /* actual cache line size */
    .endm

/*
 * __invalidate_dcache_area(addr, size)
 *
 * Ensure that the data held in the cache for the buffer is invalidated.
 *
 * - addr - start address of the buffer
 * - size - size of the buffer
 *
 * Clobbers r0 - r3
 */
FUNC(__invalidate_dcache_area)
    dcache_line_size r2, r3
    add   r1, r0, r1
    sub   r3, r2, #1
    bic   r0, r0, r3
1:  mcr   CP32(r0, DCIMVAC)     /* invalidate D line / unified line */
    add   r0, r0, r2
    cmp   r0, r1
    blo   1b
    dsb   sy
    ret
END(__invalidate_dcache_area)

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
