/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Sets a bit in a bitmap declared by DECLARE_BITMAP, symbol name passed through
 * bitmap_symbol.
 *
 * bitmap_set_bit:      symbol of the bitmap declared by DECLARE_BITMAP
 * bit:                 bit number to be set in the bitmap
 * tmp1-tmp4:           temporary registers used for the computation
 *
 * Preserves: bit.
 * Clobbers:  tmp1, tmp2, tmp3, tmp4.
 */
.macro bitmap_set_bit bitmap_symbol, bit, tmp1, tmp2, tmp3, tmp4
    adr_l   \tmp1, \bitmap_symbol
    mov     \tmp2, #(BYTES_PER_LONG - 1)
    mvn     \tmp2, \tmp2                        /* mask for the alignment ~(BYTES_PER_LONG - 1) */
    lsr     \tmp3, \bit, #3                     /* retrieve byte offset (bit/8) */
    and     \tmp2, \tmp3, \tmp2                 /* word offset = (bit/8) & ~(BYTES_PER_LONG - 1) */
    add     \tmp1, \tmp1, \tmp2                 /* bitmap_symbol + word offset */
    and     \tmp2, \bit, #(BITS_PER_LONG - 1)   /* bit offset inside word */

    ldr     \tmp3, [\tmp1]
    mov     \tmp4, #1
    lsl     \tmp4, \tmp4, \tmp2                 /* (1 << offset) */
    orr     \tmp3, \tmp3, \tmp4                 /* set the bit */
    str     \tmp3, [\tmp1]
.endm

/*
 * Clears a bit in a bitmap declared by DECLARE_BITMAP, symbol name passed
 * through bitmap_symbol.
 *
 * bitmap_set_bit:      symbol of the bitmap declared by DECLARE_BITMAP
 * bit:                 bit number to be set in the bitmap
 * tmp1-tmp4:           temporary registers used for the computation
 *
 * Preserves: bit.
 * Clobbers:  tmp1, tmp2, tmp3, tmp4.
 */
.macro bitmap_clear_bit bitmap_symbol, bit, tmp1, tmp2, tmp3, tmp4
    adr_l   \tmp1, \bitmap_symbol
    mov     \tmp2, #(BYTES_PER_LONG - 1)
    mvn     \tmp2, \tmp2                        /* mask for the alignment ~(BYTES_PER_LONG - 1) */
    lsr     \tmp3, \bit, #3                     /* retrieve byte offset (bit/8) */
    and     \tmp2, \tmp3, \tmp2                 /* word offset = (bit/8) & ~(BYTES_PER_LONG - 1) */
    add     \tmp1, \tmp1, \tmp2                 /* bitmap_symbol + word offset */
    and     \tmp2, \bit, #(BITS_PER_LONG - 1)   /* bit offset inside word */

    ldr     \tmp3, [\tmp1]
    mov     \tmp4, #1
    lsl     \tmp4, \tmp4, \tmp2                 /* (1 << offset) */
    mvn     \tmp4, \tmp4                        /* ~(1 << offset) */
    and     \tmp3, \tmp3, \tmp4                 /* clear the bit */
    str     \tmp3, [\tmp1]
.endm

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
