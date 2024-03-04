/* Portions taken from Linux arch arm64 */
#ifndef __ASM_ARM64_NOSPEC_H
#define __ASM_ARM64_NOSPEC_H

#define csdb()  asm volatile ( "hint #20" : : : "memory" )

/*
 * Generate a mask for array_index__nospec() that is ~0UL when 0 <= idx < sz
 * and 0 otherwise.
 */
static inline unsigned long array_index_mask_nospec(unsigned long idx,
                                                    unsigned long sz)
{
    unsigned long mask;

    asm volatile ( "cmp     %1, %2\n"
                   "sbc     %0, xzr, xzr\n"
                   : "=r" (mask)
                   : "r" (idx), "Ir" (sz)
                   : "cc" );
    csdb();

    return mask;
}
#define array_index_mask_nospec array_index_mask_nospec

#endif /* __ASM_ARM64_NOSPEC_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
