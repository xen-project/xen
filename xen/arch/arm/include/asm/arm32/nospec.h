/* Portions taken from Linux arch arm */
#ifndef __ASM_ARM32_NOSPEC_H
#define __ASM_ARM32_NOSPEC_H

#define CSDB    ".inst  0xe320f014"

static inline unsigned long array_index_mask_nospec(unsigned long idx,
                                                    unsigned long sz)
{
    unsigned long mask;

    asm volatile( "cmp    %1, %2\n"
                  "sbc    %0, %1, %1\n"
                  CSDB
                  : "=r" (mask)
                  : "r" (idx), "Ir" (sz)
                  : "cc" );

    return mask;
}
#define array_index_mask_nospec array_index_mask_nospec

#endif /* __ASM_ARM32_NOSPEC_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
