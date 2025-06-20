/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef X86_PDX_H
#define X86_PDX_H

#include <asm/alternative.h>

/*
 * Introduce a macro to avoid repeating the same asm goto block in each helper.
 * Note the macro is strictly tied to the code in the helpers.
 */
#define PDX_ASM_GOTO(label)                         \
    asm_inline goto (                               \
        ALTERNATIVE(                                \
            "",                                     \
            "jmp %l0",                              \
            ALT_NOT(X86_FEATURE_PDX_COMPRESSION))   \
        : : : : label )

static inline unsigned long pfn_to_pdx(unsigned long pfn)
{
    PDX_ASM_GOTO(skip);

    return pfn_to_pdx_xlate(pfn);

 skip:
    return pfn;
}

static inline unsigned long pdx_to_pfn(unsigned long pdx)
{
    PDX_ASM_GOTO(skip);

    return pdx_to_pfn_xlate(pdx);

 skip:
    return pdx;
}

static inline unsigned long maddr_to_directmapoff(paddr_t ma)
{
    PDX_ASM_GOTO(skip);

    return maddr_to_directmapoff_xlate(ma);

 skip:
    return ma;
}

static inline paddr_t directmapoff_to_maddr(unsigned long offset)
{
    PDX_ASM_GOTO(skip);

    return directmapoff_to_maddr_xlate(offset);

 skip:
    return offset;
}

#undef PDX_ASM_GOTO_SKIP

#endif /* X86_PDX_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
