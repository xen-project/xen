#ifndef __ARM_ARM64_PAGE_H__
#define __ARM_ARM64_PAGE_H__

#ifndef __ASSEMBLY__

#include <asm/alternative.h>

/* Write a pagetable entry */
static inline void write_pte(lpae_t *p, lpae_t pte)
{
    asm volatile (
        /* Ensure any writes have completed with the old mappings. */
        "dsb sy;"
        "str %0, [%1];"         /* Write the entry */
        "dsb sy;"
        : : "r" (pte.bits), "r" (p) : "memory");
}

/* Inline ASM to invalidate dcache on register R (may be an inline asm operand) */
#define __invalidate_dcache_one(R) "dc ivac, %" #R ";"

/* Inline ASM to flush dcache on register R (may be an inline asm operand) */
#define __clean_dcache_one(R)                   \
    ALTERNATIVE("dc cvac, %" #R ";",            \
                "dc civac, %" #R ";",           \
                ARM64_WORKAROUND_CLEAN_CACHE)   \

/* Inline ASM to clean and invalidate dcache on register R (may be an
 * inline asm operand) */
#define __clean_and_invalidate_dcache_one(R) "dc  civac, %" #R ";"

/* Invalidate all instruction caches in Inner Shareable domain to PoU */
static inline void invalidate_icache(void)
{
    asm volatile ("ic ialluis");
    dsb(ish);               /* Ensure completion of the flush I-cache */
    isb();
}

/* Invalidate all instruction caches on the local processor to PoU */
static inline void invalidate_icache_local(void)
{
    asm volatile ("ic iallu");
    dsb(nsh);               /* Ensure completion of the I-cache flush */
    isb();
}

/* Ask the MMU to translate a VA for us */
static inline uint64_t __va_to_par(vaddr_t va)
{
    uint64_t par, tmp = READ_SYSREG64(PAR_EL1);

    asm volatile ("at s1e2r, %0;" : : "r" (va));
    isb();
    par = READ_SYSREG64(PAR_EL1);
    WRITE_SYSREG64(tmp, PAR_EL1);
    return par;
}

/* Ask the MMU to translate a Guest VA for us */
static inline uint64_t gva_to_ma_par(vaddr_t va, unsigned int flags)
{
    uint64_t par, tmp = READ_SYSREG64(PAR_EL1);

    if ( (flags & GV2M_WRITE) == GV2M_WRITE )
        asm volatile ("at s12e1w, %0;" : : "r" (va));
    else
        asm volatile ("at s12e1r, %0;" : : "r" (va));
    isb();
    par = READ_SYSREG64(PAR_EL1);
    WRITE_SYSREG64(tmp, PAR_EL1);
    return par;
}

static inline uint64_t gva_to_ipa_par(vaddr_t va, unsigned int flags)
{
    uint64_t par, tmp = READ_SYSREG64(PAR_EL1);

    if ( (flags & GV2M_WRITE) == GV2M_WRITE )
        asm volatile ("at s1e1w, %0;" : : "r" (va));
    else
        asm volatile ("at s1e1r, %0;" : : "r" (va));
    isb();
    par = READ_SYSREG64(PAR_EL1);
    WRITE_SYSREG64(tmp, PAR_EL1);
    return par;
}

extern void clear_page(void *to);

#endif /* __ASSEMBLY__ */

#endif /* __ARM_ARM64_PAGE_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
