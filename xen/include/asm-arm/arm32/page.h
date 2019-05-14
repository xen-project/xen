#ifndef __ARM_ARM32_PAGE_H__
#define __ARM_ARM32_PAGE_H__

#ifndef __ASSEMBLY__

/* Write a pagetable entry.
 *
 * If the table entry is changing a text mapping, it is responsibility
 * of the caller to issue an ISB after write_pte.
 */
static inline void write_pte(lpae_t *p, lpae_t pte)
{
    asm volatile (
        /* Ensure any writes have completed with the old mappings. */
        "dsb;"
        /* Safely write the entry (STRD is atomic on CPUs that support LPAE) */
        "strd %0, %H0, [%1];"
        "dsb;"
        : : "r" (pte.bits), "r" (p) : "memory");
}

/* Inline ASM to invalidate dcache on register R (may be an inline asm operand) */
#define __invalidate_dcache_one(R) STORE_CP32(R, DCIMVAC)

/* Inline ASM to flush dcache on register R (may be an inline asm operand) */
#define __clean_dcache_one(R) STORE_CP32(R, DCCMVAC)

/* Inline ASM to clean and invalidate dcache on register R (may be an
 * inline asm operand) */
#define __clean_and_invalidate_dcache_one(R) STORE_CP32(R, DCCIMVAC)

/*
 * Invalidate all instruction caches in Inner Shareable domain to PoU.
 * We also need to flush the branch predictor for ARMv7 as it may be
 * architecturally visible to the software (see B2.2.4 in ARM DDI 0406C.b).
 */
static inline void invalidate_icache(void)
{
    asm volatile (
        CMD_CP32(ICIALLUIS)     /* Flush I-cache. */
        CMD_CP32(BPIALLIS)      /* Flush branch predictor. */
        : : : "memory");

    dsb(ish);                   /* Ensure completion of the flush I-cache */
    isb();                      /* Synchronize fetched instruction stream. */
}

/*
 * Invalidate all instruction caches on the local processor to PoU.
 * We also need to flush the branch predictor for ARMv7 as it may be
 * architecturally visible to the software (see B2.2.4 in ARM DDI 0406C.b).
 */
static inline void invalidate_icache_local(void)
{
    asm volatile (
        CMD_CP32(ICIALLU)       /* Flush I-cache. */
        CMD_CP32(BPIALL)        /* Flush branch predictor. */
        : : : "memory");

    dsb(nsh);                   /* Ensure completion of the flush I-cache */
    isb();                      /* Synchronize fetched instruction stream. */
}

/*
 * Flush all hypervisor mappings from the data TLB of the local
 * processor. This is not sufficient when changing code mappings or
 * for self modifying code.
 */
static inline void flush_xen_data_tlb_local(void)
{
    asm volatile("dsb;" /* Ensure preceding are visible */
                 CMD_CP32(TLBIALLH)
                 "dsb;" /* Ensure completion of the TLB flush */
                 "isb;"
                 : : : "memory");
}

/* Flush TLB of local processor for address va. */
static inline void __flush_xen_data_tlb_one_local(vaddr_t va)
{
    asm volatile(STORE_CP32(0, TLBIMVAH) : : "r" (va) : "memory");
}

/* Flush TLB of all processors in the inner-shareable domain for
 * address va. */
static inline void __flush_xen_data_tlb_one(vaddr_t va)
{
    asm volatile(STORE_CP32(0, TLBIMVAHIS) : : "r" (va) : "memory");
}

/* Ask the MMU to translate a VA for us */
static inline uint64_t __va_to_par(vaddr_t va)
{
    uint64_t par, tmp;
    tmp = READ_CP64(PAR);
    WRITE_CP32(va, ATS1HR);
    isb(); /* Ensure result is available. */
    par = READ_CP64(PAR);
    WRITE_CP64(tmp, PAR);
    return par;
}

/* Ask the MMU to translate a Guest VA for us */
static inline uint64_t gva_to_ma_par(vaddr_t va, unsigned int flags)
{
    uint64_t par, tmp;
    tmp = READ_CP64(PAR);
    if ( (flags & GV2M_WRITE) == GV2M_WRITE )
        WRITE_CP32(va, ATS12NSOPW);
    else
        WRITE_CP32(va, ATS12NSOPR);
    isb(); /* Ensure result is available. */
    par = READ_CP64(PAR);
    WRITE_CP64(tmp, PAR);
    return par;
}
static inline uint64_t gva_to_ipa_par(vaddr_t va, unsigned int flags)
{
    uint64_t par, tmp;
    tmp = READ_CP64(PAR);
    if ( (flags & GV2M_WRITE) == GV2M_WRITE )
        WRITE_CP32(va, ATS1CPW);
    else
        WRITE_CP32(va, ATS1CPR);
    isb(); /* Ensure result is available. */
    par = READ_CP64(PAR);
    WRITE_CP64(tmp, PAR);
    return par;
}

#define clear_page(page) memset((void *)(page), 0, PAGE_SIZE)

#endif /* __ASSEMBLY__ */

#endif /* __ARM_ARM32_PAGE_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
