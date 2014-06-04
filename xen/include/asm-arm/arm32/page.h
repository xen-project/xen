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

/* Inline ASM to flush dcache on register R (may be an inline asm operand) */
#define __clean_xen_dcache_one(R) STORE_CP32(R, DCCMVAC)

/* Inline ASM to clean and invalidate dcache on register R (may be an
 * inline asm operand) */
#define __clean_and_invalidate_xen_dcache_one(R) STORE_CP32(R, DCCIMVAC)

/*
 * Flush all hypervisor mappings from the TLB and branch predictor.
 * This is needed after changing Xen code mappings.
 *
 * The caller needs to issue the necessary DSB and D-cache flushes
 * before calling flush_xen_text_tlb.
 */
static inline void flush_xen_text_tlb(void)
{
    register unsigned long r0 asm ("r0");
    asm volatile (
        "isb;"                        /* Ensure synchronization with previous changes to text */
        STORE_CP32(0, TLBIALLH)       /* Flush hypervisor TLB */
        STORE_CP32(0, ICIALLU)        /* Flush I-cache */
        STORE_CP32(0, BPIALL)         /* Flush branch predictor */
        "dsb;"                        /* Ensure completion of TLB+BP flush */
        "isb;"
        : : "r" (r0) /*dummy*/ : "memory");
}

/*
 * Flush all hypervisor mappings from the data TLB. This is not
 * sufficient when changing code mappings or for self modifying code.
 */
static inline void flush_xen_data_tlb(void)
{
    register unsigned long r0 asm ("r0");
    asm volatile("dsb;" /* Ensure preceding are visible */
                 STORE_CP32(0, TLBIALLH)
                 "dsb;" /* Ensure completion of the TLB flush */
                 "isb;"
                 : : "r" (r0) /* dummy */: "memory");
}

/*
 * Flush a range of VA's hypervisor mappings from the data TLB. This is not
 * sufficient when changing code mappings or for self modifying code.
 */
static inline void flush_xen_data_tlb_range_va(unsigned long va, unsigned long size)
{
    unsigned long end = va + size;
    dsb(); /* Ensure preceding are visible */
    while ( va < end ) {
        asm volatile(STORE_CP32(0, TLBIMVAH)
                     : : "r" (va) : "memory");
        va += PAGE_SIZE;
    }
    dsb(); /* Ensure completion of the TLB flush */
    isb();
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
static inline uint64_t gva_to_ipa_par(vaddr_t va)
{
    uint64_t par, tmp;
    tmp = READ_CP64(PAR);
    WRITE_CP32(va, ATS1CPR);
    isb(); /* Ensure result is available. */
    par = READ_CP64(PAR);
    WRITE_CP64(tmp, PAR);
    return par;
}

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
