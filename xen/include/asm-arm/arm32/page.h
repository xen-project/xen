#ifndef __ARM_ARM32_PAGE_H__
#define __ARM_ARM32_PAGE_H__

#ifndef __ASSEMBLY__

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

#endif /* __ASSEMBLY__ */

#endif /* __ARM_ARM32_PAGE_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
