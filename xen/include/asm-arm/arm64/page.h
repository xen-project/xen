#ifndef __ARM_ARM64_PAGE_H__
#define __ARM_ARM64_PAGE_H__

#ifndef __ASSEMBLY__

/* Write a pagetable entry */
static inline void write_pte(lpae_t *p, lpae_t pte)
{
    asm volatile (
        /* Ensure any writes have completed with the old mappings. */
        "dsb sy;"
        "str %0, [%1];"         /* Write the entry */
        "dsb sy;"
        /* Push this cacheline to the PoC so the rest of the system sees it. */
        "dc cvac, %1;"
        /* Ensure that the data flush is completed before proceeding */
        "dsb sy;"
        : : "r" (pte.bits), "r" (p) : "memory");
}

/*
 * Flush all hypervisor mappings from the TLB
 * This is needed after changing Xen code mappings.
 *
 * The caller needs to issue the necessary DSB and D-cache flushes
 * before calling flush_xen_text_tlb.
 */
static inline void flush_xen_text_tlb(void)
{
    asm volatile (
        "isb;"       /* Ensure synchronization with previous changes to text */
        "tlbi   alle2;"                 /* Flush hypervisor TLB */
        "ic     iallu;"                 /* Flush I-cache */
        "dsb    sy;"                    /* Ensure completion of TLB flush */
        "isb;"
        : : : "memory");
}

/*
 * Flush all hypervisor mappings from the data TLB. This is not
 * sufficient when changing code mappings or for self modifying code.
 */
static inline void flush_xen_data_tlb(void)
{
    asm volatile (
        "dsb    sy;"                    /* Ensure visibility of PTE writes */
        "tlbi   alle2;"                 /* Flush hypervisor TLB */
        "dsb    sy;"                    /* Ensure completion of TLB flush */
        "isb;"
        : : : "memory");
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
        asm volatile("tlbi vae2, %0;"
                     : : "r" (va>>PAGE_SHIFT) : "memory");
        va += PAGE_SIZE;
    }
    dsb(); /* Ensure completion of the TLB flush */
    isb();
}

#endif /* __ASSEMBLY__ */

#endif /* __ARM_ARM64_PAGE_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
