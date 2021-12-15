#ifndef __ASM_ARM_ARM64_FLUSHTLB_H__
#define __ASM_ARM_ARM64_FLUSHTLB_H__

/*
 * Every invalidation operation use the following patterns:
 *
 * DSB ISHST        // Ensure prior page-tables updates have completed
 * TLBI...          // Invalidate the TLB
 * DSB ISH          // Ensure the TLB invalidation has completed
 * ISB              // See explanation below
 *
 * ARM64_WORKAROUND_REPEAT_TLBI:
 * Modification of the translation table for a virtual address might lead to
 * read-after-read ordering violation.
 * The workaround repeats TLBI+DSB operation for all the TLB flush operations.
 * While this is stricly not necessary, we don't want to take any risk.
 *
 * For Xen page-tables the ISB will discard any instructions fetched
 * from the old mappings.
 *
 * For the Stage-2 page-tables the ISB ensures the completion of the DSB
 * (and therefore the TLB invalidation) before continuing. So we know
 * the TLBs cannot contain an entry for a mapping we may have removed.
 */
#define TLB_HELPER(name, tlbop)                  \
static inline void name(void)                    \
{                                                \
    asm volatile(                                \
        "dsb  ishst;"                            \
        "tlbi "  # tlbop  ";"                    \
        ALTERNATIVE(                             \
            "nop; nop;",                         \
            "dsb  ish;"                          \
            "tlbi "  # tlbop  ";",               \
            ARM64_WORKAROUND_REPEAT_TLBI,        \
            CONFIG_ARM64_WORKAROUND_REPEAT_TLBI) \
        "dsb  ish;"                              \
        "isb;"                                   \
        : : : "memory");                         \
}

/* Flush local TLBs, current VMID only. */
TLB_HELPER(flush_guest_tlb_local, vmalls12e1);

/* Flush innershareable TLBs, current VMID only */
TLB_HELPER(flush_guest_tlb, vmalls12e1is);

/* Flush local TLBs, all VMIDs, non-hypervisor mode */
TLB_HELPER(flush_all_guests_tlb_local, alle1);

/* Flush innershareable TLBs, all VMIDs, non-hypervisor mode */
TLB_HELPER(flush_all_guests_tlb, alle1is);

/* Flush all hypervisor mappings from the TLB of the local processor. */
TLB_HELPER(flush_xen_tlb_local, alle2);

/* Flush TLB of local processor for address va. */
static inline void  __flush_xen_tlb_one_local(vaddr_t va)
{
    asm volatile("tlbi vae2, %0;" : : "r" (va>>PAGE_SHIFT) : "memory");
}

/* Flush TLB of all processors in the inner-shareable domain for address va. */
static inline void __flush_xen_tlb_one(vaddr_t va)
{
    asm volatile("tlbi vae2is, %0;" : : "r" (va>>PAGE_SHIFT) : "memory");
}

#endif /* __ASM_ARM_ARM64_FLUSHTLB_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
