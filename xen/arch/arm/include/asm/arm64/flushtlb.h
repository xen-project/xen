#ifndef __ASM_ARM_ARM64_FLUSHTLB_H__
#define __ASM_ARM_ARM64_FLUSHTLB_H__

/*
 * Every invalidation operation use the following patterns:
 *
 * DSB ISHST        ; Ensure prior page-tables updates have completed
 * TLBI...          ; Invalidate the TLB
 * DSB ISH          ; Ensure the TLB invalidation has completed
 * ISB              ; See explanation below
 *
 * ARM64_WORKAROUND_REPEAT_TLBI:
 * Modification of the translation table for a virtual address might lead to
 * read-after-read ordering violation.
 * The workaround repeats TLBI+DSB ISH operation for all the TLB flush
 * operations. While this is strictly not necessary, we don't want to
 * take any risk.
 *
 * For Xen page-tables the ISB will discard any instructions fetched
 * from the old mappings.
 *
 * For the Stage-2 page-tables the ISB ensures the completion of the DSB
 * (and therefore the TLB invalidation) before continuing. So we know
 * the TLBs cannot contain an entry for a mapping we may have removed.
 *
 * Note that for local TLB flush, using non-shareable (nsh) is sufficient
 * (see D5-4929 in ARM DDI 0487H.a). Although, the memory barrier in
 * for the workaround is left as inner-shareable to match with Linux
 * v6.1-rc8.
 */
#define TLB_HELPER(name, tlbop, sh)              \
static inline void name(void)                    \
{                                                \
    asm volatile(                                \
        "dsb  "  # sh  "st;"                     \
        "tlbi "  # tlbop  ";"                    \
        ALTERNATIVE(                             \
            "nop; nop;",                         \
            "dsb  ish;"                          \
            "tlbi "  # tlbop  ";",               \
            ARM64_WORKAROUND_REPEAT_TLBI,        \
            CONFIG_ARM64_WORKAROUND_REPEAT_TLBI) \
        "dsb  "  # sh  ";"                       \
        "isb;"                                   \
        : : : "memory");                         \
}

/*
 * FLush TLB by VA. This will likely be used in a loop, so the caller
 * is responsible to use the appropriate memory barriers before/after
 * the sequence.
 *
 * See above about the ARM64_WORKAROUND_REPEAT_TLBI sequence.
 */
#define TLB_HELPER_VA(name, tlbop)               \
static inline void name(vaddr_t va)              \
{                                                \
    asm volatile(                                \
        "tlbi "  # tlbop  ", %0;"                \
        ALTERNATIVE(                             \
            "nop; nop;",                         \
            "dsb  ish;"                          \
            "tlbi "  # tlbop  ", %0;",           \
            ARM64_WORKAROUND_REPEAT_TLBI,        \
            CONFIG_ARM64_WORKAROUND_REPEAT_TLBI) \
        : : "r" (va >> PAGE_SHIFT) : "memory");  \
}

/* Flush local TLBs, current VMID only. */
TLB_HELPER(flush_guest_tlb_local, vmalls12e1, nsh)

/* Flush innershareable TLBs, current VMID only */
TLB_HELPER(flush_guest_tlb, vmalls12e1is, ish)

/* Flush local TLBs, all VMIDs, non-hypervisor mode */
TLB_HELPER(flush_all_guests_tlb_local, alle1, nsh)

/* Flush innershareable TLBs, all VMIDs, non-hypervisor mode */
TLB_HELPER(flush_all_guests_tlb, alle1is, ish)

/* Flush all hypervisor mappings from the TLB of the local processor. */
TLB_HELPER(flush_xen_tlb_local, alle2, nsh)

/* Flush TLB of local processor for address va. */
TLB_HELPER_VA(__flush_xen_tlb_one_local, vae2)

/* Flush TLB of all processors in the inner-shareable domain for address va. */
TLB_HELPER_VA(__flush_xen_tlb_one, vae2is)

#undef TLB_HELPER
#undef TLB_HELPER_VA

#endif /* __ASM_ARM_ARM64_FLUSHTLB_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
