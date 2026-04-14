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
 * The workaround repeats TLBI+DSB ISH operation for broadcast TLB flush
 * operations. The workaround is not needed for local operations.
 *
 * It is sufficient for the additional TLBI to use *any* operation which will
 * be broadcast, regardless of which translation regime or stage of translation
 * the operation applies to. TLBI VALE2IS is used passing XZR. While there is
 * an identity mapping there, it's only used during suspend/resume, CPU on/off,
 * so the impact (performance if any) is negligible.
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
 * v6.19.
 */
#define TLB_HELPER_LOCAL(name, tlbop)            \
static inline void name(void)                    \
{                                                \
    asm_inline volatile (                        \
        "dsb  nshst;"                            \
        "tlbi "  # tlbop  ";"                    \
        "dsb  nsh;"                              \
        "isb;"                                   \
        : : : "memory");                         \
}

#define TLB_HELPER(name, tlbop)                       \
static inline void name(void)                         \
{                                                     \
    asm_inline volatile (                             \
        "dsb  ishst;"                                 \
        "tlbi "  # tlbop  ";"                         \
        ALTERNATIVE(                                  \
            "nop; nop;",                              \
            "dsb  ish;"                               \
            "tlbi vale2is, xzr;",                     \
            ARM64_WORKAROUND_REPEAT_TLBI,             \
            CONFIG_ARM64_WORKAROUND_REPEAT_TLBI)      \
        "dsb  ish;"                                   \
        "isb;"                                        \
        : : : "memory"); \
}

/* Flush local TLBs, current VMID only. */
TLB_HELPER_LOCAL(flush_guest_tlb_local, vmalls12e1)

/* Flush innershareable TLBs, current VMID only */
TLB_HELPER(flush_guest_tlb, vmalls12e1is)

/* Flush local TLBs, all VMIDs, non-hypervisor mode */
TLB_HELPER_LOCAL(flush_all_guests_tlb_local, alle1)

/* Flush innershareable TLBs, all VMIDs, non-hypervisor mode */
TLB_HELPER(flush_all_guests_tlb, alle1is)

/* Flush all hypervisor mappings from the TLB of the local processor. */
TLB_HELPER_LOCAL(flush_xen_tlb_local, alle2)

#undef TLB_HELPER_LOCAL
#undef TLB_HELPER

/*
 * FLush TLB by VA. This will likely be used in a loop, so the caller
 * is responsible to use the appropriate memory barriers before/after
 * the sequence.
 */

/* Flush TLB of local processor for address va. */
static inline void __flush_xen_tlb_one_local(vaddr_t va)
{
    asm_inline volatile (
        "tlbi vae2, %0" : : "r" (va >> PAGE_SHIFT) : "memory");
}

/* Flush TLB of all processors in the inner-shareable domain for address va. */
static inline void __flush_xen_tlb_one(vaddr_t va)
{
    asm_inline volatile (
        "tlbi vae2is, %0" : : "r" (va >> PAGE_SHIFT) : "memory");
}

/*
 * ARM64_WORKAROUND_REPEAT_TLBI:
 * For all relevant erratas it is only necessary to execute a single
 * additional TLBI;DSB sequence after any number of TLBIs are completed by DSB.
 */
static inline void __tlb_repeat_sync(void)
{
    asm_inline volatile (
        ALTERNATIVE(
            "nop; nop;",
            "tlbi vale2is, xzr;"
            "dsb  ish;",
            ARM64_WORKAROUND_REPEAT_TLBI,
            CONFIG_ARM64_WORKAROUND_REPEAT_TLBI)
        : : : "memory");
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
