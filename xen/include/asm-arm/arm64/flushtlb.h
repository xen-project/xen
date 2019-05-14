#ifndef __ASM_ARM_ARM64_FLUSHTLB_H__
#define __ASM_ARM_ARM64_FLUSHTLB_H__

/* Flush local TLBs, current VMID only */
static inline void flush_guest_tlb_local(void)
{
    asm volatile(
        "dsb sy;"
        "tlbi vmalls12e1;"
        "dsb sy;"
        "isb;"
        : : : "memory");
}

/* Flush innershareable TLBs, current VMID only */
static inline void flush_guest_tlb(void)
{
    asm volatile(
        "dsb sy;"
        "tlbi vmalls12e1is;"
        "dsb sy;"
        "isb;"
        : : : "memory");
}

/* Flush local TLBs, all VMIDs, non-hypervisor mode */
static inline void flush_all_guests_tlb_local(void)
{
    asm volatile(
        "dsb sy;"
        "tlbi alle1;"
        "dsb sy;"
        "isb;"
        : : : "memory");
}

/* Flush innershareable TLBs, all VMIDs, non-hypervisor mode */
static inline void flush_all_guests_tlb(void)
{
    asm volatile(
        "dsb sy;"
        "tlbi alle1is;"
        "dsb sy;"
        "isb;"
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
