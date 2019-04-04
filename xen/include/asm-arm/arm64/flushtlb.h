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

/* Flush all hypervisor mappings from the TLB of the local processor. */
static inline void flush_xen_tlb_local(void)
{
    asm volatile (
        "dsb    sy;"                    /* Ensure visibility of PTE writes */
        "tlbi   alle2;"                 /* Flush hypervisor TLB */
        "dsb    sy;"                    /* Ensure completion of TLB flush */
        "isb;"
        : : : "memory");
}

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
