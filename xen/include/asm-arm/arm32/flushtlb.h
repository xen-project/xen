#ifndef __ASM_ARM_ARM32_FLUSHTLB_H__
#define __ASM_ARM_ARM32_FLUSHTLB_H__

/* Flush local TLBs, current VMID only */
static inline void flush_guest_tlb_local(void)
{
    dsb(sy);

    WRITE_CP32((uint32_t) 0, TLBIALL);

    dsb(sy);
    isb();
}

/* Flush inner shareable TLBs, current VMID only */
static inline void flush_guest_tlb(void)
{
    dsb(sy);

    WRITE_CP32((uint32_t) 0, TLBIALLIS);

    dsb(sy);
    isb();
}

/* Flush local TLBs, all VMIDs, non-hypervisor mode */
static inline void flush_all_guests_tlb_local(void)
{
    dsb(sy);

    WRITE_CP32((uint32_t) 0, TLBIALLNSNH);

    dsb(sy);
    isb();
}

/* Flush innershareable TLBs, all VMIDs, non-hypervisor mode */
static inline void flush_all_guests_tlb(void)
{
    dsb(sy);

    WRITE_CP32((uint32_t) 0, TLBIALLNSNHIS);

    dsb(sy);
    isb();
}

/* Flush all hypervisor mappings from the TLB of the local processor. */
static inline void flush_xen_tlb_local(void)
{
    asm volatile("dsb;" /* Ensure preceding are visible */
                 CMD_CP32(TLBIALLH)
                 "dsb;" /* Ensure completion of the TLB flush */
                 "isb;"
                 : : : "memory");
}

/* Flush TLB of local processor for address va. */
static inline void __flush_xen_tlb_one_local(vaddr_t va)
{
    asm volatile(STORE_CP32(0, TLBIMVAH) : : "r" (va) : "memory");
}

/* Flush TLB of all processors in the inner-shareable domain for address va. */
static inline void __flush_xen_tlb_one(vaddr_t va)
{
    asm volatile(STORE_CP32(0, TLBIMVAHIS) : : "r" (va) : "memory");
}

#endif /* __ASM_ARM_ARM32_FLUSHTLB_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
