#ifndef __ASM_ARM_ARM32_FLUSHTLB_H__
#define __ASM_ARM_ARM32_FLUSHTLB_H__

/* Flush local TLBs, current VMID only */
static inline void flush_tlb_local(void)
{
    dsb(sy);

    WRITE_CP32((uint32_t) 0, TLBIALL);

    dsb(sy);
    isb();
}

/* Flush inner shareable TLBs, current VMID only */
static inline void flush_tlb(void)
{
    dsb(sy);

    WRITE_CP32((uint32_t) 0, TLBIALLIS);

    dsb(sy);
    isb();
}

/* Flush local TLBs, all VMIDs, non-hypervisor mode */
static inline void flush_tlb_all_local(void)
{
    dsb(sy);

    WRITE_CP32((uint32_t) 0, TLBIALLNSNH);

    dsb(sy);
    isb();
}

/* Flush innershareable TLBs, all VMIDs, non-hypervisor mode */
static inline void flush_tlb_all(void)
{
    dsb(sy);

    WRITE_CP32((uint32_t) 0, TLBIALLNSNHIS);

    dsb(sy);
    isb();
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
