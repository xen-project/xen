#ifndef _ARM_ARM64_VFP_H
#define _ARM_ARM64_VFP_H

/* ARM64 VFP instruction requires fpregs address to be 128-byte aligned */
#define __vfp_aligned __attribute__((aligned(16)))

struct vfp_state
{
    /*
     * When SVE is enabled for the guest, fpregs memory will be used to
     * save/restore P0-P15 registers, otherwise it will be used for the V0-V31
     * registers.
     */
    uint64_t fpregs[64] __vfp_aligned;

#ifdef CONFIG_ARM64_SVE
    /*
     * When SVE is enabled for the guest, sve_zreg_ctx_end points to memory
     * where Z0-Z31 registers and FFR can be saved/restored, it points at the
     * end of the Z0-Z31 space and at the beginning of the FFR space, it's done
     * like that to ease the save/restore assembly operations.
     */
    uint64_t *sve_zreg_ctx_end;
#endif

    register_t fpcr;
    register_t fpexc32_el2;
    register_t fpsr;
};

#endif /* _ARM_ARM64_VFP_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
