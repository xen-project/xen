#ifndef _ARM_ARM64_VFP_H
#define _ARM_ARM64_VFP_H

struct vfp_state
{
    uint64_t fpregs[64];
    uint32_t fpcr;
    uint32_t fpexc32_el2;
    uint32_t fpsr;
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
