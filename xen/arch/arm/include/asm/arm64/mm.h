#ifndef __ARM_ARM64_MM_H__
#define __ARM_ARM64_MM_H__

/*
 * On ARM64, all the RAM is currently direct mapped in Xen.
 * Hence return always true.
 */
static inline bool arch_mfn_in_directmap(unsigned long mfn)
{
    return true;
}

#endif /* __ARM_ARM64_MM_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
