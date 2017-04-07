#ifndef __ARM_ARM32_MM_H__
#define __ARM_ARM32_MM_H__

/*
 * Only a limited amount of RAM, called xenheap, is always mapped on ARM32.
 * For convenience always return false.
 */
static inline bool arch_mfn_in_directmap(unsigned long mfn)
{
    return false;
}

#endif /* __ARM_ARM32_MM_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
