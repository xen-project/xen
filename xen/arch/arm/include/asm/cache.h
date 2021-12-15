#ifndef __ARCH_ARM_CACHE_H
#define __ARCH_ARM_CACHE_H


/* L1 cache line size */
#define L1_CACHE_SHIFT  (CONFIG_ARM_L1_CACHE_SHIFT)
#define L1_CACHE_BYTES  (1 << L1_CACHE_SHIFT)

#define __read_mostly __section(".data.read_mostly")

#endif
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
