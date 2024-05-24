#ifndef _ARM_ARM64_BITOPS_H
#define _ARM_ARM64_BITOPS_H

/* Based on linux/include/asm-generic/bitops/find.h */

#ifndef CONFIG_GENERIC_FIND_FIRST_BIT

#define find_first_bit(addr, size) find_next_bit((addr), (size), 0)
#define find_first_zero_bit(addr, size) find_next_zero_bit((addr), (size), 0)

#endif /* CONFIG_GENERIC_FIND_FIRST_BIT */

#endif /* _ARM_ARM64_BITOPS_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
