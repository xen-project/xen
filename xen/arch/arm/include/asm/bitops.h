/*
 * Copyright 1995, Russell King.
 * Various bits and pieces copyrights include:
 *  Linus Torvalds (test_bit).
 * Big endian support: Copyright 2001, Nicolas Pitre
 *  reworked by rmk.
 */

#ifndef _ARM_BITOPS_H
#define _ARM_BITOPS_H

#include <xen/macros.h>

#include <asm/asm_defns.h>

/*
 * Non-atomic bit manipulation.
 *
 * Implemented using atomics to be interrupt safe. Could alternatively
 * implement with local interrupt masking.
 */
#define __set_bit(n,p)            set_bit(n,p)
#define __clear_bit(n,p)          clear_bit(n,p)

#define BITS_PER_BYTE           8

#define ADDR (*(volatile int *) addr)
#define CONST_ADDR (*(const volatile int *) addr)

#if defined(CONFIG_ARM_32)
# include <asm/arm32/bitops.h>
#elif defined(CONFIG_ARM_64)
# include <asm/arm64/bitops.h>
#else
# error "unknown ARM variant"
#endif

/*
 * Atomic bitops
 *
 * The helpers below *should* only be used on memory shared between
 * trusted threads or we know the memory cannot be accessed by another
 * thread.
 */

void set_bit(int nr, volatile void *p);
void clear_bit(int nr, volatile void *p);
void change_bit(int nr, volatile void *p);
int test_and_set_bit(int nr, volatile void *p);
int test_and_clear_bit(int nr, volatile void *p);
int test_and_change_bit(int nr, volatile void *p);

void clear_mask16(uint16_t mask, volatile void *p);

/*
 * The helpers below may fail to update the memory if the action takes
 * too long.
 *
 * @max_try: Maximum number of iterations
 *
 * The helpers will return true when the update has succeeded (i.e no
 * timeout) and false if the update has failed.
 */
bool set_bit_timeout(int nr, volatile void *p, unsigned int max_try);
bool clear_bit_timeout(int nr, volatile void *p, unsigned int max_try);
bool change_bit_timeout(int nr, volatile void *p, unsigned int max_try);
bool test_and_set_bit_timeout(int nr, volatile void *p,
                              int *oldbit, unsigned int max_try);
bool test_and_clear_bit_timeout(int nr, volatile void *p,
                                int *oldbit, unsigned int max_try);
bool test_and_change_bit_timeout(int nr, volatile void *p,
                                 int *oldbit, unsigned int max_try);
bool clear_mask16_timeout(uint16_t mask, volatile void *p,
                          unsigned int max_try);

#define arch_ffs(x)  ((x) ? 1 + __builtin_ctz(x) : 0)
#define arch_ffsl(x) ((x) ? 1 + __builtin_ctzl(x) : 0)
#define arch_fls(x)  ((x) ? 32 - __builtin_clz(x) : 0)
#define arch_flsl(x) ((x) ? BITS_PER_LONG - __builtin_clzl(x) : 0)

#endif /* _ARM_BITOPS_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
