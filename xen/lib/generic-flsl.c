/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/bitops.h>
#include <xen/init.h>
#include <xen/self-tests.h>

/* Mask of type UL with the upper x bits set. */
#define UPPER_MASK(x) (~0UL << (BITS_PER_LONG - (x)))

unsigned int generic_flsl(unsigned long x)
{
    unsigned int r = BITS_PER_LONG;

    if ( !x )
        return 0;

    BUILD_BUG_ON(BITS_PER_LONG > 64); /* Extend me when necessary. */

#if BITS_PER_LONG > 32
    if ( !(x & UPPER_MASK(32)) )
    {
        x <<= 32;
        r -= 32;
    }
#endif
    if ( !(x & UPPER_MASK(16)) )
    {
        x <<= 16;
        r -= 16;
    }
    if ( !(x & UPPER_MASK(8)) )
    {
        x <<= 8;
        r -= 8;
    }
    if ( !(x & UPPER_MASK(4)) )
    {
        x <<= 4;
        r -= 4;
    }
    if ( !(x & UPPER_MASK(2)) )
    {
        x <<= 2;
        r -= 2;
    }
    if ( !(x & UPPER_MASK(1)) )
    {
        x <<= 1;
        r -= 1;
    }

    return r;
}

#ifdef CONFIG_SELF_TESTS
static void __init __constructor test_generic_flsl(void)
{
    RUNTIME_CHECK(generic_flsl, 0, 0);
    RUNTIME_CHECK(generic_flsl, 1, 1);
    RUNTIME_CHECK(generic_flsl, 3, 2);
    RUNTIME_CHECK(generic_flsl, 7, 3);
    RUNTIME_CHECK(generic_flsl, 6, 3);

    RUNTIME_CHECK(generic_flsl, 1 | (1UL << (BITS_PER_LONG - 1)), BITS_PER_LONG);
#if BITS_PER_LONG > 32
    RUNTIME_CHECK(generic_flsl, 1 | (1UL << 32), 33);
    RUNTIME_CHECK(generic_flsl, 1 | (1UL << 63), 64);
#endif
}
#endif /* CONFIG_SELF_TESTS */
