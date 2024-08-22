/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/bitops.h>
#include <xen/init.h>
#include <xen/self-tests.h>

/* Value @b broadcast to every byte in a long */
#if BITS_PER_LONG == 32
# define BCST(b) ((b) * 0x01010101UL)
#elif BITS_PER_LONG == 64
# define BCST(b) ((b) * 0x0101010101010101UL)
#else
# error Extend me please
#endif

unsigned int generic_hweightl(unsigned long x)
{
    x -= (x >> 1) & BCST(0x55);
    x =  (x & BCST(0x33)) + ((x >> 2) & BCST(0x33));
    x =  (x + (x >> 4)) & BCST(0x0f);

    if ( IS_ENABLED(CONFIG_HAS_FAST_MULTIPLY) )
        return (x * BCST(0x01)) >> (BITS_PER_LONG - 8);

    x += x >> 8;
    x += x >> 16;
#if BITS_PER_LONG > 32
    x += x >> 32;
#endif

    return x & 0xff;
}

#ifdef CONFIG_SELF_TESTS
static void __init __constructor test_generic_hweightl(void)
{
    RUNTIME_CHECK(generic_hweightl, 0, 0);
    RUNTIME_CHECK(generic_hweightl, 1, 1);
    RUNTIME_CHECK(generic_hweightl, 3, 2);
    RUNTIME_CHECK(generic_hweightl, 7, 3);
    RUNTIME_CHECK(generic_hweightl, 0xff, 8);

    RUNTIME_CHECK(generic_hweightl, BCST(0x55), BITS_PER_LONG / 2);
    RUNTIME_CHECK(generic_hweightl, BCST(0xaa), BITS_PER_LONG / 2);

    RUNTIME_CHECK(generic_hweightl, 1 | (1UL << (BITS_PER_LONG - 1)), 2);
    RUNTIME_CHECK(generic_hweightl, -1UL, BITS_PER_LONG);
}
#endif /* CONFIG_SELF_TESTS */
