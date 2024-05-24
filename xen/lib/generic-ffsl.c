/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/bitops.h>
#include <xen/init.h>
#include <xen/self-tests.h>

unsigned int generic_ffsl(unsigned long x)
{
    unsigned int r = 1;

    if ( !x )
        return 0;

    BUILD_BUG_ON(BITS_PER_LONG > 64); /* Extend me when necessary. */

#if BITS_PER_LONG > 32
    if ( !(x & 0xffffffffU) )
    {
        x >>= 32;
        r += 32;
    }
#endif
    if ( !(x & 0xffff) )
    {
        x >>= 16;
        r += 16;
    }
    if ( !(x & 0xff) )
    {
        x >>= 8;
        r += 8;
    }
    if ( !(x & 0xf) )
    {
        x >>= 4;
        r += 4;
    }
    if ( !(x & 3) )
    {
        x >>= 2;
        r += 2;
    }
    if ( !(x & 1) )
    {
        x >>= 1;
        r += 1;
    }

    return r;
}

#ifdef CONFIG_SELF_TESTS
static void __init __constructor test_generic_ffsl(void)
{
    RUNTIME_CHECK(generic_ffsl, 0, 0);
    RUNTIME_CHECK(generic_ffsl, 1, 1);
    RUNTIME_CHECK(generic_ffsl, 3, 1);
    RUNTIME_CHECK(generic_ffsl, 7, 1);
    RUNTIME_CHECK(generic_ffsl, 6, 2);

    RUNTIME_CHECK(generic_ffsl, 1UL << (BITS_PER_LONG - 1), BITS_PER_LONG);
#if BITS_PER_LONG > 32
    RUNTIME_CHECK(generic_ffsl, 1UL << 32, 33);
    RUNTIME_CHECK(generic_ffsl, 1UL << 63, 64);
#endif
}
#endif /* CONFIG_SELF_TESTS */
