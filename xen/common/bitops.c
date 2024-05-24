/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <xen/bitops.h>
#include <xen/init.h>
#include <xen/self-tests.h>

static void __init test_ffs(void)
{
    /* unsigned int ffs(unsigned int) */
    CHECK(ffs, 0, 0);
    CHECK(ffs, 1, 1);
    CHECK(ffs, 3, 1);
    CHECK(ffs, 7, 1);
    CHECK(ffs, 6, 2);
    CHECK(ffs, 0x80000000U, 32);

    /* unsigned int ffsl(unsigned long) */
    CHECK(ffsl, 0, 0);
    CHECK(ffsl, 1, 1);
    CHECK(ffsl, 3, 1);
    CHECK(ffsl, 7, 1);
    CHECK(ffsl, 6, 2);

    CHECK(ffsl, 1UL << (BITS_PER_LONG - 1), BITS_PER_LONG);
#if BITS_PER_LONG > 32
    CHECK(ffsl, 1UL << 32, 33);
    CHECK(ffsl, 1UL << 63, 64);
#endif
}

static void __init test_fls(void)
{
    /* unsigned int fls(unsigned int) */
    CHECK(fls, 0, 0);
    CHECK(fls, 1, 1);
    CHECK(fls, 3, 2);
    CHECK(fls, 7, 3);
    CHECK(fls, 6, 3);
    CHECK(fls, 0x80000000U, 32);

    /* unsigned int flsl(unsigned long) */
    CHECK(flsl, 0, 0);
    CHECK(flsl, 1, 1);
    CHECK(flsl, 3, 2);
    CHECK(flsl, 7, 3);
    CHECK(flsl, 6, 3);

    CHECK(flsl, 1 | (1UL << (BITS_PER_LONG - 1)), BITS_PER_LONG);
#if BITS_PER_LONG > 32
    CHECK(flsl, 1 | (1UL << 32), 33);
    CHECK(flsl, 1 | (1UL << 63), 64);
#endif
}

static void __init __constructor test_bitops(void)
{
    test_ffs();
    test_fls();
}
