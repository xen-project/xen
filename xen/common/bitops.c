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

    /*
     * unsigned int ffs64(uint64_t)
     *
     * 32-bit builds of Xen have to split this into two adjacent operations,
     * so test all interesting bit positions across the divide.
     */
    CHECK(ffs64, 0, 0);
    CHECK(ffs64, 1, 1);
    CHECK(ffs64, 3, 1);
    CHECK(ffs64, 7, 1);
    CHECK(ffs64, 6, 2);

    CHECK(ffs64, 0x8000000080000000ULL, 32);
    CHECK(ffs64, 0x8000000100000000ULL, 33);
    CHECK(ffs64, 0x8000000000000000ULL, 64);
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

    /*
     * unsigned int fls64(uint64_t)
     *
     * 32-bit builds of Xen have to split this into two adjacent operations,
     * so test all interesting bit positions across the divide.
     */
    CHECK(fls64, 0, 0);
    CHECK(fls64, 1, 1);
    CHECK(fls64, 3, 2);
    CHECK(fls64, 7, 3);
    CHECK(fls64, 6, 3);

    CHECK(fls64, 0x0000000080000001ULL, 32);
    CHECK(fls64, 0x0000000100000001ULL, 33);
    CHECK(fls64, 0x8000000000000001ULL, 64);
}

static void __init test_for_each_set_bit(void)
{
    unsigned int  ui,  ui_res = 0, tmp;
    unsigned long ul,  ul_res = 0;
    uint64_t      ull, ull_res = 0;

    ui = HIDE(0x80008001U);
    for_each_set_bit ( i, ui )
        ui_res |= 1U << i;

    if ( ui != ui_res )
        panic("for_each_set_bit(uint) expected %#x, got %#x\n", ui, ui_res);

    ul = HIDE(1UL << (BITS_PER_LONG - 1) | 1);
    for_each_set_bit ( i, ul )
        ul_res |= 1UL << i;

    if ( ul != ul_res )
        panic("for_each_set_bit(ulong) expected %#lx, got %#lx\n", ul, ul_res);

    ull = HIDE(0x8000000180000001ULL);
    for_each_set_bit ( i, ull )
        ull_res |= 1ULL << i;

    if ( ull != ull_res )
        panic("for_each_set_bit(uint64) expected %#"PRIx64", got %#"PRIx64"\n", ull, ull_res);

    /* Check that we can break from the middle of the loop. */
    ui = HIDE(0x80001008U);
    tmp = 0;
    ui_res = 0;
    for_each_set_bit ( i, ui )
    {
        if ( tmp++ > 1 )
            break;

        ui_res |= 1U << i;
    }

    if ( ui_res != 0x1008 )
        panic("for_each_set_bit(break) expected 0x1008, got %#x\n", ui_res);
}

static void __init test_multiple_bits_set(void)
{
    /*
     * multiple_bits_set() is generic on the type of it's parameter, as the
     * internal expression is so simple.
     */

    CHECK(multiple_bits_set, 0, false);
    CHECK(multiple_bits_set, 1, false);
    CHECK(multiple_bits_set, 2, false);
    CHECK(multiple_bits_set, 3, true);

    CHECK(multiple_bits_set, 1 | (1UL << (BITS_PER_LONG - 1)), true);
#if BITS_PER_LONG > 32
    CHECK(multiple_bits_set, 1 | (1UL << 32), true);
#endif

    CHECK(multiple_bits_set, 0x8000000000000001ULL, true);
    CHECK(multiple_bits_set, 0xc000000000000000ULL, true);
}

static void __init test_hweight(void)
{
    /* unsigned int hweightl(unsigned long) */
    CHECK(hweightl, 0, 0);
    CHECK(hweightl, 1, 1);
    CHECK(hweightl, 3, 2);
    CHECK(hweightl, 7, 3);
    CHECK(hweightl, 0xff, 8);

    CHECK(hweightl, 1 | (1UL << (BITS_PER_LONG - 1)), 2);
    CHECK(hweightl, -1UL, BITS_PER_LONG);

    /* unsigned int hweight64(uint64_t) */
    CHECK(hweight64, -1ULL, 64);
}

static void __init __constructor test_bitops(void)
{
    test_ffs();
    test_fls();
    test_for_each_set_bit();

    test_multiple_bits_set();
    test_hweight();
}
