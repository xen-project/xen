/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Unit tests for domain ID allocator.
 *
 * Copyright 2025 Ford Motor Company
 */

#include <sysexits.h>

#include "harness.h"

#define verify(exp, fmt, args...) \
while (!(exp)) { \
    printf(fmt, ## args); \
    exit(EX_SOFTWARE); \
}

/*
 * Fail on the first error, since tests are dependent on each other.
 */
int main(int argc, char **argv)
{
    domid_t expected, allocated;

    /* Test ID cannot be allocated twice. */
    for ( expected = 0; expected < DOMID_FIRST_RESERVED; expected++ )
    {
        allocated = domid_alloc(expected);
        verify(allocated == expected,
               "TEST 1: expected %u allocated %u\n", expected, allocated);
    }
    for ( expected = 0; expected < DOMID_FIRST_RESERVED; expected++ )
    {
        allocated = domid_alloc(expected);
        verify(allocated == DOMID_INVALID,
               "TEST 2: expected %u allocated %u\n", DOMID_INVALID, allocated);
    }

    /* Ensure all IDs, including ID#0 are not allocated. */
    for ( expected = 0; expected < DOMID_FIRST_RESERVED; expected++ )
        domid_free(expected);

    /*
     * Test that that two consecutive calls of domid_alloc(DOMID_INVALID)
     * will never return the same ID.
     * NB: ID#0 is reserved and shall not be allocated by
     * domid_alloc(DOMID_INVALID).
     */
    for ( expected = 1; expected < DOMID_FIRST_RESERVED; expected++ )
    {
        allocated = domid_alloc(DOMID_INVALID);
        verify(allocated == expected,
               "TEST 3: expected %u allocated %u\n", expected, allocated);
    }
    for ( expected = 1; expected < DOMID_FIRST_RESERVED; expected++ )
    {
        allocated = domid_alloc(DOMID_INVALID);
        verify(allocated == DOMID_INVALID,
               "TEST 4: expected %u allocated %u\n", DOMID_INVALID, allocated);
    }

    /* Re-allocate first ID from [1..DOMID_FIRST_RESERVED/2]. */
    for ( expected = 1; expected < DOMID_FIRST_RESERVED / 2; expected++ )
        domid_free(expected);
    for ( expected = 1; expected < DOMID_FIRST_RESERVED / 2; expected++ )
    {
        allocated = domid_alloc(DOMID_INVALID);
        verify(allocated == expected,
               "TEST 5: expected %u allocated %u\n", expected, allocated);
    }

    /* Re-allocate last ID from [1..DOMID_FIRST_RESERVED - 1]. */
    expected = DOMID_FIRST_RESERVED - 1;
    domid_free(DOMID_FIRST_RESERVED - 1);
    allocated = domid_alloc(DOMID_INVALID);
    verify(allocated == expected,
           "TEST 6: expected %u allocated %u\n", expected, allocated);

    /* Allocate an invalid ID. */
    expected = DOMID_INVALID;
    allocated = domid_alloc(DOMID_FIRST_RESERVED);
    verify(allocated == expected,
           "TEST 7: expected %u allocated %u\n", expected, allocated);

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
