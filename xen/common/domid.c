/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Domain ID allocator.
 *
 * Covers dom0 or late hwdom, predefined domains, post-boot domains.
 * Excludes system domains (ID >= DOMID_FIRST_RESERVED).
 *
 * Copyright 2025 Ford Motor Company
 */

#include <xen/domain.h>

static DEFINE_SPINLOCK(domid_lock);
static DECLARE_BITMAP(domid_bitmap, DOMID_FIRST_RESERVED);

/*
 * Allocate domain ID.
 *
 * @param domid Domain ID hint:
 * - If an explicit domain ID is provided, verify its availability and use it
 *   if ID is not used;
 * - If DOMID_INVALID is provided, search [1..DOMID_FIRST_RESERVED-1] range,
 *   starting from the last used ID. Implementation guarantees that two
 *   consecutive calls will never return the same ID. ID#0 is reserved for
 *   the first boot domain (currently, dom0) and excluded from the allocation
 *   range.
 * @return Valid domain ID in case of successful allocation,
 *         DOMID_INVALID - otherwise.
 */
domid_t domid_alloc(domid_t domid)
{
    static domid_t domid_last;

    spin_lock(&domid_lock);

    /* Exact match. */
    if ( domid < DOMID_FIRST_RESERVED )
    {
        if ( __test_and_set_bit(domid, domid_bitmap) )
            domid = DOMID_INVALID;
    }
    /*
     * Exhaustive search.
     *
     * Domain ID#0 is reserved for the first boot domain (e.g. control domain)
     * and excluded from allocation.
     */
    else
    {
        domid_t bound = DOMID_FIRST_RESERVED;

        domid = find_next_zero_bit(domid_bitmap, bound, domid_last + 1);
        if ( domid >= bound && domid_last != 0 )
        {
            bound = domid_last + 1;
            domid = find_next_zero_bit(domid_bitmap, bound, 1);
        }

        ASSERT(domid <= DOMID_FIRST_RESERVED);
        if ( domid < bound )
        {
            __set_bit(domid, domid_bitmap);
            domid_last = domid;
        }
        else
            domid = DOMID_INVALID;
    }

    spin_unlock(&domid_lock);

    return domid;
}

void domid_free(domid_t domid)
{
    int rc;

    ASSERT(domid <= DOMID_FIRST_RESERVED);

    spin_lock(&domid_lock);
    rc = __test_and_clear_bit(domid, domid_bitmap);
    spin_unlock(&domid_lock);

    ASSERT(rc);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
