/******************************************************************************
 *
 * Xen domain paging default policy.
 *
 * Copyright (c) 2009 Citrix Systems, Inc. (Patrick Colp)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#include "xc_bitops.h"
#include "policy.h"


#define DEFAULT_MRU_SIZE (1024 * 16)


static unsigned long *mru;
static unsigned int i_mru;
static unsigned int mru_size;
static unsigned long *bitmap;
static unsigned long *unconsumed;
static unsigned int unconsumed_cleared;
static unsigned long current_gfn;
static unsigned long max_pages;


int policy_init(struct xenpaging *paging)
{
    int i;
    int rc = -ENOMEM;

    max_pages = paging->max_pages;

    /* Allocate bitmap for pages not to page out */
    bitmap = bitmap_alloc(max_pages);
    if ( !bitmap )
        goto out;
    /* Allocate bitmap to track unusable pages */
    unconsumed = bitmap_alloc(max_pages);
    if ( !unconsumed )
        goto out;

    /* Initialise MRU list of paged in pages */
    if ( paging->policy_mru_size > 0 )
        mru_size = paging->policy_mru_size;
    else
        mru_size = paging->policy_mru_size = DEFAULT_MRU_SIZE;

    mru = malloc(sizeof(*mru) * mru_size);
    if ( mru == NULL )
        goto out;

    for ( i = 0; i < mru_size; i++ )
        mru[i] = INVALID_MFN;

    /* Don't page out page 0 */
    set_bit(0, bitmap);

    /* Start in the middle to avoid paging during BIOS startup */
    current_gfn = max_pages / 2;

    rc = 0;
 out:
    return rc;
}

unsigned long policy_choose_victim(struct xenpaging *paging)
{
    xc_interface *xch = paging->xc_handle;
    unsigned long i;

    /* One iteration over all possible gfns */
    for ( i = 0; i < max_pages; i++ )
    {
        /* Try next gfn */
        current_gfn++;

        /* Restart on wrap */
        if ( current_gfn >= max_pages )
            current_gfn = 0;

        if ( (current_gfn & (BITS_PER_LONG - 1)) == 0 )
        {
            /* All gfns busy */
            if ( ~bitmap[current_gfn >> ORDER_LONG] == 0 || ~unconsumed[current_gfn >> ORDER_LONG] == 0 )
            {
                current_gfn += BITS_PER_LONG;
                i += BITS_PER_LONG;
                continue;
            }
        }

        /* gfn busy */
        if ( test_bit(current_gfn, bitmap) )
            continue;

        /* gfn already tested */
        if ( test_bit(current_gfn, unconsumed) )
            continue;

        /* gfn found */
        break;
    }

    /* Could not nominate any gfn */
    if ( i >= max_pages )
    {
        /* No more pages, wait in poll */
        paging->use_poll_timeout = 1;
        /* Count wrap arounds */
        unconsumed_cleared++;
        /* Force retry every few seconds (depends on poll() timeout) */
        if ( unconsumed_cleared > 123)
        {
            /* Force retry of unconsumed gfns on next call */
            bitmap_clear(unconsumed, max_pages);
            unconsumed_cleared = 0;
            DPRINTF("clearing unconsumed, current_gfn %lx", current_gfn);
        }
        return INVALID_MFN;
    }

    set_bit(current_gfn, unconsumed);
    return current_gfn;
}

void policy_notify_paged_out(unsigned long gfn)
{
    set_bit(gfn, bitmap);
    clear_bit(gfn, unconsumed);
}

static void policy_handle_paged_in(unsigned long gfn, int do_mru)
{
    unsigned long old_gfn = mru[i_mru & (mru_size - 1)];

    if ( old_gfn != INVALID_MFN )
        clear_bit(old_gfn, bitmap);
    
    if (do_mru) {
        mru[i_mru & (mru_size - 1)] = gfn;
    } else {
        clear_bit(gfn, bitmap);
        mru[i_mru & (mru_size - 1)] = INVALID_MFN;
    }

    i_mru++;
}

void policy_notify_paged_in(unsigned long gfn)
{
    policy_handle_paged_in(gfn, 1);
}

void policy_notify_paged_in_nomru(unsigned long gfn)
{
    policy_handle_paged_in(gfn, 0);
}

void policy_notify_dropped(unsigned long gfn)
{
    clear_bit(gfn, bitmap);
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
