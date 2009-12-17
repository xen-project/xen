/******************************************************************************
 * tools/xenpaging/policy.c
 *
 * Xen domain paging default policy.
 *
 * Copyright (c) 2009 Citrix (R&D) Inc. (Patrick Colp)
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


#include "bitops.h"
#include "xc.h"
#include "policy.h"


#define MRU_SIZE 1024


static unsigned long mru[MRU_SIZE];
static unsigned int i_mru = 0;
static unsigned long *bitmap;


int policy_init(xenpaging_t *paging)
{
    int i;
    int rc;

    /* Allocate bitmap for pages not to page out */
    rc = alloc_bitmap(&bitmap, paging->bitmap_size);
    if ( rc != 0 )
        goto out;

    /* Initialise MRU list of paged in pages */
    for ( i = 0; i < MRU_SIZE; i++ )
        mru[i] = INVALID_MFN;

    /* Don't page out page 0 */
    set_bit(0, bitmap);

    rc = 0;

 out:
    return rc;
}

int policy_choose_victim(xenpaging_t *paging, domid_t domain_id,
                         xenpaging_victim_t *victim)
{
    ASSERT(victim != NULL);

    /* Domain to pick on */
    victim->domain_id = domain_id;
    
    do
    {
        /* Randomly choose a gfn to evict */
        victim->gfn = rand() % paging->domain_info->max_pages;
    }
    while ( test_bit(victim->gfn, bitmap) );

    return 0;
}

void policy_notify_paged_out(domid_t domain_id, unsigned long gfn)
{
    set_bit(gfn, bitmap);
}

void policy_notify_paged_in(domid_t domain_id, unsigned long gfn)
{
    unsigned long old_gfn = mru[i_mru & (MRU_SIZE - 1)];

    if ( old_gfn != INVALID_MFN )
        clear_bit(old_gfn, bitmap);
    
    mru[i_mru & (MRU_SIZE - 1)] = gfn;
    i_mru++;
}


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
