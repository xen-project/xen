/******************************************************************************
 * common/grant_table.c
 * 
 * Mechanism for granting foreign access to page frames, and receiving
 * page-ownership transfers.
 * 
 * Copyright (c) 2004 K A Fraser
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

#define __GRANT_TABLE_IMPLEMENTATION__
typedef struct grant_table grant_table_t;

#include <xen/config.h>
#include <xen/sched.h>
#include <hypervisor-ifs/grant_table.h>

/* Active grant entry - used for shadowing GTF_permit_access grants. */
typedef struct {
    u32           counts; /* Reference count information.   */
    u16           next;   /* Mapping hash chain.            */
    domid_t       domid;  /* Domain being granted access.   */
    unsigned long frame;  /* Frame being granted.           */
} active_grant_entry_t;

/* Bitfields in active_grant_entry_t:counts. */
 /* Grant is pinned by 'domid' for read mappings and I/O. */
#define _GNTCNT_read_pinned  (0)
#define GNTCNT_read_pinned   (1<<_GNTCNT_read_pinned)
 /* Grant is pinned by 'domid' for write mappings and I/O. */
#define _GNTCNT_write_pinned (1)
#define GNTCNT_write_pinned  (1<<_GNTCNT_write_pinned)
 /* Grant is pinned in IOMMU (read-only unless GNTCNT_write_pinned). */
#define _GNTCNT_io_pinned    (2)
#define GNTCNT_io_pinned     (1<<_GNTCNT_io_pinned)
 /* Grant is mappable (read-only unless GNTCNT_write_pinned). */
#define _GNTCNT_mappable     (3)
#define GNTCNT_mappable      (1<<_GNTCNT_mappable)
 /* Count of writable page mappings. (!GNTCNT_write_pinned => count==0). */
#define GNTCNT_wmap_shift    (4)
#define GNTCNT_wmap_mask     (0x3FFFU << GNTCNT_wmap_shift)
 /* Count of read-only page mappings. */
#define GNTCNT_rmap_shift    (18)
#define GNTCNT_rmap_mask     (0x3FFFU << GNTCNT_rmap_shift)

#define MAPHASH_SZ       (256)
#define MAPHASH(_k)      ((_k) & (MAPHASH_SZ-1))
#define MAPHASH_INVALID  (0xFFFFU)

#define NR_GRANT_ENTRIES     (PAGE_SIZE / sizeof(grant_entry_t))

/* Per-domain grant information. */
struct grant_table {
    /* Shared grant table (see include/hypervisor-ifs/grant_table.h). */
    grant_entry_t        *shared;
    /* Active grant table. */
    active_grant_entry_t *active;
    /* Lock protecting updates to maphash and shared grant table. */
    spinlock_t            lock;
    /* Hash table: frame -> active grant entry. */
    u16                   maphash[MAPHASH_SZ];
};

int grant_table_create(struct domain *d)
{
    grant_table_t *t;
    int            i;

    if ( (t = xmalloc(sizeof(grant_table_t))) == NULL )
        goto no_mem;

    /* Simple stuff. */
    t->shared = NULL;
    t->active = NULL;
    spin_lock_init(&t->lock);
    for ( i = 0; i < MAPHASH_SZ; i++ )
        t->maphash[i] = MAPHASH_INVALID;

    /* Active grant-table page. */
    if ( (t->active = xmalloc(sizeof(active_grant_entry_t) * 
                              NR_GRANT_ENTRIES)) == NULL )
        goto no_mem;

    /* Set up shared grant-table page. */
    if ( (t->shared = (void *)alloc_xenheap_page()) == NULL )
        goto no_mem;
    memset(t->shared, 0, PAGE_SIZE);
    SHARE_PFN_WITH_DOMAIN(virt_to_page(t->shared), d);

    /* Okay, install the structure. */
    d->grant_table = t;
    return 0;

 no_mem:
    if ( t != NULL )
    {
        if ( t->active != NULL )
            xfree(t->active);
        xfree(t);
    }
    return -ENOMEM;
}

void grant_table_destroy(struct domain *d)
{
    grant_table_t *t;

    if ( (t = d->grant_table) != NULL )
    {
        /* Free memory relating to this grant table. */
        d->grant_table = NULL;
        free_xenheap_page((unsigned long)t->shared);
        xfree(t->active);
        xfree(t);
    }
}

void grant_table_init(void)
{
    /* Nothing. */
}
