/******************************************************************************
 * include/xen/grant_table.h
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

#ifndef __XEN_GRANT_H__
#define __XEN_GRANT_H__

#include <hypervisor-ifs/grant_table.h>

/* Active grant entry - used for shadowing GTF_permit_access grants. */
typedef struct {
    u32           status; /* Reference count information.  */
    u32           tlbflush_timestamp; /* Flush avoidance.  */
    u16           next;   /* Mapping hash chain.           */
    domid_t       domid;  /* Domain being granted access.  */
    unsigned long frame;  /* Frame being granted.          */
} active_grant_entry_t;

/*
 * Bitfields in active_grant_entry_t:counts.
 * NB. Some other GNTPIN_xxx definitions are in hypervisor-ifs/grant_table.h.
 */
 /* Count of writable host-CPU mappings. */
#define GNTPIN_wmap_shift    (4)
#define GNTPIN_wmap_mask     (0x3FFFU << GNTPIN_wmap_shift)
 /* Count of read-only host-CPU mappings. */
#define GNTPIN_rmap_shift    (18)
#define GNTPIN_rmap_mask     (0x3FFFU << GNTPIN_rmap_shift)

#define GNT_MAPHASH_SZ       (256)
#define GNT_MAPHASH(_k)      ((_k) & (GNT_MAPHASH_SZ-1))
#define GNT_MAPHASH_INVALID  (0xFFFFU)

#define NR_GRANT_ENTRIES     (PAGE_SIZE / sizeof(grant_entry_t))

/* Per-domain grant information. */
typedef struct {
    /* Shared grant table (see include/hypervisor-ifs/grant_table.h). */
    grant_entry_t        *shared;
    /* Active grant table. */
    active_grant_entry_t *active;
    /* Lock protecting updates to maphash and shared grant table. */
    spinlock_t            lock;
    /* Hash table: frame -> active grant entry. */
    u16                   maphash[GNT_MAPHASH_SZ];
} grant_table_t;

/* Start-of-day system initialisation. */
void grant_table_init(void);

/* Create/destroy per-domain grant table context. */
int  grant_table_create(struct domain *d);
void grant_table_destroy(struct domain *d);

#endif /* __XEN_GRANT_H__ */
