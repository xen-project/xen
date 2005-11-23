/******************************************************************************
 * include/xen/grant_table.h
 * 
 * Mechanism for granting foreign access to page frames, and receiving
 * page-ownership transfers.
 * 
 * Copyright (c) 2004-2005 K A Fraser
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

#ifndef __XEN_GRANT_TABLE_H__
#define __XEN_GRANT_TABLE_H__

#include <xen/config.h>
#include <public/grant_table.h>
#include <asm/grant_table.h>

/* Active grant entry - used for shadowing GTF_permit_access grants. */
typedef struct {
    u32           pin;    /* Reference count information.  */
    domid_t       domid;  /* Domain being granted access.  */
    unsigned long frame;  /* Frame being granted.          */
} active_grant_entry_t;

 /* Count of writable host-CPU mappings. */
#define GNTPIN_hstw_shift    (0)
#define GNTPIN_hstw_inc      (1 << GNTPIN_hstw_shift)
#define GNTPIN_hstw_mask     (0xFFU << GNTPIN_hstw_shift)
 /* Count of read-only host-CPU mappings. */
#define GNTPIN_hstr_shift    (8)
#define GNTPIN_hstr_inc      (1 << GNTPIN_hstr_shift)
#define GNTPIN_hstr_mask     (0xFFU << GNTPIN_hstr_shift)
 /* Count of writable device-bus mappings. */
#define GNTPIN_devw_shift    (16)
#define GNTPIN_devw_inc      (1 << GNTPIN_devw_shift)
#define GNTPIN_devw_mask     (0xFFU << GNTPIN_devw_shift)
 /* Count of read-only device-bus mappings. */
#define GNTPIN_devr_shift    (24)
#define GNTPIN_devr_inc      (1 << GNTPIN_devr_shift)
#define GNTPIN_devr_mask     (0xFFU << GNTPIN_devr_shift)

#define NR_GRANT_FRAMES      (1U << ORDER_GRANT_FRAMES)
#define NR_GRANT_ENTRIES     \
    ((NR_GRANT_FRAMES << PAGE_SHIFT) / sizeof(grant_entry_t))

/*
 * Tracks a mapping of another domain's grant reference. Each domain has a
 * table of these, indexes into which are returned as a 'mapping handle'.
 */
typedef struct {
    u16      ref_and_flags; /* 0-4: GNTMAP_* ; 5-15: grant ref */
    domid_t  domid;         /* granting domain */
} grant_mapping_t;
#define MAPTRACK_GNTMAP_MASK  0x1f
#define MAPTRACK_REF_SHIFT    5
#define MAPTRACK_MAX_ENTRIES  (1 << (16 - MAPTRACK_REF_SHIFT))

/* Per-domain grant information. */
typedef struct {
    /* Shared grant table (see include/public/grant_table.h). */
    grant_entry_t        *shared;
    /* Active grant table. */
    active_grant_entry_t *active;
    /* Mapping tracking table. */
    grant_mapping_t      *maptrack;
    unsigned int          maptrack_head;
    unsigned int          maptrack_order;
    unsigned int          maptrack_limit;
    unsigned int          map_count;
    /* Lock protecting updates to active and shared grant tables. */
    spinlock_t            lock;
} grant_table_t;

/* Start-of-day system initialisation. */
void grant_table_init(
    void);

/* Create/destroy per-domain grant table context. */
int grant_table_create(
    struct domain *d);
void grant_table_destroy(
    struct domain *d);

/*
 * Check that the given grant reference (rd,ref) allows 'ld' to transfer
 * ownership of a page frame. If so, lock down the grant entry.
 */
int 
gnttab_prepare_for_transfer(
    struct domain *rd, struct domain *ld, grant_ref_t ref);

/* Domain death release of granted mappings of other domains' memory. */
void
gnttab_release_mappings(
    struct domain *d);

#endif /* __XEN_GRANT_TABLE_H__ */
