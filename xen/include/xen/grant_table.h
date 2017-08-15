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
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __XEN_GRANT_TABLE_H__
#define __XEN_GRANT_TABLE_H__

#include <xen/rwlock.h>
#include <public/grant_table.h>
#include <asm/page.h>
#include <asm/grant_table.h>

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

#ifndef DEFAULT_MAX_NR_GRANT_FRAMES /* to allow arch to override */
/* Default maximum size of a grant table. [POLICY] */
#define DEFAULT_MAX_NR_GRANT_FRAMES   32
#endif
/* The maximum size of a grant table. */
extern unsigned int max_grant_frames;

DECLARE_PERCPU_RWLOCK_GLOBAL(grant_rwlock);

/* Per-domain grant information. */
struct grant_table {
    /*
     * Lock protecting updates to grant table state (version, active
     * entry list, etc.)
     */
    percpu_rwlock_t       lock;
    /* Table size. Number of frames shared with guest */
    unsigned int          nr_grant_frames;
    /* Shared grant table (see include/public/grant_table.h). */
    union {
        void **shared_raw;
        struct grant_entry_v1 **shared_v1;
        union grant_entry_v2 **shared_v2;
    };
    /* Number of grant status frames shared with guest (for version 2) */
    unsigned int          nr_status_frames;
    /* State grant table (see include/public/grant_table.h). */
    grant_status_t       **status;
    /* Active grant table. */
    struct active_grant_entry **active;
    /* Mapping tracking table per vcpu. */
    struct grant_mapping **maptrack;
    unsigned int          maptrack_limit;
    /* Lock protecting the maptrack limit */
    spinlock_t            maptrack_lock;
    /* The defined versions are 1 and 2.  Set to 0 if we don't know
       what version to use yet. */
    unsigned              gt_version;
};

static inline void grant_read_lock(struct grant_table *gt)
{
    percpu_read_lock(grant_rwlock, &gt->lock);
}

static inline void grant_read_unlock(struct grant_table *gt)
{
    percpu_read_unlock(grant_rwlock, &gt->lock);
}

static inline void grant_write_lock(struct grant_table *gt)
{
    percpu_write_lock(grant_rwlock, &gt->lock);
}

static inline void grant_write_unlock(struct grant_table *gt)
{
    percpu_write_unlock(grant_rwlock, &gt->lock);
}

/* Create/destroy per-domain grant table context. */
int grant_table_create(
    struct domain *d);
void grant_table_destroy(
    struct domain *d);
void grant_table_init_vcpu(struct vcpu *v);

/*
 * Check if domain has active grants and log first 10 of them.
 */
void grant_table_warn_active_grants(struct domain *d);

/* Domain death release of granted mappings of other domains' memory. */
void
gnttab_release_mappings(
    struct domain *d);

/* Increase the size of a domain's grant table.
 * Caller must hold d's grant table write lock.
 */
int
gnttab_grow_table(struct domain *d, unsigned int req_nr_frames);

/* Number of grant table frames. Caller must hold d's grant table lock. */
static inline unsigned int nr_grant_frames(struct grant_table *gt)
{
    return gt->nr_grant_frames;
}

/* Number of status grant table frames. Caller must hold d's gr. table lock.*/
static inline unsigned int nr_status_frames(struct grant_table *gt)
{
    return gt->nr_status_frames;
}

#define GRANT_STATUS_PER_PAGE (PAGE_SIZE / sizeof(grant_status_t))
#define GRANT_PER_PAGE (PAGE_SIZE / sizeof(grant_entry_v2_t))
/* Number of grant table status entries. Caller must hold d's gr. table lock.*/
static inline unsigned int grant_to_status_frames(int grant_frames)
{
    return (grant_frames * GRANT_PER_PAGE + GRANT_STATUS_PER_PAGE - 1) /
        GRANT_STATUS_PER_PAGE;
}

int mem_sharing_gref_to_gfn(struct grant_table *gt, grant_ref_t ref,
                            gfn_t *gfn, uint16_t *status);

#endif /* __XEN_GRANT_TABLE_H__ */
