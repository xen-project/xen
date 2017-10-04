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

#include <xen/mm.h>
#include <xen/rwlock.h>
#include <public/grant_table.h>
#include <asm/page.h>
#include <asm/grant_table.h>

struct grant_table;

/* Create/destroy per-domain grant table context. */
int grant_table_create(
    struct domain *d);
void grant_table_destroy(
    struct domain *d);
void grant_table_init_vcpu(struct vcpu *v);
int grant_table_set_limits(struct domain *d, unsigned int grant_frames,
                           unsigned int maptrack_frames);

/*
 * Check if domain has active grants and log first 10 of them.
 */
void grant_table_warn_active_grants(struct domain *d);

/* Domain death release of granted mappings of other domains' memory. */
void
gnttab_release_mappings(
    struct domain *d);

int mem_sharing_gref_to_gfn(struct grant_table *gt, grant_ref_t ref,
                            gfn_t *gfn, uint16_t *status);

int gnttab_map_frame(struct domain *d, unsigned long idx, gfn_t gfn,
                     mfn_t *mfn);

unsigned int gnttab_dom0_frames(void);

#endif /* __XEN_GRANT_TABLE_H__ */
