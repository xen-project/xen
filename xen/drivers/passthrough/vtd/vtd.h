/*
 * Copyright (c) 2006, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 * Copyright (C) Allen Kay <allen.m.kay@intel.com>
 * Copyright (C) Weidong Han <weidong.han@intel.com>
 */

#ifndef _VTD_H_
#define _VTD_H_

#include <xen/iommu.h>

struct IO_APIC_route_remap_entry {
    union {
        u64 val;
        struct {
            u64 vector:8,
            delivery_mode:3,
            index_15:1,
            delivery_status:1,
            polarity:1,
            irr:1,
            trigger:1,
            mask:1,
            reserved:31,
            format:1,
            index_0_14:15;
        };
    };
};

struct msi_msg_remap_entry {
    union {
        u32 val;
        struct {
            u32 dontcare:2,
                index_15:1,
                SHV:1,
                format:1,
                index_0_14:15,
                addr_id_val:12; /* Interrupt address identifier value,
                                   must be 0FEEh */
        };
    } address_lo;   /* low 32 bits of msi message address */

    u32	address_hi;	/* high 32 bits of msi message address */
    u32	data;		/* msi message data */
};

unsigned int get_clflush_size(void);
u64 alloc_pgtable_maddr(void);
void free_pgtable_maddr(u64 maddr);
void *map_vtd_domain_page(u64 maddr);
void unmap_vtd_domain_page(void *va);

void iommu_flush_cache_entry(void *addr);
void iommu_flush_cache_page(void *addr);

#endif // _VTD_H_
