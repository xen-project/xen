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

#include <xen/list.h>
#include <asm/iommu.h>

#define VTDPREFIX "[VT-D]" 

#define DMAR_OPERATION_TIMEOUT (HZ*60) /* 1m */
#define time_after(a,b)         \
        (typecheck(unsigned long, a) && \
         typecheck(unsigned long, b) && \
         ((long)(b) - (long)(a) < 0))

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

#endif // _VTD_H_
