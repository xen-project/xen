/******************************************************************************
 * mem_access.h
 *
 * Memory access support.
 *
 * Copyright (c) 2011 Virtuata, Inc.
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

#ifndef _XEN_MEM_ACCESS_H
#define _XEN_MEM_ACCESS_H

#include <xen/types.h>
#include <xen/mm.h>
#include <public/memory.h>
#include <public/vm_event.h>
#include <asm/mem_access.h>

/*
 * Additional access types, which are used to further restrict
 * the permissions given my the p2m_type_t memory type.  Violations
 * caused by p2m_access_t restrictions are sent to the vm_event
 * interface.
 *
 * The access permissions are soft state: when any ambiguous change of page
 * type or use occurs, or when pages are flushed, swapped, or at any other
 * convenient type, the access permissions can get reset to the p2m_domain
 * default.
 */
typedef enum {
    /* Code uses bottom three bits with bitmask semantics */
    p2m_access_n     = 0, /* No access allowed. */
    p2m_access_r     = 1 << 0,
    p2m_access_w     = 1 << 1,
    p2m_access_x     = 1 << 2,
    p2m_access_rw    = p2m_access_r | p2m_access_w,
    p2m_access_rx    = p2m_access_r | p2m_access_x,
    p2m_access_wx    = p2m_access_w | p2m_access_x,
    p2m_access_rwx   = p2m_access_r | p2m_access_w | p2m_access_x,

    p2m_access_rx2rw = 8, /* Special: page goes from RX to RW on write */
    p2m_access_n2rwx = 9, /* Special: page goes from N to RWX on access, *
                           * generates an event but does not pause the
                           * vcpu */

    /* NOTE: Assumed to be only 4 bits right now on x86. */
} p2m_access_t;

/*
 * Set access type for a region of gfns.
 * If gfn == INVALID_GFN, sets the default access type.
 */
long p2m_set_mem_access(struct domain *d, gfn_t gfn, uint32_t nr,
                        uint32_t start, uint32_t mask, xenmem_access_t access,
                        unsigned int altp2m_idx);

long p2m_set_mem_access_multi(struct domain *d,
                              const XEN_GUEST_HANDLE(const_uint64) pfn_list,
                              const XEN_GUEST_HANDLE(const_uint8) access_list,
                              uint32_t nr, uint32_t start, uint32_t mask,
                              unsigned int altp2m_idx);

/*
 * Get access type for a gfn.
 * If gfn == INVALID_GFN, gets the default access type.
 */
int p2m_get_mem_access(struct domain *d, gfn_t gfn, xenmem_access_t *access);

#ifdef CONFIG_HAS_MEM_ACCESS
int mem_access_memop(unsigned long cmd,
                     XEN_GUEST_HANDLE_PARAM(xen_mem_access_op_t) arg);
#else
static inline
int mem_access_memop(unsigned long cmd,
                     XEN_GUEST_HANDLE_PARAM(xen_mem_access_op_t) arg)
{
    return -ENOSYS;
}
#endif /* CONFIG_HAS_MEM_ACCESS */

#endif /* _XEN_MEM_ACCESS_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
