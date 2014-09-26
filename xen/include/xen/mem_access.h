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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _XEN_ASM_MEM_ACCESS_H
#define _XEN_ASM_MEM_ACCESS_H

#include <public/memory.h>

#ifdef HAS_MEM_ACCESS

int mem_access_memop(unsigned long cmd,
                     XEN_GUEST_HANDLE_PARAM(xen_mem_access_op_t) arg);
int mem_access_send_req(struct domain *d, mem_event_request_t *req);

/* Resumes the running of the VCPU, restarting the last instruction */
void mem_access_resume(struct domain *d);

#else

static inline
int mem_access_memop(unsigned long cmd,
                     XEN_GUEST_HANDLE_PARAM(xen_mem_access_op_t) arg)
{
    return -ENOSYS;
}

static inline
int mem_access_send_req(struct domain *d, mem_event_request_t *req)
{
    return -ENOSYS;
}

static inline void mem_access_resume(struct domain *d) {}

#endif /* HAS_MEM_ACCESS */

#endif /* _XEN_ASM_MEM_ACCESS_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
