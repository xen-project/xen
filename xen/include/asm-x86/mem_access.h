/******************************************************************************
 * include/asm-x86/mem_access.h
 *
 * Memory access support.
 *
 * Copyright (c) 2011 GridCentric Inc. (Andres Lagar-Cavilla)
 * Copyright (c) 2007 Advanced Micro Devices (Wei Huang)
 * Parts of this code are Copyright (c) 2006-2007 by XenSource Inc.
 * Parts of this code are Copyright (c) 2006 by Michael A Fetterman
 * Parts based on earlier work by Michael A Fetterman, Ian Pratt et al.
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

#ifndef __ASM_X86_MEM_ACCESS_H__
#define __ASM_X86_MEM_ACCESS_H__

/*
 * Setup vm_event request based on the access (gla is -1ull if not available).
 * Handles the rw2rx conversion. Boolean return value indicates if event type
 * is syncronous (aka. requires vCPU pause). If the req_ptr has been populated,
 * then the caller should use monitor_traps to send the event on the MONITOR
 * ring. Once having released get_gfn* locks caller must also xfree the
 * request.
 */
bool p2m_mem_access_check(paddr_t gpa, unsigned long gla,
                          struct npfec npfec,
                          struct vm_event_st **req_ptr);

/* Check for emulation and mark vcpu for skipping one instruction
 * upon rescheduling if required. */
bool p2m_mem_access_emulate_check(struct vcpu *v,
                                  const struct vm_event_st *rsp);

/* Sanity check for mem_access hardware support */
bool p2m_mem_access_sanity_check(const struct domain *d);

int p2m_set_suppress_ve(struct domain *d, gfn_t gfn, bool suppress_ve,
                        unsigned int altp2m_idx);

struct xen_hvm_altp2m_suppress_ve_multi;
int p2m_set_suppress_ve_multi(struct domain *d,
                              struct xen_hvm_altp2m_suppress_ve_multi *suppress_ve);

int p2m_get_suppress_ve(struct domain *d, gfn_t gfn, bool *suppress_ve,
                        unsigned int altp2m_idx);

#endif /*__ASM_X86_MEM_ACCESS_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
