/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * include/asm-x86/mem_paging.h
 *
 * Memory paging support.
 *
 * Copyright (c) 2009 Citrix Systems, Inc. (Patrick Colp)
 */

#ifndef __ASM_X86_MEM_PAGING_H__
#define __ASM_X86_MEM_PAGING_H__

int mem_paging_memop(XEN_GUEST_HANDLE_PARAM(xen_mem_paging_op_t) arg);

#ifdef CONFIG_MEM_PAGING
# define mem_paging_enabled(d) vm_event_check_ring((d)->vm_event_paging)
#else
# define mem_paging_enabled(d) false
#endif

#endif /*__ASM_X86_MEM_PAGING_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
