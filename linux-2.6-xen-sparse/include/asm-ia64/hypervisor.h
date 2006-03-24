/******************************************************************************
 * hypervisor.h
 * 
 * Linux-specific hypervisor handling.
 * 
 * Copyright (c) 2002-2004, K A Fraser
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef __HYPERVISOR_H__
#define __HYPERVISOR_H__

#include <linux/config.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <xen/interface/xen.h>
#include <xen/interface/dom0_ops.h>
#include <asm/ptrace.h>
#include <asm/page.h>
#include <asm/xen/privop.h> // for running_on_xen

extern shared_info_t *HYPERVISOR_shared_info;
extern start_info_t *xen_start_info;

void force_evtchn_callback(void);

int xen_init(void);

/* Turn jiffies into Xen system time. XXX Implement me. */
#define jiffies_to_st(j)	0

// for drivers/xen/privcmd/privcmd.c
#define direct_remap_pfn_range(a,b,c,d,e,f) remap_pfn_range(a,b,c,d,e)
#define	pfn_to_mfn(x)	(x)
#define	mfn_to_pfn(x)	(x)
#define machine_to_phys_mapping 0

// for drivers/xen/balloon/balloon.c
#ifdef CONFIG_XEN_SCRUB_PAGES
#define scrub_pages(_p,_n) memset((void *)(_p), 0, (_n) << PAGE_SHIFT)
#else
#define scrub_pages(_p,_n) ((void)0)
#endif
#define	pte_mfn(_x)	pte_pfn(_x)
#define INVALID_P2M_ENTRY	(~0UL)
#define __pte_ma(_x)	((pte_t) {(_x)})
#define phys_to_machine_mapping_valid(_x)	(1)
#define	kmap_flush_unused()	do {} while (0)
#define set_phys_to_machine(_x,_y)	do {} while (0)
#define xen_machphys_update(_x,_y)	do {} while (0)
#define pfn_pte_ma(_x,_y)	__pte_ma(0)

#endif /* __HYPERVISOR_H__ */
