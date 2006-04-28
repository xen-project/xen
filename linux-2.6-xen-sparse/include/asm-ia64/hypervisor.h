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
#include <linux/errno.h>
#include <xen/interface/xen.h>
#include <xen/interface/dom0_ops.h>
#include <xen/interface/sched.h>
#include <asm/hypercall.h>
#include <asm/ptrace.h>
#include <asm/page.h>
#include <asm/xen/privop.h> // for running_on_xen

extern shared_info_t *HYPERVISOR_shared_info;
extern start_info_t *xen_start_info;

void force_evtchn_callback(void);

int xen_init(void);

/* Turn jiffies into Xen system time. XXX Implement me. */
#define jiffies_to_st(j)	0

static inline int
HYPERVISOR_yield(
	void)
{
	int rc = HYPERVISOR_sched_op(SCHEDOP_yield, NULL);

	if (rc == -ENOSYS)
		rc = HYPERVISOR_sched_op_compat(SCHEDOP_yield, 0);

	return rc;
}

static inline int
HYPERVISOR_block(
	void)
{
	int rc = HYPERVISOR_sched_op(SCHEDOP_block, NULL);

	if (rc == -ENOSYS)
		rc = HYPERVISOR_sched_op_compat(SCHEDOP_block, 0);

	return rc;
}

static inline int
HYPERVISOR_shutdown(
	unsigned int reason)
{
	struct sched_shutdown sched_shutdown = {
		.reason = reason
	};

	int rc = HYPERVISOR_sched_op(SCHEDOP_shutdown, &sched_shutdown);

	if (rc == -ENOSYS)
		rc = HYPERVISOR_sched_op_compat(SCHEDOP_shutdown, reason);

	return rc;
}

static inline int
HYPERVISOR_poll(
	evtchn_port_t *ports, unsigned int nr_ports, u64 timeout)
{
	struct sched_poll sched_poll = {
		.nr_ports = nr_ports,
		.timeout = jiffies_to_st(timeout)
	};

	int rc;

	set_xen_guest_handle(sched_poll.ports, ports);
	rc = HYPERVISOR_sched_op(SCHEDOP_poll, &sched_poll);
	if (rc == -ENOSYS)
		rc = HYPERVISOR_sched_op_compat(SCHEDOP_yield, 0);

	return rc;
}

// for drivers/xen/privcmd/privcmd.c
#define direct_remap_pfn_range(a,b,c,d,e,f) remap_pfn_range(a,b,c,d,e)
#define machine_to_phys_mapping 0
#ifndef CONFIG_XEN_IA64_DOM0_VP
#define	pfn_to_mfn(x)	(x)
#define	mfn_to_pfn(x)	(x)
#endif

// for drivers/xen/balloon/balloon.c
#ifdef CONFIG_XEN_SCRUB_PAGES
#define scrub_pages(_p,_n) memset((void *)(_p), 0, (_n) << PAGE_SHIFT)
#else
#define scrub_pages(_p,_n) ((void)0)
#endif
#define	pte_mfn(_x)	pte_pfn(_x)
#define __pte_ma(_x)	((pte_t) {(_x)})
#define phys_to_machine_mapping_valid(_x)	(1)
#define	kmap_flush_unused()	do {} while (0)
#define pfn_pte_ma(_x,_y)	__pte_ma(0)
#ifndef CONFIG_XEN_IA64_DOM0_VP //XXX
#define set_phys_to_machine(_x,_y)	do {} while (0)
#define xen_machphys_update(_x,_y)	do {} while (0)
#endif

#ifdef CONFIG_XEN_IA64_DOM0_VP
int __xen_create_contiguous_region(unsigned long vstart, unsigned int order, unsigned int address_bits);
static inline int
xen_create_contiguous_region(unsigned long vstart,
                             unsigned int order, unsigned int address_bits)
{
	int ret = 0;
	if (running_on_xen) {
		ret = __xen_create_contiguous_region(vstart, order,
		                                     address_bits);
	}
	return ret;
}

void __xen_destroy_contiguous_region(unsigned long vstart, unsigned int order);
static inline void
xen_destroy_contiguous_region(unsigned long vstart, unsigned int order)
{
	if (running_on_xen)
		__xen_destroy_contiguous_region(vstart, order);
}
#else
#define xen_create_contiguous_region(vstart, order, address_bits)	({0;})
#define xen_destroy_contiguous_region(vstart, order)	do {} while (0)
#endif

// for debug
asmlinkage int xprintk(const char *fmt, ...);
#define xprintd(fmt, ...)	xprintk("%s:%d " fmt, __func__, __LINE__, \
					##__VA_ARGS__)

#endif /* __HYPERVISOR_H__ */
