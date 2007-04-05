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

#ifdef CONFIG_XEN
extern int running_on_xen;
#define is_running_on_xen()			(running_on_xen)
#else /* CONFIG_XEN */
# ifdef CONFIG_VMX_GUEST
#  define is_running_on_xen()			(1)
# else /* CONFIG_VMX_GUEST */
#  define is_running_on_xen()			(0)
#  define HYPERVISOR_ioremap(offset, size)	(offset)
# endif /* CONFIG_VMX_GUEST */
#endif /* CONFIG_XEN */

#if defined(CONFIG_XEN) || defined(CONFIG_VMX_GUEST)
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/errno.h>
#include <xen/interface/xen.h>
#include <xen/interface/platform.h>
#include <xen/interface/event_channel.h>
#include <xen/interface/physdev.h>
#include <xen/interface/sched.h>
#include <xen/hypercall.h>
#include <asm/ptrace.h>
#include <asm/page.h>

extern shared_info_t *HYPERVISOR_shared_info;
extern start_info_t *xen_start_info;

void force_evtchn_callback(void);

#ifndef CONFIG_VMX_GUEST
/* Turn jiffies into Xen system time. XXX Implement me. */
#define jiffies_to_st(j)	0

static inline int
HYPERVISOR_yield(
	void)
{
	int rc = HYPERVISOR_sched_op(SCHEDOP_yield, NULL);

	return rc;
}

static inline int
HYPERVISOR_block(
	void)
{
	int rc = HYPERVISOR_sched_op(SCHEDOP_block, NULL);

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

	return rc;
}

// for drivers/xen/privcmd/privcmd.c
#define machine_to_phys_mapping 0
struct vm_area_struct;
int direct_remap_pfn_range(struct vm_area_struct *vma,
			   unsigned long address,
			   unsigned long mfn,
			   unsigned long size,
			   pgprot_t prot,
			   domid_t  domid);
struct file;
int privcmd_enforce_singleshot_mapping(struct vm_area_struct *vma);
int privcmd_mmap(struct file * file, struct vm_area_struct * vma);
#define HAVE_ARCH_PRIVCMD_MMAP

// for drivers/xen/balloon/balloon.c
#ifdef CONFIG_XEN_SCRUB_PAGES
#define scrub_pages(_p,_n) memset((void *)(_p), 0, (_n) << PAGE_SHIFT)
#else
#define scrub_pages(_p,_n) ((void)0)
#endif
#define	pte_mfn(_x)	pte_pfn(_x)
#define phys_to_machine_mapping_valid(_x)	(1)

#endif /* !CONFIG_VMX_GUEST */

#define __pte_ma(_x)	((pte_t) {(_x)})        /* unmodified use */
#define pfn_pte_ma(_x,_y)	__pte_ma(0)     /* unmodified use */

#ifndef CONFIG_VMX_GUEST
int __xen_create_contiguous_region(unsigned long vstart, unsigned int order, unsigned int address_bits);
static inline int
xen_create_contiguous_region(unsigned long vstart,
                             unsigned int order, unsigned int address_bits)
{
	int ret = 0;
	if (is_running_on_xen()) {
		ret = __xen_create_contiguous_region(vstart, order,
		                                     address_bits);
	}
	return ret;
}

void __xen_destroy_contiguous_region(unsigned long vstart, unsigned int order);
static inline void
xen_destroy_contiguous_region(unsigned long vstart, unsigned int order)
{
	if (is_running_on_xen())
		__xen_destroy_contiguous_region(vstart, order);
}

#endif /* !CONFIG_VMX_GUEST */

// for netfront.c, netback.c
#define MULTI_UVMFLAGS_INDEX 0 //XXX any value

static inline void
MULTI_update_va_mapping(
	multicall_entry_t *mcl, unsigned long va,
	pte_t new_val, unsigned long flags)
{
	mcl->op = __HYPERVISOR_update_va_mapping;
	mcl->result = 0;
}

static inline void
MULTI_grant_table_op(multicall_entry_t *mcl, unsigned int cmd,
	void *uop, unsigned int count)
{
	mcl->op = __HYPERVISOR_grant_table_op;
	mcl->args[0] = cmd;
	mcl->args[1] = (unsigned long)uop;
	mcl->args[2] = count;
}

/*
 * for blktap.c
 * int create_lookup_pte_addr(struct mm_struct *mm, 
 *                            unsigned long address,
 *                            uint64_t *ptep);
 */
#define create_lookup_pte_addr(mm, address, ptep)			\
	({								\
		printk(KERN_EMERG					\
		       "%s:%d "						\
		       "create_lookup_pte_addr() isn't supported.\n",	\
		       __func__, __LINE__);				\
		BUG();							\
		(-ENOSYS);						\
	})

// for debug
asmlinkage int xprintk(const char *fmt, ...);
#define xprintd(fmt, ...)	xprintk("%s:%d " fmt, __func__, __LINE__, \
					##__VA_ARGS__)

#endif /* CONFIG_XEN || CONFIG_VMX_GUEST */

#ifdef CONFIG_XEN_PRIVILEGED_GUEST
#define is_initial_xendomain()						\
	(is_running_on_xen() ? xen_start_info->flags & SIF_INITDOMAIN : 0)
#else
#define is_initial_xendomain() 0
#endif

#endif /* __HYPERVISOR_H__ */
