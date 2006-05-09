/******************************************************************************
 * hypercall.h
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

#ifndef __HYPERCALL_H__
#define __HYPERCALL_H__

#include <linux/string.h> /* memcpy() */

#ifndef __HYPERVISOR_H__
# error "please don't include this file directly"
#endif

/*
 * Assembler stubs for hyper-calls.
 */

#define _hypercall0(type, name)					\
({								\
	long __res;						\
	__asm__ __volatile__ (";;\n"				\
			      "mov r2=%1\n"			\
			      "break 0x1000 ;;\n"		\
			      "mov %0=r8 ;;\n"			\
			      : "=r" (__res)			\
			      : "i" (__HYPERVISOR_##name)	\
			      : "r2","r8",			\
			        "memory" );			\
	(type)__res;						\
})

#define _hypercall1(type, name, a1)				\
({								\
	long __res;						\
	__asm__ __volatile__ (";;\n"				\
			      "mov r14=%2\n"			\
			      "mov r2=%1\n"			\
			      "break 0x1000 ;;\n"		\
			      "mov %0=r8 ;;\n"			\
			      : "=r" (__res)			\
			      : "i" (__HYPERVISOR_##name),	\
				"r" ((unsigned long)(a1))	\
			      : "r14","r2","r8",		\
				"memory" );			\
	(type)__res;						\
})

#define _hypercall2(type, name, a1, a2)				\
({								\
	long __res;						\
	__asm__ __volatile__ (";;\n"				\
			      "mov r14=%2\n"			\
			      "mov r15=%3\n"			\
			      "mov r2=%1\n"			\
			      "break 0x1000 ;;\n"		\
			      "mov %0=r8 ;;\n"			\
			      : "=r" (__res)			\
			      : "i" (__HYPERVISOR_##name),	\
				"r" ((unsigned long)(a1)),	\
				"r" ((unsigned long)(a2))	\
			      : "r14","r15","r2","r8",		\
				"memory" );			\
	(type)__res;						\
})

#define _hypercall3(type, name, a1, a2, a3)			\
({								\
	long __res;						\
	__asm__ __volatile__ (";;\n"                            \
			      "mov r14=%2\n"                    \
			      "mov r15=%3\n"                    \
			      "mov r16=%4\n"                    \
			      "mov r2=%1\n"                     \
			      "break 0x1000 ;;\n"               \
			      "mov %0=r8 ;;\n"                  \
			      : "=r" (__res)                    \
			      : "i" (__HYPERVISOR_##name),      \
				"r" ((unsigned long)(a1)),	\
				"r" ((unsigned long)(a2)),	\
				"r" ((unsigned long)(a3))	\
			      : "r14","r15","r16","r2","r8",	\
			        "memory" );                     \
	(type)__res;                                            \
})

#define _hypercall4(type, name, a1, a2, a3, a4)			\
({								\
	long __res;						\
	__asm__ __volatile__ (";;\n"                            \
			      "mov r14=%2\n"                    \
			      "mov r15=%3\n"                    \
			      "mov r16=%4\n"                    \
			      "mov r17=%5\n"                    \
			      "mov r2=%1\n"                     \
			      "break 0x1000 ;;\n"               \
			      "mov %0=r8 ;;\n"                  \
			      : "=r" (__res)                    \
			      : "i" (__HYPERVISOR_##name),      \
				"r" ((unsigned long)(a1)),	\
				"r" ((unsigned long)(a2)),	\
				"r" ((unsigned long)(a3)),	\
				"r" ((unsigned long)(a4))       \
			      : "r14","r15","r16","r2","r8",	\
			        "r17","memory" );               \
	(type)__res;                                            \
})

#define _hypercall5(type, name, a1, a2, a3, a4, a5)		\
({								\
	long __res;						\
	__asm__ __volatile__ (";;\n"                            \
			      "mov r14=%2\n"                    \
			      "mov r15=%3\n"                    \
			      "mov r16=%4\n"                    \
			      "mov r17=%5\n"                    \
			      "mov r18=%6\n"                    \
			      "mov r2=%1\n"                     \
			      "break 0x1000 ;;\n"               \
			      "mov %0=r8 ;;\n"                  \
			      : "=r" (__res)                    \
			      : "i" (__HYPERVISOR_##name),      \
				"r" ((unsigned long)(a1)),	\
				"r" ((unsigned long)(a2)),	\
				"r" ((unsigned long)(a3)),	\
				"r" ((unsigned long)(a4)),	\
				"r" ((unsigned long)(a5))       \
			      : "r14","r15","r16","r2","r8",	\
			        "r17","r18","memory" );         \
	(type)__res;                                            \
})

static inline int
HYPERVISOR_sched_op_compat(
    int cmd, unsigned long arg)
{
	return _hypercall2(int, sched_op_compat, cmd, arg);
}

static inline int
HYPERVISOR_sched_op(
	int cmd, void *arg)
{
	return _hypercall2(int, sched_op, cmd, arg);
}

static inline long
HYPERVISOR_set_timer_op(
    u64 timeout)
{
    unsigned long timeout_hi = (unsigned long)(timeout>>32);
    unsigned long timeout_lo = (unsigned long)timeout;
    return _hypercall2(long, set_timer_op, timeout_lo, timeout_hi);
}

static inline int
HYPERVISOR_dom0_op(
    dom0_op_t *dom0_op)
{
    dom0_op->interface_version = DOM0_INTERFACE_VERSION;
    return _hypercall1(int, dom0_op, dom0_op);
}

static inline int
HYPERVISOR_multicall(
    void *call_list, int nr_calls)
{
    return _hypercall2(int, multicall, call_list, nr_calls);
}

static inline int
HYPERVISOR_memory_op(
    unsigned int cmd, void *arg)
{
    return _hypercall2(int, memory_op, cmd, arg);
}

static inline int
HYPERVISOR_event_channel_op(
    int cmd, void *arg)
{
    int rc = _hypercall2(int, event_channel_op, cmd, arg);
    if (unlikely(rc == -ENOSYS)) {
        struct evtchn_op op;
        op.cmd = cmd;
        memcpy(&op.u, arg, sizeof(op.u));
        rc = _hypercall1(int, event_channel_op_compat, &op);
    }
    return rc;
}

static inline int
HYPERVISOR_xen_version(
    int cmd, void *arg)
{
    return _hypercall2(int, xen_version, cmd, arg);
}

static inline int
HYPERVISOR_console_io(
    int cmd, int count, char *str)
{
    return _hypercall3(int, console_io, cmd, count, str);
}

static inline int
HYPERVISOR_physdev_op(
    int cmd, void *arg)
{
    int rc = _hypercall2(int, physdev_op, cmd, arg);
    if (unlikely(rc == -ENOSYS)) {
        struct physdev_op op;
        op.cmd = cmd;
        memcpy(&op.u, arg, sizeof(op.u));
        rc = _hypercall1(int, physdev_op_compat, &op);
    }
    return rc;
}

//XXX __HYPERVISOR_grant_table_op is used for this hypercall constant.
static inline int
____HYPERVISOR_grant_table_op(
    unsigned int cmd, void *uop, unsigned int count)
{
    return _hypercall3(int, grant_table_op, cmd, uop, count);
}
#ifndef CONFIG_XEN_IA64_DOM0_VP
#define HYPERVISOR_grant_table_op(cmd, uop, count) \
	____HYPERVISOR_grant_table_op((cmd), (uop), (count))
#else
int HYPERVISOR_grant_table_op(unsigned int cmd, void *uop, unsigned int count);
#endif

static inline int
HYPERVISOR_vcpu_op(
	int cmd, int vcpuid, void *extra_args)
{
    return _hypercall3(int, vcpu_op, cmd, vcpuid, extra_args);
}

static inline int
HYPERVISOR_suspend(
	unsigned long srec)
{
	struct sched_shutdown sched_shutdown = {
		.reason = SHUTDOWN_suspend
	};

	int rc = _hypercall3(int, sched_op, SCHEDOP_shutdown,
			     &sched_shutdown, srec);

	if (rc == -ENOSYS)
		rc = _hypercall3(int, sched_op_compat, SCHEDOP_shutdown,
				 SHUTDOWN_suspend, srec);

	return rc;
}

extern fastcall unsigned int __do_IRQ(unsigned int irq, struct pt_regs *regs);
static inline void exit_idle(void) {}
#define do_IRQ(irq, regs) __do_IRQ((irq), (regs))

#ifdef CONFIG_XEN_IA64_DOM0_VP
#include <asm/xen/privop.h>

#define _hypercall_imm1(type, name, imm, a1)			\
({								\
	long __res;						\
	__asm__ __volatile__ (";;\n"				\
			      "mov r14=%2\n"			\
			      "mov r15=%3\n"			\
			      "mov r2=%1\n"			\
			      "break 0x1000 ;;\n"		\
			      "mov %0=r8 ;;\n"			\
			      : "=r" (__res)			\
			      : "i" (__HYPERVISOR_##name),	\
				"i" (imm),			\
				"r" ((unsigned long)(a1))	\
			      : "r14","r15","r2","r8",		\
				"memory" );			\
	(type)__res;						\
})

#define _hypercall_imm2(type, name, imm, a1, a2)		\
({								\
	long __res;						\
	__asm__ __volatile__ (";;\n"				\
			      "mov r14=%2\n"			\
			      "mov r15=%3\n"			\
			      "mov r16=%4\n"			\
			      "mov r2=%1\n"			\
			      "break 0x1000 ;;\n"		\
			      "mov %0=r8 ;;\n"			\
			      : "=r" (__res)			\
			      : "i" (__HYPERVISOR_##name),	\
				"i" (imm),			\
				"r" ((unsigned long)(a1)),	\
				"r" ((unsigned long)(a2))	\
			      : "r14","r15","r16","r2","r8",	\
				"memory" );			\
	(type)__res;						\
})

#define _hypercall_imm3(type, name, imm, a1, a2, a3)		\
({								\
	long __res;						\
	__asm__ __volatile__ (";;\n"				\
			      "mov r14=%2\n"			\
			      "mov r15=%3\n"			\
			      "mov r16=%4\n"			\
			      "mov r17=%5\n"			\
			      "mov r2=%1\n"			\
			      "break 0x1000 ;;\n"		\
			      "mov %0=r8 ;;\n"			\
			      : "=r" (__res)			\
			      : "i" (__HYPERVISOR_##name),	\
				"i" (imm),			\
				"r" ((unsigned long)(a1)),	\
				"r" ((unsigned long)(a2)),	\
				"r" ((unsigned long)(a3))	\
			      : "r14","r15","r16","r17",	\
				"r2","r8",			\
				"memory" );			\
	(type)__res;						\
})

#define _hypercall_imm4(type, name, imm, a1, a2, a3, a4)	\
({								\
	long __res;						\
	__asm__ __volatile__ (";;\n"				\
			      "mov r14=%2\n"			\
			      "mov r15=%3\n"			\
			      "mov r16=%4\n"			\
			      "mov r17=%5\n"			\
			      "mov r18=%6\n"			\
			      "mov r2=%1\n"			\
			      "break 0x1000 ;;\n"		\
			      "mov %0=r8 ;;\n"			\
			      : "=r" (__res)			\
			      : "i" (__HYPERVISOR_##name),	\
				"i" (imm),			\
				"r" ((unsigned long)(a1)),	\
				"r" ((unsigned long)(a2)),	\
				"r" ((unsigned long)(a3)),	\
				"r" ((unsigned long)(a4))	\
			      : "r14","r15","r16","r17","r18",	\
				"r2","r8",			\
				"memory" );			\
	(type)__res;						\
})

static inline unsigned long
__HYPERVISOR_ioremap(unsigned long ioaddr, unsigned long size)
{
	return _hypercall_imm2(unsigned long, ia64_dom0vp_op,
			       IA64_DOM0VP_ioremap, ioaddr, size);
}

static inline unsigned long
HYPERVISOR_ioremap(unsigned long ioaddr, unsigned long size)
{
	unsigned long ret = ioaddr;
	if (running_on_xen) {
		ret = __HYPERVISOR_ioremap(ioaddr, size);
	}
	return ret;
}

static inline unsigned long
__HYPERVISOR_phystomach(unsigned long gpfn)
{
	return _hypercall_imm1(unsigned long, ia64_dom0vp_op,
			       IA64_DOM0VP_phystomach, gpfn);
}

static inline unsigned long
HYPERVISOR_phystomach(unsigned long gpfn)
{
	unsigned long ret = gpfn;
	if (running_on_xen) {
		ret = __HYPERVISOR_phystomach(gpfn);
	}
	return ret;
}

static inline unsigned long
__HYPERVISOR_machtophys(unsigned long mfn)
{
	return _hypercall_imm1(unsigned long, ia64_dom0vp_op,
			       IA64_DOM0VP_machtophys, mfn);
}

static inline unsigned long
HYPERVISOR_machtophys(unsigned long mfn)
{
	unsigned long ret = mfn;
	if (running_on_xen) {
		ret = __HYPERVISOR_machtophys(mfn);
	}
	return ret;
}

static inline unsigned long
__HYPERVISOR_populate_physmap(unsigned long gpfn, unsigned int extent_order,
			      unsigned int address_bits)
{
	return _hypercall_imm3(unsigned long, ia64_dom0vp_op,
			       IA64_DOM0VP_populate_physmap, gpfn, 
			       extent_order, address_bits);
}

static inline unsigned long
HYPERVISOR_populate_physmap(unsigned long gpfn, unsigned int extent_order,
			    unsigned int address_bits)
{
	unsigned long ret = 0;
	if (running_on_xen) {
		ret = __HYPERVISOR_populate_physmap(gpfn, extent_order,
						    address_bits);
	}
	return ret;
}

static inline unsigned long
__HYPERVISOR_zap_physmap(unsigned long gpfn, unsigned int extent_order)
{
	return _hypercall_imm2(unsigned long, ia64_dom0vp_op,
			       IA64_DOM0VP_zap_physmap, gpfn, extent_order);
}

static inline unsigned long
HYPERVISOR_zap_physmap(unsigned long gpfn, unsigned int extent_order)
{
	unsigned long ret = 0;
	if (running_on_xen) {
		ret = __HYPERVISOR_zap_physmap(gpfn, extent_order);
	}
	return ret;
}

static inline unsigned long
__HYPERVISOR_add_physmap(unsigned long gpfn, unsigned long mfn,
			 unsigned int flags, domid_t domid)
{
	return _hypercall_imm4(unsigned long, ia64_dom0vp_op,
			       IA64_DOM0VP_add_physmap, gpfn, mfn, flags,
			       domid);
}
static inline unsigned long
HYPERVISOR_add_physmap(unsigned long gpfn, unsigned long mfn,
		       unsigned int flags, domid_t domid)
{
	unsigned long ret = 0;
	BUG_ON(!running_on_xen);//XXX
	if (running_on_xen) {
		ret = __HYPERVISOR_add_physmap(gpfn, mfn, flags, domid);
	}
	return ret;
}
#else
#define HYPERVISOR_ioremap(ioaddr, size)		(ioaddr)
#define HYPERVISOR_phystomach(gpfn)			(gpfn)
#define HYPERVISOR_machtophys(mfn)			(mfn)
#define HYPERVISOR_populate_physmap(gpfn, extent_order, address_bits) \
							(0)
#define HYPERVISOR_zap_physmap(gpfn, extent_order)	(0)
#define HYPERVISOR_add_physmap(gpfn, mfn, flags)	(0)
#endif
#endif /* __HYPERCALL_H__ */
